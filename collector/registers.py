"""
Register maps turning raw Modbus registers into named metrics.

An important caveat, stated plainly: "POWMR" is a brand that rebadges several
different inverter platforms, and the register layout differs between them. The
POWMR profile below is a best-effort starting map, NOT a verified one for this
specific unit. Every reading is therefore stored twice: the decoded metrics, and
the raw register block they came from. If the profile turns out to be wrong, the
raw data is still there and the mapping can be corrected after the fact without
losing a single sample.

`suggest_mapping()` exists for exactly that: point it at real captured frames and
it ranks which register indices plausibly hold which metric, based on value
ranges and how much each register moves over time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Optional


@dataclass(frozen=True)
class Field:
    """One decoded metric: where to read it, how to scale it, what it is."""

    name: str
    register: int
    scale: float = 1.0
    unit: str = ""
    signed: bool = False
    # Registers that pair with the next one to form a 32-bit value.
    wide: bool = False

    def decode(self, registers: list[int], base: int = 0) -> Optional[float]:
        index = self.register - base
        if index < 0 or index >= len(registers):
            return None

        if self.wide:
            if index + 1 >= len(registers):
                return None
            raw = (registers[index] << 16) | registers[index + 1]
            width = 32
        else:
            raw = registers[index]
            width = 16

        if self.signed and raw >= (1 << (width - 1)):
            raw -= 1 << width

        return raw * self.scale


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    fields: tuple[Field, ...]

    def decode(self, registers: list[int], base: int = 0) -> dict[str, float]:
        decoded: dict[str, float] = {}
        for field in self.fields:
            value = field.decode(registers, base)
            if value is not None:
                decoded[field.name] = value
        return decoded


# Best-effort POWMR hybrid map. Treat the register numbers as a hypothesis to be
# confirmed against captured traffic, not as fact.
POWMR = Profile(
    name="powmr_hybrid",
    description="POWMR hybrid inverter, best-effort map -- verify against captured frames",
    fields=(
        Field("grid_voltage", 0x0000, 0.1, "V"),
        Field("grid_frequency", 0x0001, 0.01, "Hz"),
        Field("grid_power", 0x0002, 1.0, "W", signed=True),
        Field("pv1_voltage", 0x0006, 0.1, "V"),
        Field("pv1_current", 0x0007, 0.1, "A"),
        Field("pv1_power", 0x0008, 1.0, "W"),
        Field("pv2_voltage", 0x0009, 0.1, "V"),
        Field("pv2_current", 0x000A, 0.1, "A"),
        Field("pv2_power", 0x000B, 1.0, "W"),
        Field("battery_voltage", 0x000E, 0.01, "V"),
        Field("battery_current", 0x000F, 0.1, "A", signed=True),
        Field("battery_power", 0x0010, 1.0, "W", signed=True),
        Field("battery_soc", 0x0011, 1.0, "%"),
        Field("load_voltage", 0x0014, 0.1, "V"),
        Field("load_power", 0x0016, 1.0, "W"),
        Field("inverter_temperature", 0x0018, 0.1, "degC", signed=True),
        Field("pv_energy_today", 0x001C, 0.1, "kWh"),
        Field("load_energy_today", 0x001E, 0.1, "kWh"),
    ),
)

PROFILES: dict[str, Profile] = {POWMR.name: POWMR}


# Plausibility windows used to guess what an unknown register might be. Ranges
# are deliberately generous -- the goal is to narrow dozens of registers down to
# a handful of candidates a human can then confirm, not to decide automatically.
CANDIDATE_RANGES: dict[str, tuple[float, float, float]] = {
    # name: (min, max, scale to apply before testing)
    "grid_voltage": (180.0, 270.0, 0.1),
    "grid_frequency": (45.0, 65.0, 0.01),
    "battery_voltage_48v": (40.0, 60.0, 0.01),
    "battery_soc": (0.0, 100.0, 1.0),
    "pv_voltage": (50.0, 500.0, 0.1),
    "temperature": (0.0, 90.0, 0.1),
}


def suggest_mapping(
    samples: Iterable[list[int]],
    ranges: Optional[dict[str, tuple[float, float, float]]] = None,
) -> dict[str, list[tuple[int, float]]]:
    """
    Rank candidate register indices for each metric, given several samples.

    Scoring is deliberately simple: a register scores for a metric if every
    sample falls inside that metric's plausible range once scaled. Ties are
    broken by variance -- a register that never changes is far more likely to be
    a constant or a model code than a live measurement, so movement is treated
    as evidence.

    Returns {metric: [(register_index, variance), ...]} sorted best-first.
    """
    ranges = ranges or CANDIDATE_RANGES
    sample_list = [s for s in samples if s]
    if not sample_list:
        return {}

    width = min(len(s) for s in sample_list)
    suggestions: dict[str, list[tuple[int, float]]] = {}

    for metric, (low, high, scale) in ranges.items():
        hits: list[tuple[int, float]] = []
        for index in range(width):
            values = [s[index] * scale for s in sample_list]
            if not all(low <= v <= high for v in values):
                continue
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            hits.append((index, variance))

        hits.sort(key=lambda pair: pair[1], reverse=True)
        suggestions[metric] = hits

    return suggestions


def derive(metrics: dict[str, float]) -> dict[str, float]:
    """
    Fill in metrics the inverter does not report directly.

    Kept separate from the profile so the stored raw-to-named mapping stays a
    pure function of the register block, and anything computed is clearly marked
    as computed.
    """
    out = dict(metrics)

    pv1 = metrics.get("pv1_power")
    pv2 = metrics.get("pv2_power")
    if pv1 is not None or pv2 is not None:
        out["pv_power_total"] = (pv1 or 0.0) + (pv2 or 0.0)

    # Positive means the battery is charging, negative means it is discharging.
    battery = metrics.get("battery_power")
    if battery is not None:
        out["battery_charging"] = 1.0 if battery > 0 else 0.0

    return out
