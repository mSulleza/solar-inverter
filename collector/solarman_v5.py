"""
Solarman V5 protocol decoder.

The IGEN/Solarman "SWB1" logger stick (firmware SWB1-v1.44.5_SolarV70) has no
usable local API -- its entire local web surface is a firmware-upload page, and
it exposes neither Modbus TCP nor the older UDP AT-command interface. Everything
it knows goes out over a single TCP connection to the Solarman collection server
on port 10000, wrapped in Solarman's "V5" framing.

That framing is a thin envelope around ordinary Modbus RTU: the stick polls the
inverter over RS485, then forwards each raw RTU response upstream. So decoding
V5 gets us the exact register values the inverter reported, with no polling of
our own and no extra load on the bus.

Frame layout (all multi-byte fields little-endian):

    offset  size  field
    0       1     start byte, always 0xA5
    1       2     payload length
    3       2     control code (0x4210 data, 0x4110 hello, 0x4710 heartbeat, ...)
    5       2     frame sequence number
    7       4     logger serial number
    11      n     payload
    11+n    1     checksum (sum of bytes[1:-2] & 0xFF)
    12+n    1     end byte, always 0x15

A 0x4210 data payload carries some stick-local telemetry followed by the
embedded Modbus RTU response:

    offset  size  field
    0       1     frame type (0x02 = inverter data)
    1       2     status
    3       4     total working time (seconds)
    7       4     power-on time (seconds)
    11      4     offset time (unix epoch offset)
    15      m     Modbus RTU response frame

Reference for the framing: the pysolarmanv5 project and community reverse
engineering of the LSW-3/LSE-3/SWB1 sticks.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

START_BYTE = 0xA5
END_BYTE = 0x15

# Real stick frames are a few hundred bytes. A header claiming more than this is
# garbage (or hostile): honouring it would make the stream buffer up to 64 KB
# waiting for a frame that never comes, so it is rejected and we resync.
MAX_PAYLOAD_LEN = 2048

# Control codes seen from these sticks. The stick sends the "request" variants;
# the server replies with the matching 0x1x form.
CONTROL_HELLO = 0x4110
CONTROL_DATA = 0x4210
CONTROL_WIFI = 0x4310
CONTROL_HEARTBEAT = 0x4710
CONTROL_NAMES = {
    CONTROL_HELLO: "hello",
    CONTROL_DATA: "data",
    CONTROL_WIFI: "wifi_info",
    CONTROL_HEARTBEAT: "heartbeat",
}


def checksum(frame: bytes) -> int:
    """V5 checksum: plain byte sum over everything but start, checksum, end."""
    return sum(frame[1:-2]) & 0xFF


def modbus_crc16(data: bytes) -> int:
    """Standard Modbus RTU CRC-16, little-endian on the wire."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


@dataclass
class ModbusResponse:
    """A parsed Modbus RTU response lifted out of a V5 data payload."""

    slave: int
    function: int
    registers: list[int] = field(default_factory=list)
    raw: bytes = b""
    crc_ok: bool = False
    exception: Optional[int] = None

    @property
    def is_read(self) -> bool:
        # 0x03 read holding registers, 0x04 read input registers.
        return self.function in (0x03, 0x04)


@dataclass
class V5Frame:
    control: int
    sequence: int
    logger_serial: int
    payload: bytes
    checksum_ok: bool
    raw: bytes

    # Only populated for CONTROL_DATA frames.
    frame_type: Optional[int] = None
    status: Optional[int] = None
    total_working_time: Optional[int] = None
    power_on_time: Optional[int] = None
    offset_time: Optional[int] = None
    modbus: Optional[ModbusResponse] = None

    @property
    def control_name(self) -> str:
        return CONTROL_NAMES.get(self.control, f"0x{self.control:04X}")


def parse_modbus_rtu(data: bytes) -> Optional[ModbusResponse]:
    """
    Parse a Modbus RTU response. Returns None if it is too short to be one.

    The CRC is checked but a bad CRC is reported rather than raised -- a stick
    that forwards a corrupted bus read is itself a useful signal, and dropping
    the frame silently would hide it.
    """
    if len(data) < 4:
        return None

    slave, function = data[0], data[1]
    crc_ok = modbus_crc16(data[:-2]) == int.from_bytes(data[-2:], "little")

    # High bit set on the function code marks a Modbus exception response.
    if function & 0x80:
        return ModbusResponse(
            slave=slave,
            function=function,
            raw=data,
            crc_ok=crc_ok,
            exception=data[2] if len(data) > 2 else None,
        )

    registers: list[int] = []
    if function in (0x03, 0x04) and len(data) >= 5:
        byte_count = data[2]
        body = data[3 : 3 + byte_count]
        # Registers are 16-bit big-endian within the RTU payload.
        registers = [
            int.from_bytes(body[i : i + 2], "big")
            for i in range(0, len(body) - 1, 2)
        ]

    return ModbusResponse(
        slave=slave,
        function=function,
        registers=registers,
        raw=data,
        crc_ok=crc_ok,
    )


def parse_frame(frame: bytes) -> Optional[V5Frame]:
    """Parse one complete V5 frame. Returns None if it is not well-formed."""
    if len(frame) < 13 or frame[0] != START_BYTE or frame[-1] != END_BYTE:
        return None

    payload_len, control, sequence, logger_serial = struct.unpack("<HHHI", frame[1:11])
    if payload_len > MAX_PAYLOAD_LEN:
        return None
    payload = frame[11 : 11 + payload_len]

    parsed = V5Frame(
        control=control,
        sequence=sequence,
        logger_serial=logger_serial,
        payload=payload,
        checksum_ok=frame[-2] == checksum(frame),
        raw=frame,
    )

    # Only data frames carry inverter registers; the rest are stick housekeeping.
    if control == CONTROL_DATA and len(payload) >= 15:
        parsed.frame_type = payload[0]
        parsed.status = int.from_bytes(payload[1:3], "little")
        (
            parsed.total_working_time,
            parsed.power_on_time,
            parsed.offset_time,
        ) = struct.unpack("<III", payload[3:15])
        parsed.modbus = parse_modbus_rtu(payload[15:])

    return parsed


class V5Stream:
    """
    Reassembles V5 frames from a TCP byte stream.

    TCP gives no message boundaries, so bytes are buffered until a full frame is
    present. Resynchronisation matters here: if the buffer does not start with
    0xA5 (a mid-frame connect, or a corrupted frame), everything up to the next
    0xA5 is discarded rather than the whole buffer, so one bad frame costs one
    frame rather than the rest of the session.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[V5Frame]:
        self._buffer.extend(data)
        frames: list[V5Frame] = []

        while True:
            if len(self._buffer) < 13:
                break

            if self._buffer[0] != START_BYTE:
                next_start = self._buffer.find(START_BYTE, 1)
                if next_start == -1:
                    self._buffer.clear()
                    break
                del self._buffer[:next_start]
                continue

            payload_len = int.from_bytes(self._buffer[1:3], "little")
            if payload_len > MAX_PAYLOAD_LEN:
                # Impossible length: drop this start byte now and hunt for the
                # next one, rather than waiting for up to 64 KB to arrive.
                del self._buffer[:1]
                continue
            total_len = payload_len + 13
            if len(self._buffer) < total_len:
                break

            candidate = bytes(self._buffer[:total_len])
            if candidate[-1] != END_BYTE:
                # Length field lied -- treat the start byte as spurious and hunt
                # for the next one instead of trusting the rest of the buffer.
                del self._buffer[:1]
                continue

            del self._buffer[:total_len]
            parsed = parse_frame(candidate)
            if parsed is not None:
                frames.append(parsed)

        return frames
