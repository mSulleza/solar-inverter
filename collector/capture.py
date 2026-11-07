"""
Offline decode of a captured session -- no network, no root.

Two ways to get a capture to feed this:

  1. tcpdump on the collector machine while the stick is talking to us:
         sudo tcpdump -i any -w solar.pcap 'tcp port 10000'
     then extract the stick->server payloads however you like into a raw byte
     file, or point this at the pcap if scapy is installed.

  2. the collector's own spooled raw_frames: every frame it ever saw is stored
     as payload_hex, so a session can be replayed from the database.

Usage:
    python capture.py --hex-file frames.hex        # newline-separated hex frames
    python capture.py --raw-file stream.bin        # one concatenated byte stream

This is the safe way to confirm the POWMR register map against real data before
trusting it: decode a real capture, eyeball the numbers, adjust registers.py.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from registers import PROFILES, derive, suggest_mapping
from solarman_v5 import CONTROL_DATA, V5Stream, parse_frame


def load_stream(raw: bytes) -> list:
    return V5Stream().feed(raw)


def load_hex_frames(text: str) -> list:
    frames = []
    for line in text.splitlines():
        line = line.strip().replace(" ", "")
        if not line:
            continue
        parsed = parse_frame(bytes.fromhex(line))
        if parsed:
            frames.append(parsed)
    return frames


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode a captured Solarman V5 session offline")
    parser.add_argument("--raw-file", help="one concatenated byte stream")
    parser.add_argument("--hex-file", help="newline-separated hex frames")
    parser.add_argument("--profile", default="powmr_hybrid", choices=sorted(PROFILES))
    parser.add_argument("--suggest", action="store_true",
                        help="rank candidate registers instead of decoding with the profile")
    args = parser.parse_args()

    if args.raw_file:
        frames = load_stream(Path(args.raw_file).read_bytes())
    elif args.hex_file:
        frames = load_hex_frames(Path(args.hex_file).read_text())
    else:
        parser.error("give --raw-file or --hex-file")

    data_frames = [f for f in frames if f.control == CONTROL_DATA and f.modbus and f.modbus.registers]
    print(f"parsed {len(frames)} frames, {len(data_frames)} carry inverter registers\n")

    if not data_frames:
        return

    if args.suggest:
        samples = [f.modbus.registers for f in data_frames]
        print("candidate register indices (best first, by how much each moves):\n")
        for metric, hits in suggest_mapping(samples).items():
            top = ", ".join(f"reg[{i}] (var {v:.1f})" for i, v in hits[:4]) or "none in range"
            print(f"  {metric:22} {top}")
        return

    profile = PROFILES[args.profile]
    for i, frame in enumerate(data_frames):
        metrics = derive(profile.decode(frame.modbus.registers))
        print(f"--- frame {i}  logger {frame.logger_serial}  ({len(frame.modbus.registers)} regs) ---")
        for key, value in metrics.items():
            print(f"    {key:22} {value}")
        print()


if __name__ == "__main__":
    main()
