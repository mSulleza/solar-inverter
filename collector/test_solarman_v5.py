"""Round-trip tests for the V5 decoder, built on synthesised frames."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from solarman_v5 import (  # noqa: E402
    CONTROL_DATA,
    END_BYTE,
    START_BYTE,
    V5Stream,
    checksum,
    modbus_crc16,
    parse_frame,
)


def build_modbus_response(slave: int, function: int, registers: list[int]) -> bytes:
    body = b"".join(r.to_bytes(2, "big") for r in registers)
    frame = bytes([slave, function, len(body)]) + body
    return frame + modbus_crc16(frame).to_bytes(2, "little")


def build_v5(control: int, logger_serial: int, payload: bytes, sequence: int = 1) -> bytes:
    header = struct.pack("<HHHI", len(payload), control, sequence, logger_serial)
    frame = bytes([START_BYTE]) + header + payload
    return frame + bytes([checksum(frame + b"\x00\x00"), END_BYTE])


def build_data_payload(registers: list[int], slave: int = 1, function: int = 0x03) -> bytes:
    head = bytes([0x02]) + (0).to_bytes(2, "little") + struct.pack("<III", 3600, 7200, 0)
    return head + build_modbus_response(slave, function, registers)


def test_modbus_crc_matches_known_vector():
    # Canonical Modbus example: read 1 holding register from slave 1 -> bytes 84 0A.
    assert modbus_crc16(bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])) == 0x0A84


def test_parses_data_frame_registers():
    registers = [2301, 500, 4998, 55, 1234]
    frame = build_v5(CONTROL_DATA, 1234567890, build_data_payload(registers))
    parsed = parse_frame(frame)

    assert parsed is not None
    assert parsed.checksum_ok
    assert parsed.control_name == "data"
    assert parsed.logger_serial == 1234567890
    assert parsed.total_working_time == 3600
    assert parsed.modbus is not None
    assert parsed.modbus.crc_ok
    assert parsed.modbus.registers == registers


def test_stream_reassembles_across_arbitrary_chunk_boundaries():
    registers = [1, 2, 3, 4]
    frame = build_v5(CONTROL_DATA, 999, build_data_payload(registers))

    # Feed one byte at a time -- the worst case a TCP stream can hand us.
    stream = V5Stream()
    collected = []
    for i in range(len(frame)):
        collected.extend(stream.feed(frame[i : i + 1]))

    assert len(collected) == 1
    assert collected[0].modbus.registers == registers


def test_stream_resyncs_after_leading_garbage():
    frame = build_v5(CONTROL_DATA, 42, build_data_payload([7, 8]))
    stream = V5Stream()

    frames = stream.feed(b"\xde\xad\xbe\xef" + frame)

    assert len(frames) == 1
    assert frames[0].modbus.registers == [7, 8]


def test_stream_handles_two_frames_in_one_packet():
    a = build_v5(CONTROL_DATA, 1, build_data_payload([10]), sequence=1)
    b = build_v5(CONTROL_DATA, 1, build_data_payload([20]), sequence=2)

    frames = V5Stream().feed(a + b)

    assert [f.modbus.registers for f in frames] == [[10], [20]]


def test_exception_response_is_surfaced_not_dropped():
    head = bytes([0x02]) + (0).to_bytes(2, "little") + struct.pack("<III", 1, 1, 0)
    body = bytes([0x01, 0x83, 0x02])
    payload = head + body + modbus_crc16(body).to_bytes(2, "little")

    parsed = parse_frame(build_v5(CONTROL_DATA, 1, payload))

    assert parsed.modbus.exception == 0x02
    assert parsed.modbus.registers == []
