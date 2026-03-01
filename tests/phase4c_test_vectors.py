#!/usr/bin/env python3
"""Phase 4c: Python test vector generator for waypoint msgpack encoding.

Generates hex-encoded msgpack test vectors for firmware byte-for-byte matching.
Run: python3 tests/phase4c_test_vectors.py
"""

import msgpack
import struct

def print_hex(label, data):
    print(f"{label}: {data.hex()}")
    print(f"  length: {len(data)} bytes")

# Test vector 1: Full waypoint with notes
wp_full = {
    "lat": 38.9717,
    "lon": -95.2353,
    "ele": 267.0,
    "name": "Camp",
    "notes": "Water source",
    "ts": 1709312400,
}
packed_full = msgpack.packb(wp_full, use_bin_type=True)
print_hex("FULL_WAYPOINT", packed_full)

# Test vector 2: Waypoint without notes (notes key omitted entirely)
wp_no_notes = {
    "lat": 38.9717,
    "lon": -95.2353,
    "ele": 267.0,
    "name": "Camp",
    "ts": 1709312400,
}
packed_no_notes = msgpack.packb(wp_no_notes, use_bin_type=True)
print_hex("NO_NOTES_WAYPOINT", packed_no_notes)

# Verify float64 precision
print(f"\nlat float64 bytes: {struct.pack('>d', 38.9717).hex()}")
print(f"lon float64 bytes: {struct.pack('>d', -95.2353).hex()}")
print(f"ele float64 bytes: {struct.pack('>d', 267.0).hex()}")
print(f"ts  uint32  bytes: ce{struct.pack('>I', 1709312400).hex()}")

# Decode roundtrip verification
unpacked = msgpack.unpackb(packed_full, raw=False)
assert unpacked["lat"] == 38.9717
assert unpacked["lon"] == -95.2353
assert unpacked["ele"] == 267.0
assert unpacked["name"] == "Camp"
assert unpacked["notes"] == "Water source"
assert unpacked["ts"] == 1709312400
print("\nRoundtrip verification: PASS")
