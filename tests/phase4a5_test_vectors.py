#!/usr/bin/env python3
"""
Phase 4a.5 Test Vectors: Dual destination hashes + announce app_data format

Generates test vectors for firmware to verify:
1. lxmf.delivery dest_hash computation
2. traildrop.waypoint dest_hash computation (sanity check)
3. LXMF 0.5.0+ announce app_data encoding: msgpack [display_name_bytes, null]
"""

import hashlib
import msgpack
import os
import sys

def identity_hash(x25519_pub: bytes, ed25519_pub: bytes) -> bytes:
    """Compute RNS identity hash: SHA-256(x25519_pub + ed25519_pub)[:16]"""
    return hashlib.sha256(x25519_pub + ed25519_pub).digest()[:16]

def name_hash(full_name: str) -> bytes:
    """Compute RNS name_hash: SHA-256(full_name)[:10]"""
    return hashlib.sha256(full_name.encode()).digest()[:10]

def dest_hash(nh: bytes, ih: bytes) -> bytes:
    """Compute RNS dest_hash: SHA-256(name_hash + identity_hash)[:16]"""
    return hashlib.sha256(nh + ih).digest()[:16]

def compute_destination(x25519_pub: bytes, ed25519_pub: bytes,
                        app_name: str, aspects: str) -> bytes:
    """Full destination hash computation from raw keys"""
    ih = identity_hash(x25519_pub, ed25519_pub)
    full_name = f"{app_name}.{aspects}"
    nh = name_hash(full_name)
    return dest_hash(nh, ih)

def main():
    # Use deterministic test keys (same sender keys from Phase 4a LXMF test vectors)
    x25519_prv = bytes.fromhex("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b")
    x25519_pub = bytes.fromhex("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313")
    ed25519_prv = bytes.fromhex("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968")
    ed25519_pub = bytes.fromhex("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213")

    ih = identity_hash(x25519_pub, ed25519_pub)
    print(f"identity_hash: {ih.hex()}")

    # Compute traildrop.waypoint destination
    td_nh = name_hash("traildrop.waypoint")
    td_dest = dest_hash(td_nh, ih)
    print(f"traildrop.waypoint name_hash: {td_nh.hex()}")
    print(f"traildrop.waypoint dest_hash: {td_dest.hex()}")

    # Compute lxmf.delivery destination
    lxmf_nh = name_hash("lxmf.delivery")
    lxmf_dest = dest_hash(lxmf_nh, ih)
    print(f"lxmf.delivery name_hash: {lxmf_nh.hex()}")
    print(f"lxmf.delivery dest_hash: {lxmf_dest.hex()}")

    # Verify they're different
    assert td_dest != lxmf_dest, "Destinations should be different!"
    print(f"\nDestinations are different: OK")

    # Generate LXMF 0.5.0+ announce app_data
    display_name = "TrailDrop"
    app_data = msgpack.packb([display_name.encode(), None])
    print(f"\nannounce app_data (LXMF 0.5.0+):")
    print(f"  display_name: {display_name!r}")
    print(f"  packed_hex: {app_data.hex()}")
    print(f"  first_byte: 0x{app_data[0]:02x} (should be 0x92 = fixarray(2))")
    assert app_data[0] == 0x92, f"Expected 0x92, got 0x{app_data[0]:02x}"

    # Decode to verify
    decoded = msgpack.unpackb(app_data, raw=True)
    print(f"  decoded: {decoded}")
    assert decoded[0] == display_name.encode()
    assert decoded[1] is None

    # Also test with longer name
    long_name = "TrailDrop-ABCD"
    long_app_data = msgpack.packb([long_name.encode(), None])
    print(f"\nlong name app_data:")
    print(f"  display_name: {long_name!r}")
    print(f"  packed_hex: {long_app_data.hex()}")

    # Print C++ test vector constants
    print("\n// === C++ Test Vector Constants ===")
    print(f'// Identity: x25519_pub + ed25519_pub')
    print(f'static const char* tv_x25519_pub  = "{x25519_pub.hex()}";')
    print(f'static const char* tv_ed25519_pub = "{ed25519_pub.hex()}";')
    print(f'static const char* tv_identity_hash = "{ih.hex()}";')
    print(f'static const char* tv_td_dest_hash  = "{td_dest.hex()}";')
    print(f'static const char* tv_lxmf_dest_hash = "{lxmf_dest.hex()}";')
    print(f'static const char* tv_app_data_hex   = "{app_data.hex()}";')
    print(f'// app_data length: {len(app_data)}')

    print("\nAll vectors generated successfully.")

if __name__ == "__main__":
    main()
