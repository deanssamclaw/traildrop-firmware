#!/usr/bin/env python3
"""
Generate LXMF test vectors for TrailDrop firmware Phase 4a.
Run: python3 tests/lxmf_test_vectors.py > tests/lxmf_test_vectors.json
"""

import json
import RNS
import LXMF
import RNS.vendor.umsgpack as msgpack


def to_hex(data):
    if isinstance(data, bytes):
        return data.hex()
    return str(data)


def main():
    # Initialize RNS (required for Destination registration)
    import tempfile, os
    tmpdir = tempfile.mkdtemp()
    RNS.Reticulum(configdir=tmpdir, loglevel=RNS.LOG_CRITICAL)

    vectors = {}

    # =====================================================================
    # Part 1: Standalone msgpack encoding test vectors
    # =====================================================================
    mp = {}

    # Nil, Bool
    mp["nil"] = to_hex(msgpack.packb(None))
    mp["true"] = to_hex(msgpack.packb(True))
    mp["false"] = to_hex(msgpack.packb(False))

    # Positive fixint (0x00-0x7f)
    mp["fixint_0"] = to_hex(msgpack.packb(0))
    mp["fixint_42"] = to_hex(msgpack.packb(42))
    mp["fixint_127"] = to_hex(msgpack.packb(127))

    # uint8 (0xcc)
    mp["uint8_128"] = to_hex(msgpack.packb(128))
    mp["uint8_200"] = to_hex(msgpack.packb(200))
    mp["uint8_255"] = to_hex(msgpack.packb(255))

    # uint16 (0xcd)
    mp["uint16_256"] = to_hex(msgpack.packb(256))
    mp["uint16_1000"] = to_hex(msgpack.packb(1000))
    mp["uint16_65535"] = to_hex(msgpack.packb(65535))

    # Negative fixint (0xe0-0xff) and int8 (0xd0)
    mp["negfixint_m1"] = to_hex(msgpack.packb(-1))
    mp["negfixint_m32"] = to_hex(msgpack.packb(-32))
    mp["int8_m33"] = to_hex(msgpack.packb(-33))
    mp["int8_m128"] = to_hex(msgpack.packb(-128))

    # LXMF field keys (0xFB=251, 0xFC=252 -> uint8 format, NOT fixint)
    mp["uint8_251"] = to_hex(msgpack.packb(251))
    mp["uint8_252"] = to_hex(msgpack.packb(252))

    # Float64 (0xcb)
    mp["float64_0"] = to_hex(msgpack.packb(0.0))
    mp["float64_1_5"] = to_hex(msgpack.packb(1.5))
    mp["float64_timestamp"] = to_hex(msgpack.packb(1709000000.5))
    mp["float64_neg"] = to_hex(msgpack.packb(-95.2353))

    # Binary (0xc4 bin8)
    mp["bin_empty"] = to_hex(msgpack.packb(b""))
    mp["bin_4bytes"] = to_hex(msgpack.packb(b"Test"))
    mp["bin_18bytes"] = to_hex(msgpack.packb(b"Hello from Python!"))

    # String (fixstr 0xa0-0xbf)
    mp["fixstr_empty"] = to_hex(msgpack.packb(""))
    mp["fixstr_lat"] = to_hex(msgpack.packb("lat"))
    mp["fixstr_lon"] = to_hex(msgpack.packb("lon"))

    # Fixarray (0x90-0x9f)
    mp["fixarray_empty"] = to_hex(msgpack.packb([]))
    mp["fixarray_4ints"] = to_hex(msgpack.packb([1, 2, 3, 4]))

    # Fixmap (0x80-0x8f)
    mp["fixmap_empty"] = to_hex(msgpack.packb({}))
    mp["fixmap_field_keys"] = to_hex(msgpack.packb({251: b"type_val", 252: b"data_val"}))

    # Complete LXMF-style payload (4-element array, no fields)
    payload_simple = [1709000000.5, b"Test", b"Hello from Python!", {}]
    mp["lxmf_payload_simple"] = to_hex(msgpack.packb(payload_simple))

    vectors["msgpack"] = mp

    # =====================================================================
    # Part 2: Identity and Destination keys
    # =====================================================================
    sender = RNS.Identity()
    receiver = RNS.Identity()

    sender_dest = RNS.Destination(
        sender, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"
    )
    receiver_dest = RNS.Destination(
        receiver, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"
    )

    vectors["sender"] = {
        "x25519_private": to_hex(sender.prv.private_bytes()),
        "x25519_public": to_hex(sender.pub_bytes),
        "ed25519_private": to_hex(sender.sig_prv.private_bytes()),
        "ed25519_public": to_hex(sender.sig_pub.public_bytes()),
        "identity_hash": to_hex(sender.hash),
        "dest_hash": to_hex(sender_dest.hash),
    }

    vectors["receiver"] = {
        "x25519_private": to_hex(receiver.prv.private_bytes()),
        "x25519_public": to_hex(receiver.pub_bytes),
        "ed25519_private": to_hex(receiver.sig_prv.private_bytes()),
        "ed25519_public": to_hex(receiver.sig_pub.public_bytes()),
        "identity_hash": to_hex(receiver.hash),
        "dest_hash": to_hex(receiver_dest.hash),
    }

    # =====================================================================
    # Part 3: Simple LXMF message (no custom fields)
    # =====================================================================
    msg1 = LXMF.LXMessage(
        receiver_dest, sender_dest,
        content="Hello from Python!", title="Test"
    )
    msg1.timestamp = 1709000000.5
    msg1.pack()

    packed_payload_1 = msg1.packed[2 * 16 + 64:]

    vectors["simple_message"] = {
        "timestamp": msg1.timestamp,
        "title_hex": to_hex(msg1.title),
        "content_hex": to_hex(msg1.content),
        "packed_payload_hex": to_hex(packed_payload_1),
        "message_hash_hex": to_hex(msg1.hash),
        "signature_hex": to_hex(msg1.signature),
        "full_packed_hex": to_hex(msg1.packed),
        "opportunistic_hex": to_hex(msg1.packed[16:]),
    }

    # =====================================================================
    # Part 4: LXMF message with custom fields
    # =====================================================================
    custom_type = b"traildrop/waypoint"
    waypoint_data = {"lat": 38.9717, "lon": -95.2353}
    custom_data = msgpack.packb(waypoint_data)

    msg2 = LXMF.LXMessage(
        receiver_dest, sender_dest,
        content="Camp waypoint", title="Waypoint",
        fields={0xFB: custom_type, 0xFC: custom_data}
    )
    msg2.timestamp = 1709000001.0
    msg2.pack()

    packed_payload_2 = msg2.packed[2 * 16 + 64:]

    vectors["fields_message"] = {
        "timestamp": msg2.timestamp,
        "title_hex": to_hex(msg2.title),
        "content_hex": to_hex(msg2.content),
        "custom_type_hex": to_hex(custom_type),
        "custom_data_hex": to_hex(custom_data),
        "packed_payload_hex": to_hex(packed_payload_2),
        "message_hash_hex": to_hex(msg2.hash),
        "signature_hex": to_hex(msg2.signature),
        "full_packed_hex": to_hex(msg2.packed),
    }

    # =====================================================================
    # Part 5: Stamped message simulation (5-element payload)
    # =====================================================================
    payload_4 = [msg1.timestamp, msg1.title, msg1.content, msg1.fields]
    fake_stamp = b"\xaa" * 16
    payload_5 = payload_4 + [fake_stamp]

    packed_4 = msgpack.packb(payload_4)
    packed_5 = msgpack.packb(payload_5)

    hashed_part = receiver_dest.hash + sender_dest.hash + packed_4
    expected_hash = RNS.Identity.full_hash(hashed_part)

    vectors["stamped_message"] = {
        "packed_5elem_hex": to_hex(packed_5),
        "packed_4elem_hex": to_hex(packed_4),
        "expected_hash_hex": to_hex(expected_hash),
        "matches_simple_hash": to_hex(expected_hash) == to_hex(msg1.hash),
    }

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
