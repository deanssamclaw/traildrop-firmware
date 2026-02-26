# Reticulum Wire Format Notes

Research notes from reading the Python reference implementation.
This document will be filled in during Phase 3 development.

## Sources
- `RNS/Packet.py` — packet structure, header flags, serialization
- `RNS/Identity.py` — keypair generation, encryption, signing
- `RNS/Destination.py` — address derivation
- `RNS/Transport.py` — routing, announce handling
- `LXMF/LXMessage.py` — LXMF message format

## Packet Structure
```
TODO: Document after source analysis

Known from docs:
- MTU: 500 bytes
- Destination: 16 bytes (truncated SHA-256)
- Encryption: X25519 ECDH per-packet, AES-256-CBC, HMAC-SHA256
- Addressing: no source address in packets (initiator anonymity)
```

## Identity
```
TODO: Document key format and derivation

Known:
- 512-bit EC keyset (X25519 + Ed25519)
- X25519 for encryption (ECDH key agreement)
- Ed25519 for signing (announces, proofs)
```

## Announce Format
```
TODO: Document announce packet structure

Known:
- Contains public keys
- Contains app name + aspects
- Signed with Ed25519
- Rate-limited (ANNOUNCE_CAP = 2% of bandwidth)
```

## LXMF Message Format
```
TODO: Document LXMF envelope structure

Known:
- Source + destination
- Content (our waypoint JSON)
- Title
- Timestamp
- Delivery confirmation
```
