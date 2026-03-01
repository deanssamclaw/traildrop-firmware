#include "msgpack.h"
#include <cstring>

namespace msg {

// =====================================================================
// Encoder
// =====================================================================

Encoder::Encoder(uint8_t* buffer, size_t capacity)
    : buf(buffer), cap(capacity), pos(0), error(false) {}

void Encoder::write_byte(uint8_t b) {
    if (pos >= cap) { error = true; return; }
    buf[pos++] = b;
}

void Encoder::write_bytes(const uint8_t* data, size_t len) {
    if (pos + len > cap) { error = true; return; }
    memcpy(buf + pos, data, len);
    pos += len;
}

void Encoder::write_be16(uint16_t val) {
    write_byte((uint8_t)(val >> 8));
    write_byte((uint8_t)(val & 0xFF));
}

void Encoder::write_be64(uint64_t val) {
    write_byte((uint8_t)(val >> 56));
    write_byte((uint8_t)(val >> 48));
    write_byte((uint8_t)(val >> 40));
    write_byte((uint8_t)(val >> 32));
    write_byte((uint8_t)(val >> 24));
    write_byte((uint8_t)(val >> 16));
    write_byte((uint8_t)(val >> 8));
    write_byte((uint8_t)(val & 0xFF));
}

void Encoder::write_array(uint8_t count) {
    if (count <= 15) {
        write_byte(0x90 | count);  // fixarray
    } else {
        write_byte(0xdc);  // array16
        write_be16(count);
    }
}

void Encoder::write_map(uint8_t count) {
    if (count <= 15) {
        write_byte(0x80 | count);  // fixmap
    } else {
        write_byte(0xde);  // map16
        write_be16(count);
    }
}

void Encoder::write_float64(double val) {
    write_byte(0xcb);
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    write_be64(bits);  // big-endian (network byte order)
}

void Encoder::write_bin(const uint8_t* data, size_t len) {
    if (len < 256) {
        write_byte(0xc4);  // bin8
        write_byte((uint8_t)len);
    } else if (len < 65536) {
        write_byte(0xc5);  // bin16
        write_be16((uint16_t)len);
    } else {
        error = true;
        return;
    }
    write_bytes(data, len);
}

void Encoder::write_str(const char* str, size_t len) {
    if (len < 32) {
        write_byte(0xa0 | (uint8_t)len);  // fixstr
    } else if (len < 256) {
        write_byte(0xd9);  // str8
        write_byte((uint8_t)len);
    } else {
        error = true;
        return;
    }
    write_bytes((const uint8_t*)str, len);
}

void Encoder::write_uint(uint32_t val) {
    if (val < 128) {
        write_byte((uint8_t)val);  // positive fixint
    } else if (val < 256) {
        write_byte(0xcc);  // uint8
        write_byte((uint8_t)val);
    } else if (val < 65536) {
        write_byte(0xcd);  // uint16
        write_be16((uint16_t)val);
    } else {
        write_byte(0xce);  // uint32
        write_byte((uint8_t)(val >> 24));
        write_byte((uint8_t)(val >> 16));
        write_byte((uint8_t)(val >> 8));
        write_byte((uint8_t)(val & 0xFF));
    }
}

void Encoder::write_int(int32_t val) {
    if (val >= 0) {
        write_uint((uint32_t)val);
    } else if (val >= -32) {
        write_byte((uint8_t)(int8_t)val);  // negative fixint (0xe0-0xff)
    } else if (val >= -128) {
        write_byte(0xd0);  // int8
        write_byte((uint8_t)(int8_t)val);
    } else {
        write_byte(0xd1);  // int16
        int16_t v16 = (int16_t)val;
        write_byte((uint8_t)(v16 >> 8));
        write_byte((uint8_t)(v16 & 0xFF));
    }
}

void Encoder::write_nil() {
    write_byte(0xc0);
}

void Encoder::write_bool(bool val) {
    write_byte(val ? 0xc3 : 0xc2);
}

// =====================================================================
// Decoder
// =====================================================================

Decoder::Decoder(const uint8_t* buffer, size_t length)
    : buf(buffer), len(length), pos(0), error(false) {}

uint8_t Decoder::read_byte() {
    if (pos >= len) { error = true; return 0; }
    return buf[pos++];
}

void Decoder::read_bytes(uint8_t* out, size_t count) {
    if (pos + count > len) { error = true; return; }
    memcpy(out, buf + pos, count);
    pos += count;
}

uint16_t Decoder::read_be16() {
    uint8_t hi = read_byte();
    uint8_t lo = read_byte();
    return ((uint16_t)hi << 8) | lo;
}

uint32_t Decoder::read_be32() {
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) val = (val << 8) | read_byte();
    return val;
}

uint64_t Decoder::read_be64() {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | read_byte();
    return val;
}

uint8_t Decoder::peek_type() {
    if (pos >= len) { error = true; return 0; }
    return buf[pos];
}

uint8_t Decoder::read_array() {
    uint8_t tag = read_byte();
    if ((tag & 0xf0) == 0x90) {
        return tag & 0x0f;  // fixarray
    } else if (tag == 0xdc) {
        uint16_t n = read_be16();  // array16
        return (n > 255) ? (error = true, (uint8_t)0) : (uint8_t)n;
    }
    error = true;
    return 0;
}

uint8_t Decoder::read_map() {
    uint8_t tag = read_byte();
    if ((tag & 0xf0) == 0x80) {
        return tag & 0x0f;  // fixmap
    } else if (tag == 0xde) {
        uint16_t n = read_be16();  // map16
        return (n > 255) ? (error = true, (uint8_t)0) : (uint8_t)n;
    }
    error = true;
    return 0;
}

double Decoder::read_float64() {
    uint8_t tag = read_byte();
    if (tag == 0xcb) {
        uint64_t bits = read_be64();
        double val;
        memcpy(&val, &bits, sizeof(val));
        return val;
    } else if (tag == 0xca) {
        // float32 — promote to double
        uint32_t bits = read_be32();
        float fval;
        memcpy(&fval, &bits, sizeof(fval));
        return (double)fval;
    }
    error = true;
    return 0.0;
}

size_t Decoder::read_bin(uint8_t* out, size_t max_len) {
    uint8_t tag = read_byte();
    size_t data_len = 0;

    if (tag == 0xc4) {
        data_len = read_byte();       // bin8
    } else if (tag == 0xc5) {
        data_len = read_be16();       // bin16
    } else if (tag == 0xc6) {
        data_len = read_be32();       // bin32
    } else {
        error = true;
        return 0;
    }

    if (data_len > max_len) { error = true; return 0; }
    read_bytes(out, data_len);
    return data_len;
}

size_t Decoder::read_str(char* out, size_t max_len) {
    uint8_t tag = read_byte();
    size_t data_len = 0;

    if ((tag & 0xe0) == 0xa0) {
        data_len = tag & 0x1f;        // fixstr
    } else if (tag == 0xd9) {
        data_len = read_byte();       // str8
    } else if (tag == 0xda) {
        data_len = read_be16();       // str16
    } else {
        error = true;
        return 0;
    }

    if (data_len > max_len) { error = true; return 0; }
    read_bytes((uint8_t*)out, data_len);
    return data_len;
}

uint32_t Decoder::read_uint() {
    uint8_t tag = read_byte();

    if (tag <= 0x7f) return tag;                    // positive fixint
    if (tag == 0xcc) return read_byte();            // uint8
    if (tag == 0xcd) return read_be16();            // uint16
    if (tag == 0xce) return read_be32();            // uint32

    error = true;
    return 0;
}

int32_t Decoder::read_int() {
    uint8_t tag = read_byte();

    if (tag <= 0x7f) return (int32_t)tag;                      // positive fixint
    if (tag >= 0xe0) return (int32_t)(int8_t)tag;              // negative fixint
    if (tag == 0xd0) return (int32_t)(int8_t)read_byte();      // int8
    if (tag == 0xd1) return (int32_t)(int16_t)read_be16();     // int16
    if (tag == 0xcc) return (int32_t)read_byte();              // uint8
    if (tag == 0xcd) return (int32_t)read_be16();              // uint16

    error = true;
    return 0;
}

void Decoder::read_nil() {
    uint8_t tag = read_byte();
    if (tag != 0xc0) error = true;
}

bool Decoder::read_bool() {
    uint8_t tag = read_byte();
    if (tag == 0xc3) return true;
    if (tag == 0xc2) return false;
    error = true;
    return false;
}

void Decoder::skip() {
    if (error || pos >= len) { error = true; return; }

    uint8_t tag = read_byte();

    // Positive fixint (0x00-0x7f)
    if (tag <= 0x7f) return;

    // Fixmap (0x80-0x8f)
    if ((tag & 0xf0) == 0x80) {
        uint8_t count = tag & 0x0f;
        for (int i = 0; i < count * 2; i++) skip();
        return;
    }

    // Fixarray (0x90-0x9f)
    if ((tag & 0xf0) == 0x90) {
        uint8_t count = tag & 0x0f;
        for (int i = 0; i < count; i++) skip();
        return;
    }

    // Fixstr (0xa0-0xbf)
    if ((tag & 0xe0) == 0xa0) {
        size_t n = tag & 0x1f;
        pos += n;
        if (pos > len) error = true;
        return;
    }

    switch (tag) {
        case 0xc0: return;  // nil
        case 0xc2: return;  // false
        case 0xc3: return;  // true

        // bin8, bin16, bin32
        case 0xc4: { size_t n = read_byte(); pos += n; break; }
        case 0xc5: { size_t n = read_be16(); pos += n; break; }
        case 0xc6: { size_t n = read_be32(); pos += n; break; }

        // ext8, ext16, ext32
        case 0xc7: { size_t n = read_byte(); pos += 1 + n; break; }
        case 0xc8: { size_t n = read_be16(); pos += 1 + n; break; }
        case 0xc9: { size_t n = read_be32(); pos += 1 + n; break; }

        // float32, float64
        case 0xca: pos += 4; break;
        case 0xcb: pos += 8; break;

        // uint8, uint16, uint32, uint64
        case 0xcc: pos += 1; break;
        case 0xcd: pos += 2; break;
        case 0xce: pos += 4; break;
        case 0xcf: pos += 8; break;

        // int8, int16, int32, int64
        case 0xd0: pos += 1; break;
        case 0xd1: pos += 2; break;
        case 0xd2: pos += 4; break;
        case 0xd3: pos += 8; break;

        // fixext1..fixext16
        case 0xd4: pos += 2; break;
        case 0xd5: pos += 3; break;
        case 0xd6: pos += 5; break;
        case 0xd7: pos += 9; break;
        case 0xd8: pos += 17; break;

        // str8, str16, str32
        case 0xd9: { size_t n = read_byte(); pos += n; break; }
        case 0xda: { size_t n = read_be16(); pos += n; break; }
        case 0xdb: { size_t n = read_be32(); pos += n; break; }

        // array16, array32
        case 0xdc: { uint16_t n = read_be16(); for (uint16_t i = 0; i < n; i++) skip(); return; }
        case 0xdd: { uint32_t n = read_be32(); for (uint32_t i = 0; i < n; i++) skip(); return; }

        // map16, map32
        case 0xde: { uint16_t n = read_be16(); for (uint32_t i = 0; i < (uint32_t)n * 2; i++) skip(); return; }
        case 0xdf: { uint32_t n = read_be32(); for (uint64_t i = 0; i < (uint64_t)n * 2; i++) skip(); return; }

        default:
            // Negative fixint (0xe0-0xff) — already consumed by read_byte
            if (tag >= 0xe0) return;
            error = true;  // 0xc1 reserved
            return;
    }

    if (pos > len) error = true;
}

} // namespace msg
