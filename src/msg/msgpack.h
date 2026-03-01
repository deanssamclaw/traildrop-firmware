#pragma once
// Minimal msgpack encoder/decoder for LXMF compatibility
// Supports: fixarray, array16, fixmap, float64, bin8/bin16,
//           fixstr, str8, positive fixint, uint8, uint16, int8, nil, bool

#include <cstdint>
#include <cstddef>

namespace msg {

struct Encoder {
    uint8_t* buf;
    size_t cap;
    size_t pos;
    bool error;

    Encoder(uint8_t* buffer, size_t capacity);

    void write_array(uint8_t count);      // fixarray (0-15) or array16 (16-255)
    void write_map(uint8_t count);        // fixmap (0-15)
    void write_float64(double val);       // 0xcb + 8 bytes big-endian IEEE 754
    void write_bin(const uint8_t* data, size_t len);  // bin8/bin16
    void write_str(const char* str, size_t len);      // fixstr/str8
    void write_uint(uint32_t val);        // fixint/uint8/uint16/uint32
    void write_int(int32_t val);          // fixint/negfixint/int8
    void write_nil();                     // 0xc0
    void write_bool(bool val);            // 0xc2/0xc3

private:
    void write_byte(uint8_t b);
    void write_bytes(const uint8_t* data, size_t len);
    void write_be16(uint16_t val);
    void write_be64(uint64_t val);
};

struct Decoder {
    const uint8_t* buf;
    size_t len;
    size_t pos;
    bool error;

    Decoder(const uint8_t* buffer, size_t length);

    uint8_t peek_type();                  // peek next type tag without consuming
    uint8_t read_array();                 // returns element count
    uint8_t read_map();                   // returns entry count
    double read_float64();
    size_t read_bin(uint8_t* out, size_t max_len);  // returns actual length
    size_t read_str(char* out, size_t max_len);     // returns actual length
    uint32_t read_uint();
    int32_t read_int();
    void read_nil();
    bool read_bool();
    void skip();                          // skip one element (any type)

private:
    uint8_t read_byte();
    void read_bytes(uint8_t* out, size_t count);
    uint16_t read_be16();
    uint32_t read_be32();
    uint64_t read_be64();
};

} // namespace msg
