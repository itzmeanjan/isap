#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Utility Routines used in ISAP AEAD Scheme
namespace isap_utils {

// Given a {16, 64} -bit unsigned integer word, this routine swaps byte order
// and returns byte swapped {16, 64} -bit word.
//
// Collects inspiration from
// https://github.com/itzmeanjan/photon-beetle/blob/140b2f316c21633eb0cb717fd15b8348e6c010fd/include/utils.hpp#L11-L25
template<typename T>
static inline constexpr T
bswap(const T a)
  requires(std::is_unsigned_v<T> && ((sizeof(T) == 2) || (sizeof(T) == 8)))
{
  if constexpr (sizeof(T) == 2) {
    // uint16_t

#if defined __GNUG__
    return __builtin_bswap16(a);
#else
    return ((a & 0x00ff) << 8) | ((a & 0xff00) >> 8);
#endif

  } else {
    // uint64_t

#if defined __GNUG__
    return __builtin_bswap64(a);
#else
    return ((a & 0x00000000000000fful) << 56) |
           ((a & 0x000000000000ff00ul) << 40) |
           ((a & 0x0000000000ff0000ul) << 24) |
           ((a & 0x00000000ff000000ul) << 0x8) |
           ((a & 0x000000ff00000000ul) >> 0x8) |
           ((a & 0x0000ff0000000000ul) >> 24) |
           ((a & 0x00ff000000000000ul) >> 40) |
           ((a & 0xff00000000000000ul) >> 56);
#endif
  }
}

// Given N (>=0) -many bytes, this routine copies them to 64 -bit unsigned
// integer target s.t. these bytes are interpreted in big-endian byte order.
//
// Note, N doesn't necessarily need to be multiple of 8. Last u64 word can be
// partially filled.
static inline void
copy_bytes_to_be_u64(const uint8_t* const __restrict bytes,
                     const size_t blen,
                     uint64_t* const __restrict words)
{
  std::memcpy(words, bytes, blen);

  if constexpr (std::endian::native == std::endian::little) {
    // # of u64 words ( last one may be partially filled )
    const size_t wlen = (blen + 7) / 8;
    for (size_t i = 0; i < wlen; i++) {
      words[i] = bswap(words[i]);
    }
  }
}

// Given N (>=0) -many bytes, this routine copies them to 16 -bit unsigned
// integer target s.t. these bytes are interpreted in little-endian byte order.
//
// Note, N doesn't necessarily need to be multiple of 2. Last u16 word can be
// partially filled.
static inline void
copy_bytes_to_le_u16(const uint8_t* const __restrict bytes,
                     const size_t blen,
                     uint16_t* const __restrict words)
{
  std::memcpy(words, bytes, blen);

  if constexpr (std::endian::native == std::endian::big) {
    // # of u16 words ( last one may be partially filled )
    const size_t wlen = (blen + 1) / 2;
    for (size_t i = 0; i < wlen; i++) {
      words[i] = bswap(words[i]);
    }
  }
}

// Given N (>=0) -many bytes, this routine copies them to 64 -bit unsigned
// integer target s.t. these bytes are interpreted in little-endian byte order.
//
// Note, N doesn't necessarily need to be multiple of 8. Last u64 word can be
// partially filled.
static inline void
copy_bytes_to_le_u64(const uint8_t* const __restrict bytes,
                     const size_t blen,
                     uint64_t* const __restrict words)
{
  std::memcpy(words, bytes, blen);

  if constexpr (std::endian::native == std::endian::big) {
    // # of u64 words ( last one may be partially filled )
    const size_t wlen = (blen + 7) / 8;
    for (size_t i = 0; i < wlen; i++) {
      words[i] = bswap(words[i]);
    }
  }
}

// Given N (>=0) -many bytes, this routine copies 16 -bit unsigned integer
// source to 64 -bit unsigned integer target s.t. both source and destination
// bytes are interpreted in little-endian byte order.
static inline void
copy_le_u16_to_le_u64(const uint16_t* const __restrict u16s,
                      const size_t blen,
                      uint64_t* const __restrict u64s)
{
  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(u64s, u16s, blen);
  } else {
    for (size_t i = 0; i < blen; i++) {
      const uint8_t byte = static_cast<uint8_t>(u16s[i / 2] >> ((i & 1) * 8));
      u64s[i / 8] |= static_cast<uint64_t>(byte) << ((i & 7) * 8);
    }
  }
}

// Given little-endian byte ordered 64 -bit unsigned integers, this routine
// copies N (>=0) -many bytes ( from those u64 words ) to destination u16 array
// s.t. both source and destination interprets bytes in little-endian order.
static inline void
copy_le_u64_to_le_u16(const uint64_t* const __restrict u64s,
                      uint16_t* const __restrict u16s,
                      const size_t blen)
{
  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(u16s, u64s, blen);
  } else {
    for (size_t i = 0; i < blen; i++) {
      const uint8_t byte = static_cast<uint8_t>(u64s[i / 8] >> ((i & 7) * 8));
      u16s[i / 2] |= static_cast<uint16_t>(byte) << ((i & 1) * 8);
    }
  }
}

// Given little-endian byte ordered 64 -bit unsigned integers, this routine
// copies N (>=0) -many bytes ( from those u64 words ) to destination byte
// array.
//
// Note, N doesn't necessarily need to be multiple of 8. It may not be necessary
// to copy all bytes of last u64 word.
static inline void
copy_le_u64_to_bytes(const uint64_t* const __restrict words,
                     uint8_t* const __restrict bytes,
                     const size_t blen)
{
  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(bytes, words, blen);
  } else {
    size_t boff = 0;
    while (boff < blen) {
      const size_t elen = std::min(blen - boff, 8ul);
      const uint64_t v = bswap(words[boff / 8]);

      std::memcpy(bytes + boff, &v, elen);
      boff += elen;
    }
  }
}

// Given big-endian byte ordered 64 -bit unsigned integers, this routine copies
// N (>=0) -many bytes ( from those u64 words ) to destination byte array.
//
// Note, N doesn't necessarily need to be multiple of 8. It may not be necessary
// to copy all bytes of last u64 word.
static inline void
copy_be_u64_to_bytes(const uint64_t* const __restrict words,
                     uint8_t* const __restrict bytes,
                     const size_t blen)
{
  if constexpr (std::endian::native == std::endian::little) {
    size_t boff = 0;
    while (boff < blen) {
      const size_t elen = std::min(blen - boff, 8ul);
      const uint64_t v = bswap(words[boff / 8]);

      std::memcpy(bytes + boff, &v, elen);
      boff += elen;
    }
  } else {
    std::memcpy(bytes, words, blen);
  }
}

// Given little-endian byte ordered 16 -bit unsigned integers, this routine
// copies N (>=0) -many bytes ( from those u16 words ) to destination byte
// array.
//
// Note, N doesn't necessarily need to be multiple of 2. It may not be necessary
// to copy all bytes of last u16 word.
static inline void
copy_le_u16_to_bytes(const uint16_t* const __restrict words,
                     uint8_t* const __restrict bytes,
                     const size_t blen)
{
  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(bytes, words, blen);
  } else {
    size_t boff = 0;
    while (boff < blen) {
      const size_t elen = std::min(blen - boff, 2ul);
      const uint16_t v = bswap(words[boff / 2]);

      std::memcpy(bytes + boff, &v, elen);
      boff += elen;
    }
  }
}

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1 | N >= 0
static inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

// Generates N -many random elements of type T | N >= 0
template<typename T>
inline static void
random_data(T* const data, const size_t dlen)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<T> dis;

  for (size_t i = 0; i < dlen; i++) {
    data[i] = dis(gen);
  }
}

}
