#pragma once
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <type_traits>

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
