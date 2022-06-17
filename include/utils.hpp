#pragma once
#include <cstddef>
#include <cstdint>

// Compile-time check to ensure # -of rounds Ascon-p permutation to be applied,
// is lesser than 12
inline static constexpr bool
check_lt_12(const size_t x)
{
  return x <= 12;
}
