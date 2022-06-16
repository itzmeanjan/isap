#pragma once
#include <cstddef>
#include <cstdint>

// Compile-time check to ensure # -of rounds permutation to be applied, is set
// to 6
inline static constexpr bool
check_6(const size_t x)
{
  return !static_cast<bool>(x ^ 6);
}

// Compile-time check to ensure # -of rounds permutation to be applied, is set
// to 8
inline static constexpr bool
check_8(const size_t x)
{
  return !static_cast<bool>(x ^ 8);
}

// Compile-time check to ensure # -of rounds permutation to be applied, is set
// to 12
inline static constexpr bool
check_12(const size_t x)
{
  return !static_cast<bool>(x ^ 12);
}
