#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>

// Keccak-p[400] permutation, adapted from my previous work on Keccak-p[1600]
// https://github.com/itzmeanjan/merklize-sha/blob/53c339d/include/sha3.hpp
namespace keccak {

// Maximum number of Keccak-p[400] rounds that can be (safely) applied on state
constexpr size_t MAX_ROUNDS = 20;

// Leftwards circular rotation offset of 24 lanes of state array ( except
// lane(0, 0), which is not touched ), as provided in table 2 below algorithm 2
// in section 3.2.2 of http://dx.doi.org/10.6028/NIST.FIPS.202
//
// Note, following offsets are obtained by performing % 16 ( = lane size in bits
// ) on offsets provided in above mentioned link
constexpr size_t ROT[24]{ 1 & 15,   190 & 15, 28 & 15,  91 & 15,  36 & 15,
                          300 & 15, 6 & 15,   55 & 15,  276 & 15, 3 & 15,
                          10 & 15,  171 & 15, 153 & 15, 231 & 15, 105 & 15,
                          45 & 15,  15 & 15,  21 & 15,  136 & 15, 210 & 15,
                          66 & 15,  253 & 15, 120 & 15, 78 & 15 };

// Precomputed table used for looking up source index during application of π
// step mapping function on keccak-p[400] state
//
// print('to <= from')
// for y in range(5):
//    for x in range(5):
//        print(f'{y * 5 + x} <= {x * 5 + (x + 3 * y) % 5}')
//
// Table generated using above Python code snippet. See section 3.2.3 of the
// specification https://dx.doi.org/10.6028/NIST.FIPS.202
//
// Taken from
// https://github.com/itzmeanjan/sha3/blob/b5e897ed8002c94569a5d7433f65ba606880ac12/include/keccak.hpp#L37-L48
constexpr size_t PERM[]{ 0,  6,  12, 18, 24, 3,  9,  10, 16, 22, 1,  7, 13,
                         19, 20, 4,  5,  11, 17, 23, 2,  8,  14, 15, 21 };

// Round constants to be XORed with lane (0, 0) of keccak-p[400] permutation
// state, see section 3.2.5 of http://dx.doi.org/10.6028/NIST.FIPS.202
constexpr uint16_t RC[MAX_ROUNDS]{ 1,     32898, 32906, 32768, 32907,
                                   1,     32897, 32777, 138,   136,
                                   32777, 10,    32907, 139,   32905,
                                   32771, 32770, 128,   32778, 10 };

// keccak-p[400] step mapping function `θ`, see specification in section 3.2.1
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
theta(uint16_t* const state)
{
  uint16_t c[5]{}; // initialization with zeros is important
  uint16_t d[5];

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 5
#endif
  for (size_t x = 0; x < 25; x += 5) {
    c[0] ^= state[x + 0];
    c[1] ^= state[x + 1];
    c[2] ^= state[x + 2];
    c[3] ^= state[x + 3];
    c[4] ^= state[x + 4];
  }

  d[0] = c[4] ^ std::rotl(c[1], 1);
  d[1] = c[0] ^ std::rotl(c[2], 1);
  d[2] = c[1] ^ std::rotl(c[3], 1);
  d[3] = c[2] ^ std::rotl(c[4], 1);
  d[4] = c[3] ^ std::rotl(c[0], 1);

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 5
#endif
  for (size_t x = 0; x < 25; x += 5) {
    state[x + 0] ^= d[0];
    state[x + 1] ^= d[1];
    state[x + 2] ^= d[2];
    state[x + 3] ^= d[3];
    state[x + 4] ^= d[4];
  }
}

// keccak-p[400] step mapping function `ρ`, see specification in section 3.2.2
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
rho(uint16_t* const state)
{
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 24
#endif
  for (size_t i = 1; i < 25; i++) {
    state[i] = std::rotl(state[i], ROT[i - 1]);
  }
}

// keccak-p[400] step mapping function `π`, see specification in section 3.2.3
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
pi(const uint16_t* __restrict state_in, uint16_t* const __restrict state_out)
{
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUC__
#pragma GCC ivdep
#pragma GCC unroll 25
#endif
  for (size_t i = 0; i < 25; i++) {
    state_out[i] = state_in[PERM[i]];
  }
}

// keccak-p[400] step mapping function `χ`, see specification in section 3.2.4
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
chi(const uint16_t* __restrict state_in, uint16_t* const __restrict state_out)
{
  for (size_t y = 0; y < 5; y++) {
    const size_t yoff = y * 5;

#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 5
#endif
    for (size_t x = 0; x < 5; x++) {
      const size_t x0 = (x + 1) % 5;
      const size_t x1 = (x + 2) % 5;

      const uint16_t rhs = ~state_in[yoff + x0] & state_in[yoff + x1];
      state_out[yoff + x] = state_in[yoff + x] ^ rhs;
    }
  }
}

// keccak-p[400] step mapping function `ι`, see specification in section 3.2.5
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
iota(uint16_t* const state, const size_t r_idx)
{
  state[0] ^= RC[r_idx];
}

// keccak-p[400] round function, which applies all five
// step mapping functions in order, updating state array
//
// See section 3.3 of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline constexpr void
round(uint16_t* const state, const size_t r_idx)
{
  uint16_t tmp[25];

  theta(state);
  rho(state);
  pi(state, tmp);
  chi(tmp, state);
  iota(state, r_idx);
}

// keccak-p[400] permutation, applying ROUNDS -many rounds of permutation
// on state of dimension 5 x 5 x 16, using algorithm 7 defined in section 3.3 of
// http://dx.doi.org/10.6028/NIST.FIPS.202
template<const size_t ROUNDS>
static inline constexpr void
permute(uint16_t* const state)
  requires(ROUNDS <= MAX_ROUNDS)
{
  constexpr size_t beg = MAX_ROUNDS - ROUNDS;

  for (size_t i = beg; i < MAX_ROUNDS; i++) {
    round(state, i);
  }
}

}
