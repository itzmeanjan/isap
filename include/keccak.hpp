#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>

// Keccak-p[400] permutation, adapted from my previous work on Keccak-p[1600]
// https://github.com/itzmeanjan/merklize-sha/blob/53c339d/include/sha3.hpp
namespace keccak {

// # -of times keccak-p[400] permutation round function to be applied on state
// array of dimension 5 x 5 x 16
constexpr size_t ROUNDS = 20;

// Leftwards circular rotation offset of 24 lanes of state array ( except
// lane(0, 0), which is not touched ), as provided in table 2 below algorithm 2
// in section 3.2.2 of http://dx.doi.org/10.6028/NIST.FIPS.202
//
// Note, following offsets are obtained by performing % 16 ( = lane size in bits
// ) on offsets provided in above mentioned link
constexpr size_t ROT[24] = { 1 & 15,   190 & 15, 28 & 15,  91 & 15,  36 & 15,
                             300 & 15, 6 & 15,   55 & 15,  276 & 15, 3 & 15,
                             10 & 15,  171 & 15, 153 & 15, 231 & 15, 105 & 15,
                             45 & 15,  15 & 15,  21 & 15,  136 & 15, 210 & 15,
                             66 & 15,  253 & 15, 120 & 15, 78 & 15 };

// Round constants to be XORed with lane (0, 0) of keccak-p[400] permutation
// state, see section 3.2.5 of http://dx.doi.org/10.6028/NIST.FIPS.202
constexpr uint16_t RC[ROUNDS] = { 1,     32898, 32906, 32768, 32907,
                                  1,     32897, 32777, 138,   136,
                                  32777, 10,    32907, 139,   32905,
                                  32771, 32770, 128,   32778, 10 };

// keccak-p[400] step mapping function `θ`, see specification in section 3.2.1
// of http://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
theta(uint16_t* const state)
{
  uint16_t c[5];
  uint16_t d[5];

  for (size_t x = 0; x < 5; x++) {
    const uint16_t t0 = state[x] ^ state[x + 5];
    const uint16_t t1 = state[x + 10] ^ state[x + 15];
    const uint16_t t2 = t0 ^ t1 ^ state[x + 20];

    c[x] = t2;
  }

  for (size_t x = 1; x < 5; x++) {
    d[x] = c[x - 1] ^ std::rotl(c[(x + 1) % 5], 1);
  }

  d[0] = c[4] ^ std::rotl(c[1], 1);

  for (size_t x = 0; x < 5; x++) {
    state[x + 0] ^= d[0];
    state[x + 5] ^= d[1];
    state[x + 10] ^= d[2];
    state[x + 15] ^= d[3];
    state[x + 20] ^= d[4];
  }
}

// keccak-p[400] step mapping function `ρ`, see specification in section 3.2.2
// of http://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
rho(uint16_t* const state)
{
  for (size_t i = 1; i < 25; i++) {
    state[i] = std::rotl(state[i], ROT[i - 1]);
  }
}

// keccak-p[400] step mapping function `π`, see specification in section 3.2.3
// of http://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
pi(const uint16_t* __restrict state_in, uint16_t* const __restrict state_out)
{
  for (size_t y = 0; y < 5; y++) {
    for (size_t x = 0; x < 5; x++) {
      state_out[y * 5 + x] = state_in[5 * x + (x + 3 * y) % 5];
    }
  }
}

// keccak-p[400] step mapping function `χ`, see specification in section 3.2.4
// of http://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
chi(const uint16_t* __restrict state_in, uint16_t* const __restrict state_out)
{
  for (size_t y = 0; y < 5; y++) {
    const size_t yoff = y * 5;

    for (size_t x = 0; x < 5; x++) {
      const size_t x0 = (x + 1) % 5;
      const size_t x1 = (x + 2) % 5;

      state_out[yoff + x] ^= ~state_in[yoff + x0] & state_in[yoff + x1];
    }
  }
}

// keccak-p[400] step mapping function `ι`, see specification in section 3.2.5
// of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline void
iota(uint16_t* const state, const size_t r_idx)
{
  state[0] ^= RC[r_idx];
}

// keccak-p[400] round function, which applies all five
// step mapping functions in order, updating state array
//
// See section 3.3 of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline void
round(uint16_t* const state, const size_t r_idx)
{
  uint16_t tmp[25];

  theta(state);
  rho(state);
  pi(state, tmp);
  chi(tmp, state);
  iota(state, r_idx);
}

// keccak-p[400] permutation, applying n_r ( = 20 ) rounds
// on state of dimension 5 x 5 x 16, using algorithm 7
// defined in section 3.3 of http://dx.doi.org/10.6028/NIST.FIPS.202
static inline void
permute(uint16_t* const state)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    round(state, i);
  }
}

}
