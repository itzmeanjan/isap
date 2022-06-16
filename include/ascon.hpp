#pragma once
#include "utils.hpp"
#include <bit>

// Ascon-p Permutation, copied from my previous implementation
// https://github.com/itzmeanjan/ascon/blob/58a1a1e/include/permutation.hpp
namespace ascon {

// Ascon-p round constants; taken from table A.2 in ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr uint64_t RC[12] = { 0x00000000000000f0ul, 0x00000000000000e1ul,
                              0x00000000000000d2ul, 0x00000000000000c3ul,
                              0x00000000000000b4ul, 0x00000000000000a5ul,
                              0x0000000000000096ul, 0x0000000000000087ul,
                              0x0000000000000078ul, 0x0000000000000069ul,
                              0x000000000000005aul, 0x000000000000004bul };

// Addition of constants step; see appendix A of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
inline static void
p_c(uint64_t* const state, const size_t c_idx)
{
  state[2] ^= RC[c_idx];
}

// Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken from
// figure 5 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
inline static void
p_s(uint64_t* const state)
{
  state[0] ^= state[4];
  state[4] ^= state[3];
  state[2] ^= state[1];

  const uint64_t t0 = state[1] & ~state[0];
  const uint64_t t1 = state[2] & ~state[1];
  const uint64_t t2 = state[3] & ~state[2];
  const uint64_t t3 = state[4] & ~state[3];
  const uint64_t t4 = state[0] & ~state[4];

  state[0] ^= t1;
  state[1] ^= t2;
  state[2] ^= t3;
  state[3] ^= t4;
  state[4] ^= t0;

  state[1] ^= state[0];
  state[0] ^= state[4];
  state[3] ^= state[2];
  state[2] = ~state[2];
}

// Linear diffusion layer; taken from figure A.1 in ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
inline static void
p_l(uint64_t* const state)
{
  using namespace std;

  state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28);
  state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39);
  state[2] ^= rotr(state[2], 1) ^ rotr(state[2], 6);
  state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17);
  state[4] ^= rotr(state[4], 7) ^ rotr(state[4], 41);
}

// Ascon permutation; taken from appendix A of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
inline static void
permute(uint64_t* const state, const size_t c_idx)
{
  p_c(state, c_idx);
  p_s(state);
  p_l(state);
}

// Permutation `p_a` to be sequentially applied on state for `a` -many
// times | a = 12; taken from appendix A of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const size_t a>
inline static void
p_a(uint64_t* const state) requires(check_12(a))
{
  for (size_t i = 0; i < a; i++) {
    permute(state, i);
  }
}

// Permutation `p_b` to be sequentially applied on state for `b` -many
// times | b ∈ {6, 8, 12}; taken from appendix A of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const size_t b>
inline static void
p_b(uint64_t* const state) requires(check_6(b) || check_8(b) || check_12(b))
{
  constexpr size_t a = 12;

  for (size_t i = a - b; i < a; i++) {
    permute(state, i);
  }
}

}
