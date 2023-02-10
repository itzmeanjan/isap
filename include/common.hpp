#pragma once
#include "ascon.hpp"
#include "keccak.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstring>
#include <iterator>
#include <type_traits>

// ISAP AEAD common functions
namespace isap_common {

// Which permutation is being used for AEAD scheme
enum class perm_t : uint32_t
{
  ASCON, // Ascon-p used in ISAP-A-128{A}
  KECCAK // Keccak-p[400] used in ISAP-K-128{A}
};

// Generate session key for encryption/ authentication operation
enum class rk_flag_t : uint32_t
{
  ENC, // encryption mode
  MAC  // authentication mode
};

// Ascon-p, Keccak-p[400] permutation's state byte length,
// see column `n` of table 2.2 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr size_t PERM_STATE_LEN[]{ 40, 50 };

// Byte length of secret key, nonce & authentication tag, see table 2.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr size_t knt_len = 16;

// Generates session key `Ke` for encryption & `Ka` for authentication, given
// 128 -bit secret key, 128 -bit string Y & a flag denoting encryption/
// authentication mode
//
// Read section 2.1 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 4 ( named `ISAP_Rk` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const rk_flag_t f,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
rekeying(const uint8_t* const __restrict key,
         const uint8_t* const __restrict y,
         uint8_t* const __restrict skey)
{
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);

  constexpr size_t Z[]{ slen - knt_len, knt_len };
  constexpr size_t z = Z[static_cast<size_t>(f)];

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KA[8]{ 0x02, knt_len << 3, rate << 3, 0x01,
                              s_h,  s_b,          s_e,       s_k };

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KE[8]{ 0x03, knt_len << 3, rate << 3, 0x01,
                              s_h,  s_b,          s_e,       s_k };

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    uint64_t state[5]{};

    std::memcpy(state, key, knt_len);
    if constexpr (std::endian::native == std::endian::little) {
      state[0] = bswap(state[0]);
      state[1] = bswap(state[1]);
    }

    if constexpr (f == rk_flag_t::ENC) {
      static_assert(f == rk_flag_t::ENC, "Rekeying mode must be ENC !");

      std::memcpy(state + 2, IV_KE, sizeof(IV_KE));
      if constexpr (std::endian::native == std::endian::little) {
        state[2] = bswap(state[2]);
      }
    } else {
      static_assert(f == rk_flag_t::MAC, "Rekeying mode must be MAC !");

      std::memcpy(state + 2, IV_KA, sizeof(IV_KA));
      if constexpr (std::endian::native == std::endian::little) {
        state[2] = bswap(state[2]);
      }
    }

    ascon::permute<s_k>(state);

    // --- end initialization ---

    // --- begin absorption ---

    constexpr size_t bits = (knt_len << 3) - 1;

    for (size_t i = 0; i < bits; i++) {
      const size_t off = i >> 3;       // byte offset
      const size_t bpos = 7 - (i & 7); // bit position in selected byte

      const uint8_t bit = (y[off] >> bpos) & 0b1;
      state[0] ^= static_cast<uint64_t>(bit) << 63;

      ascon::permute<s_b>(state);
    }

    const uint8_t bit = y[15] & 0b1;
    state[0] ^= static_cast<uint64_t>(bit) << 63;

    ascon::permute<s_k>(state);

    // --- end absorption ---

    // --- begin squeezing ---

    if constexpr (z == 24) {
      static_assert(z == 24, "Session key should be 24 -bytes wide !");

      if constexpr (std::endian::native == std::endian::little) {
        const auto t0 = bswap(state[0]);
        std::memcpy(skey, &t0, sizeof(t0));

        const auto t1 = bswap(state[1]);
        std::memcpy(skey + 8, &t1, sizeof(t1));

        const auto t2 = bswap(state[2]);
        std::memcpy(skey + 16, &t2, sizeof(t2));
      } else {
        std::memcpy(skey, state, z);
      }
    } else {
      static_assert(z == 16, "Session key should be 16 -bytes wide !");

      if constexpr (std::endian::native == std::endian::little) {
        const auto t0 = bswap(state[0]);
        std::memcpy(skey, &t0, sizeof(t0));

        const auto t1 = bswap(state[1]);
        std::memcpy(skey + 8, &t1, sizeof(t1));
      } else {
        std::memcpy(skey, state, z);
      }
    }

    // --- end squeezing ---

  } else {
    // --- begin initialization ---

    uint16_t state[25]{};

    std::memcpy(state, key, knt_len);
    if constexpr (std::endian::native == std::endian::big) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < knt_len / 2; i++) {
        state[i] = bswap(state[i]);
      }
    }

    if constexpr (f == rk_flag_t::ENC) {
      static_assert(f == rk_flag_t::ENC, "Rekeying mode must be ENC !");

      std::memcpy(state + 8, IV_KE, sizeof(IV_KE));
      if constexpr (std::endian::native == std::endian::big) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 4
#endif
        for (size_t i = 8; i < 8 + (sizeof(IV_KE) / 2); i++) {
          state[i] = bswap(state[i]);
        }
      }
    } else {
      static_assert(f == rk_flag_t::MAC, "Rekeying mode must be MAC !");

      std::memcpy(state + 8, IV_KA, sizeof(IV_KA));
      if constexpr (std::endian::native == std::endian::big) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 4
#endif
        for (size_t i = 8; i < 8 + (sizeof(IV_KA) / 2); i++) {
          state[i] = bswap(state[i]);
        }
      }
    }

    keccak::permute<s_k>(state);

    // --- end initialization ---

    // --- begin absorption ---

    constexpr size_t bits = (knt_len << 3) - 1;

    for (size_t i = 0; i < bits; i++) {
      const size_t off = i >> 3;       // byte offset
      const size_t bpos = 7 - (i & 7); // bit position in selected byte

      const uint8_t bit = (y[off] >> bpos) & 0b1;
      state[0] ^= static_cast<uint16_t>(bit) << 7;

      keccak::permute<s_b>(state);
    }

    const uint8_t bit = y[15] & 0b1;
    state[0] ^= static_cast<uint16_t>(bit) << 7;

    keccak::permute<s_k>(state);

    // --- end absorption ---

    // --- begin squeezing ---

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(skey, state, z);
    } else {
      for (size_t i = 0; i < z / 2; i++) {
        const auto t = bswap(state[i]);
        std::memcpy(skey + i * 2, &t, sizeof(t));
      }
    }

    // --- end squeezing ---
  }
}

// Encrypts/ decrypts N -many message bytes ( producing equal many encrypted/
// decrypted bytes as output ), using keyed sponge construction in streaming
// mode, when 128 -bit secret key, 128 -bit public message nonce is provided
//
// Read section 2.2 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 3 ( named `ISAP_Enc` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
enc(const uint8_t* const __restrict key,
    const uint8_t* const __restrict nonce,
    const uint8_t* const __restrict msg,
    uint8_t* const __restrict out,
    const size_t mlen)
{
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;
    uint8_t skey[z];
    rekeying<p, rk_flag_t::ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint64_t state[5];
    std::memcpy(state, skey, z);
    std::memcpy(state + (z / 8), nonce, knt_len);

    if constexpr (std::endian::native == std::endian::little) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 5
#endif
      for (size_t i = 0; i < 5; i++) {
        state[i] = bswap(state[i]);
      }
    }

    // --- end initialization ---

    // --- begin squeezing ---

    size_t off = 0;
    while (off < mlen) {
      ascon::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);

      uint64_t mword = 0;
      std::memcpy(&mword, msg + off, elen);
      if constexpr (std::endian::native == std::endian::little) {
        mword = bswap(mword);
      }

      uint64_t eword = mword ^ state[0];
      if constexpr (std::endian::native == std::endian::little) {
        eword = bswap(eword);
      }
      std::memcpy(out + off, &eword, elen);

      off += elen;
    }

    // --- end squeezing ---

  } else {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;
    uint8_t skey[z];
    rekeying<p, rk_flag_t::ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint16_t state[25];
    std::memcpy(state, skey, z);
    std::memcpy(state + (z / 2), nonce, knt_len);

    if constexpr (std::endian::native == std::endian::big) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 25
#endif
      for (size_t i = 0; i < 25; i++) {
        state[i] = bswap(state[i]);
      }
    }

    // --- end initialization ---

    // --- begin squeezing ---

    size_t off = 0;
    while (off < mlen) {
      keccak::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);
      for (size_t i = 0; i < elen; i += 2) {
        uint16_t mword = 0;
        std::memcpy(&mword, msg + off + i, std::min(elen - i, sizeof(mword)));
        if constexpr (std::endian::native == std::endian::big) {
          mword = bswap(mword);
        }

        uint16_t eword = mword ^ state[i / 2];
        if constexpr (std::endian::native == std::endian::big) {
          eword = bswap(eword);
        }
        std::memcpy(out + off + i, &eword, std::min(elen - i, sizeof(eword)));
      }

      off += elen;
    }

    // --- end squeezing ---
  }
}

// Computes 128 -bit suffix-MAC ( message authentication code ), using sponge
// based hash function, used for message authentication purpose, given 128 -bit
// secret key, 128 -bit public message nonce, N -bytes associated data & M
// -bytes cipher text
//
// Read section 2.3 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 5 ( named `ISAP_Mac` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
mac(const uint8_t* const __restrict key,
    const uint8_t* const __restrict nonce,
    const uint8_t* const __restrict data,
    const size_t dlen,
    const uint8_t* const __restrict cipher,
    const size_t clen,
    uint8_t* const __restrict tag)
{
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);
  constexpr uint8_t seperator = 0b10000000;

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_A[8]{ 0x01, knt_len << 3, rate << 3, 0x01,
                             s_h,  s_b,          s_e,       s_k };

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    uint64_t state[5]{};

    std::memcpy(state, nonce, 16);
    std::memcpy(state + 2, IV_A, sizeof(IV_A));

    if constexpr (std::endian::native == std::endian::little) {
      for (size_t i = 0; i < 3; i++) {
        state[i] = bswap(state[i]);
      }
    }

    ascon::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      const size_t blk_cnt = dlen / rate;
      const size_t rm_bytes = dlen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;

        uint64_t word;
        std::memcpy(&word, data + off, sizeof(word));

        if constexpr (std::endian::native == std::endian::little) {
          word = bswap(word);
        }

        state[0] ^= word;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      uint64_t word = 0;
      std::memcpy(&word, data + off, rm_bytes);

      if constexpr (std::endian::native == std::endian::little) {
        word |= static_cast<uint64_t>(seperator) << (rm_bytes * 8);
        word = bswap(word);
      } else {
        word |= static_cast<uint64_t>(seperator) << ((7 - rm_bytes) * 8);
      }

      state[0] ^= word;
      ascon::permute<s_h>(state);

      state[4] ^= 0b1; // seperator between associated data & cipher text
    }
    // --- end absorbing associated data ---

    // --- begin absorbing cipher text ---
    {
      const size_t blk_cnt = clen / rate;
      const size_t rm_bytes = clen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;

        uint64_t word;
        std::memcpy(&word, cipher + off, sizeof(word));

        if constexpr (std::endian::native == std::endian::little) {
          word = bswap(word);
        }

        state[0] ^= word;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      uint64_t word = 0;
      std::memcpy(&word, cipher + off, rm_bytes);

      if constexpr (std::endian::native == std::endian::little) {
        word |= static_cast<uint64_t>(seperator) << (rm_bytes * 8);
        word = bswap(word);
      } else {
        word |= static_cast<uint64_t>(seperator) << ((7 - rm_bytes) * 8);
      }

      state[0] ^= word;
      ascon::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];
    uint64_t tmp[2];

    std::memcpy(tmp, state, sizeof(tmp));
    if constexpr (std::endian::native == std::endian::little) {
      tmp[0] = bswap(tmp[0]);
      tmp[1] = bswap(tmp[1]);
    }

    std::memcpy(y, tmp, sizeof(tmp));

    rekeying<p, rk_flag_t::MAC, s_b, s_k, s_e, s_h>(key, y, skey);

    std::memcpy(state, skey, sizeof(skey));
    if constexpr (std::endian::native == std::endian::little) {
      state[0] = bswap(state[0]);
      state[1] = bswap(state[1]);
    }

    ascon::permute<s_h>(state);

    std::memcpy(tmp, state, sizeof(tmp));
    if constexpr (std::endian::native == std::endian::little) {
      tmp[0] = bswap(tmp[0]);
      tmp[1] = bswap(tmp[1]);
    }
    std::memcpy(tag, tmp, sizeof(tmp));

    // --- end squeezing tag ---

  } else {
    // --- begin initialization ---

    uint16_t state[25]{};

    std::memcpy(state, nonce, 16);
    std::memcpy(state + 8, IV_A, sizeof(IV_A));

    if constexpr (std::endian::native == std::endian::big) {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 12
#endif
      for (size_t i = 0; i < 12; i++) {
        state[i] = bswap(state[i]);
      }
    }

    keccak::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      size_t off = 0;
      while (off < dlen) {
        const size_t elen = std::min(rate, dlen - off);

        for (size_t i = 0; i < elen; i += 2) {
          uint16_t mword = 0;
          std::memcpy(&mword, data + off + i, std::min(elen - i, 2ul));

          if constexpr (std::endian::native == std::endian::big) {
            mword = bswap(mword);
          }

          state[i / 2] ^= mword;
        }

        off += elen;

        if (elen == rate) [[likely]] {
          keccak::permute<s_h>(state);
        }
      }

      const size_t rm_bytes = dlen % rate;
      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) * 8;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;
      state[soff] ^= w;

      keccak::permute<s_h>(state);

      state[24] ^= 0b1 << 8; // seperator between associated data & cipher text
    }
    // --- end absorbing associated data ---

    // --- begin absorbing cipher text ---
    {
      size_t off = 0;
      while (off < clen) {
        const size_t elen = std::min(rate, clen - off);

        for (size_t i = 0; i < elen; i += 2) {
          uint16_t mword = 0;
          std::memcpy(&mword, cipher + off + i, std::min(elen - i, 2ul));

          if constexpr (std::endian::native == std::endian::big) {
            mword = bswap(mword);
          }

          state[i / 2] ^= mword;
        }

        off += elen;

        if (elen == rate) [[likely]] {
          keccak::permute<s_h>(state);
        }
      }

      const size_t rm_bytes = clen % rate;
      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) * 8;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;
      state[soff] ^= w;

      keccak::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(y, state, sizeof(y));
    } else {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 16
#endif
      for (size_t i = 0; i < knt_len; i++) {
        y[i] = static_cast<uint8_t>(state[i >> 1] >> ((i & 1) << 3));
      }
    }

    rekeying<p, rk_flag_t::MAC, s_b, s_k, s_e, s_h>(key, y, skey);

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(state, skey, sizeof(skey));
    } else {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < 8; i++) {
        const size_t skoff = i << 1;

        state[i] = (static_cast<uint16_t>(skey[skoff + 1]) << 8) |
                   (static_cast<uint16_t>(skey[skoff + 0]) << 0);
      }
    }

    keccak::permute<s_h>(state);

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(tag, state, 16);
    } else {
#if defined __clang__
#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 16
#endif
      for (size_t i = 0; i < knt_len; i++) {
        tag[i] = static_cast<uint8_t>(state[i >> 1] >> ((i & 1) << 3));
      }
    }

    // --- end squeezing tag ---
  }
}

}
