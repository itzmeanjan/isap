#pragma once
#include "isap_k_128a.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>
#include <cstring>

// Benchmark ISAP Authenticated Encryption with Associated Data
namespace isap_bench {

// Benchmarks ISAP-K-128A instance's encrypt routine on CPU based systems
static void
isap_k_128a_aead_encrypt(benchmark::State& state)
{
  const size_t dlen = static_cast<size_t>(state.range(0));
  const size_t mlen = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  random_data(key, 16);
  random_data(nonce, 16);
  random_data(data, dlen);
  random_data(txt, mlen);

  std::memset(tag, 0, 16);
  std::memset(enc, 0, mlen);
  std::memset(dec, 0, mlen);

  for (auto _ : state) {
    isap_k_128a::encrypt(key, nonce, data, dlen, txt, enc, mlen, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  // --- test correctness ---
  bool f0 = false;
  f0 = isap_k_128a::decrypt(key, nonce, tag, data, dlen, enc, dec, mlen);

  assert(f0);

  bool f1 = false;
  for (size_t i = 0; i < mlen; i++) {
    f1 |= txt[i] ^ dec[i];
  }

  assert(!f1);
  // --- test correctness ---

  const size_t per_itr = mlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

// Benchmarks ISAP-K-128A instance's decrypt routine on CPU based systems
static void
isap_k_128a_aead_decrypt(benchmark::State& state)
{
  const size_t dlen = static_cast<size_t>(state.range(0));
  const size_t mlen = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  random_data(key, 16);
  random_data(nonce, 16);
  random_data(data, dlen);
  random_data(txt, mlen);

  std::memset(tag, 0, 16);
  std::memset(enc, 0, mlen);
  std::memset(dec, 0, mlen);

  isap_k_128a::encrypt(key, nonce, data, dlen, txt, enc, mlen, tag);

  for (auto _ : state) {
    bool f = false;
    f = isap_k_128a::decrypt(key, nonce, tag, data, dlen, enc, dec, mlen);

    benchmark::DoNotOptimize(f);
    benchmark::DoNotOptimize(dec);
    benchmark::ClobberMemory();
  }

  // --- test correctness ---
  bool f = false;
  for (size_t i = 0; i < mlen; i++) {
    f |= txt[i] ^ dec[i];
  }

  assert(!f);
  // --- test correctness ---

  const size_t per_itr = mlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

}
