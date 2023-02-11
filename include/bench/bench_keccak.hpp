#pragma once
#include "keccak.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark ISAP Authenticated Encryption with Associated Data
namespace isap_bench {

// Benchmarks Keccak-p[400] permutation on CPU based systems, for specified #
// -of rounds
template<const size_t ROUNDS>
static void
keccak_permutation(benchmark::State& state)
{
  uint16_t pstate[25];
  isap_utils::random_data<uint16_t>(pstate, 25);

  for (auto _ : state) {
    keccak::permute<ROUNDS>(pstate);

    benchmark::DoNotOptimize(pstate);
    benchmark::ClobberMemory();
  }

  constexpr size_t per_itr = sizeof(pstate);
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));
}

}
