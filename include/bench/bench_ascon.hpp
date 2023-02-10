#pragma once
#include "ascon.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark ISAP Authenticated Encryption with Associated Data
namespace isap_bench {

// Benchmarks Ascon permutation on CPU based systems, for specified # -of rounds
template<const size_t ROUNDS>
static void
ascon_permutation(benchmark::State& state)
{
  uint64_t pstate[5];
  isap_utils::random_data<uint64_t>(pstate, 5);

  for (auto _ : state) {
    ascon::permute<ROUNDS>(pstate);

    benchmark::DoNotOptimize(pstate);
    benchmark::ClobberMemory();
  }

  constexpr size_t per_itr = sizeof(pstate);
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));
}

}
