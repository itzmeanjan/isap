#include "bench/bench_isap.hpp"

// registering Ascon permutation for benchmark
BENCHMARK(isap_bench::ascon_permutation<1>);
BENCHMARK(isap_bench::ascon_permutation<6>);
BENCHMARK(isap_bench::ascon_permutation<12>);

// registering Keccak-p[400] permutation for benchmark
BENCHMARK(isap_bench::keccak_permutation<1>);
BENCHMARK(isap_bench::keccak_permutation<8>);
BENCHMARK(isap_bench::keccak_permutation<12>);
BENCHMARK(isap_bench::keccak_permutation<16>);
BENCHMARK(isap_bench::keccak_permutation<20>);

// registering ISAP-A-128A encrypt/ decrypt routines for benchmark
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_a_128a_aead_encrypt)->Args({ 32, 4096 });
BENCHMARK(isap_bench::isap_a_128a_aead_decrypt)->Args({ 32, 4096 });

// registering ISAP-A-128 encrypt/ decrypt routines for benchmark
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_a_128_aead_encrypt)->Args({ 32, 4096 });
BENCHMARK(isap_bench::isap_a_128_aead_decrypt)->Args({ 32, 4096 });

// registering ISAP-K-128A encrypt/ decrypt routines for benchmark
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_k_128a_aead_encrypt)->Args({ 32, 4096 });
BENCHMARK(isap_bench::isap_k_128a_aead_decrypt)->Args({ 32, 4096 });

// registering ISAP-K-128 encrypt/ decrypt routines for benchmark
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 64 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 128 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 256 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 512 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 1024 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 2048 });
BENCHMARK(isap_bench::isap_k_128_aead_encrypt)->Args({ 32, 4096 });
BENCHMARK(isap_bench::isap_k_128_aead_decrypt)->Args({ 32, 4096 });

// main function to drive execution of benchmark
BENCHMARK_MAIN();
