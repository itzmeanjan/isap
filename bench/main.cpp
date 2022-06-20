#include "bench_isap_a_128.hpp"
#include "bench_isap_a_128a.hpp"

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

// main function to drive execution of benchmark
BENCHMARK_MAIN();
