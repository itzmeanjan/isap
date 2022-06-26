# isap
Lightweight Authenticated Encryption with Associated Data

## Overview

ISAP is the sixth NIST Light Weight Cryptography (LWC) competition's final round candidate, which I've decided to work on. Here I'm maintaining a zero-dependency, easy-to-use, header-only C++ library, implementing all variants of ISAP Authenticated Encryption with Associated Data ( AEAD ) scheme.

Variant | Based on
--- | ---
ISAP-A-128A ( **default** ) | Ascon permutation, with smaller # -of rounds
ISAP-A-128 | Ascon permutation, with higher # -of rounds
ISAP-K-128A | Keccak-p[400] permutation, with smaller # -of rounds
ISAP-K-128 | Keccak-p[400] permutation, with higher # -of rounds

All of these AEAD schemes do following

- `encrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, authenticated encryption algorithm computes M -bytes cipher text along with 16 -bytes authentication tag | N, M >= 0

> Note, associated data is never encrypted i.e. AEAD provides secrecy only for plain text but integrity for both cipher text & associated data.

> Avoid reusing same nonce under same secret key.

- `decrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, verified decryption algorithm computes M -bytes plain text along with boolean verification flag denoting authenticity, integrity check result | N, M >= 0

> Note, if boolean verification flag returned by decrypt routine isn't holding truth value, make sure you don't consume decrypted bytes.

During this work, I followed ISAP specification, which was submitted to NIST's final round call in Light Weight Cryptography standardization effort. I suggest to go through ISAP [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf) to better understand ISAP AEAD schemes.

Other Lightweight AEAD scheme which I've already worked on

- Ascon, see [here](https://github.com/itzmeanjan/ascon)
- TinyJambu, see [here](https://github.com/itzmeanjan/tinyjambu)
- Xoodyak, see [here](https://github.com/itzmeanjan/xoodyak)
- Sparkle, see [here](https://github.com/itzmeanjan/sparkle)
- Photon-Beetle, see [here](https://github.com/itzmeanjan/photon-beetle)

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```fish
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- System development utilities such as `make`, `cmake`

```fish
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of ISAP implementation `wget`, `unzip` & `python3`

```fish
$ python3 --version
Python 3.9.13
```

- Install Python3 dependencies using

```fish
python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking ISAP on CPU based systems, install `google-benchmark` globally, see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for help

## Testing

For testing functional correctness of ISAP implementation, I make use of ISAP Known Answer Tests ( KATs ) submitted to NIST Light Weight Cryptography Competition's final round call. 

Given secret key, nonce, associated data & plain text, I check whether computed cipher text and authentication tag matches what's provided in specific KAT. Along with that I also attempt to decrypt cipher text back to plain text, while ensuring that it can be verifiably decrypted.

For executing the tests, issue

```fish
make
```

## Benchmarking

For benchmarking ISAP implementation on CPU based systems, issue

```fish
make benchmark
```

> Your CPU may have scaling enabled, for disabling that check [here](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

### On AWS Graviton3

```fish
2022-06-26T08:14:42+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.08, 0.02, 0.01
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   6.83 ns         6.83 ns    102305815 bytes_per_second=5.45049G/s
isap_bench::ascon_permutation<6>                   28.4 ns         28.4 ns     24630614 bytes_per_second=1.31058G/s
isap_bench::ascon_permutation<12>                  55.0 ns         55.0 ns     12730434 bytes_per_second=693.766M/s
isap_bench::keccak_permutation<1>                  30.1 ns         30.1 ns     23288167 bytes_per_second=1.54483G/s
isap_bench::keccak_permutation<8>                   188 ns          188 ns      3717539 bytes_per_second=253.417M/s
isap_bench::keccak_permutation<12>                  275 ns          275 ns      2542617 bytes_per_second=173.154M/s
isap_bench::keccak_permutation<16>                  364 ns          364 ns      1924748 bytes_per_second=131.132M/s
isap_bench::keccak_permutation<20>                  461 ns          461 ns      1518210 bytes_per_second=103.376M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         2515 ns         2515 ns       278309 bytes_per_second=36.4028M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2529 ns         2529 ns       276742 bytes_per_second=36.2072M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        3176 ns         3176 ns       220366 bytes_per_second=48.043M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        3188 ns         3188 ns       219640 bytes_per_second=47.8598M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4493 ns         4492 ns       155880 bytes_per_second=61.1381M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4506 ns         4505 ns       155333 bytes_per_second=60.9619M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        7127 ns         7127 ns        98217 bytes_per_second=72.7966M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        7140 ns         7139 ns        98001 bytes_per_second=72.6669M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      12393 ns        12392 ns        56488 bytes_per_second=81.2666M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      12409 ns        12409 ns        56399 bytes_per_second=81.1591M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      22928 ns        22927 ns        30538 bytes_per_second=86.5197M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      22948 ns        22948 ns        30503 bytes_per_second=86.4424M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      43959 ns        43958 ns        15937 bytes_per_second=89.5576M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      44018 ns        44016 ns        15899 bytes_per_second=89.4393M/s
isap_bench::isap_a_128_aead_encrypt/32/64         15109 ns        15109 ns        46345 bytes_per_second=6.05958M/s
isap_bench::isap_a_128_aead_decrypt/32/64         15109 ns        15109 ns        46316 bytes_per_second=6.05942M/s
isap_bench::isap_a_128_aead_encrypt/32/128        16025 ns        16024 ns        43795 bytes_per_second=9.52224M/s
isap_bench::isap_a_128_aead_decrypt/32/128        16001 ns        16001 ns        43735 bytes_per_second=9.53631M/s
isap_bench::isap_a_128_aead_encrypt/32/256        17693 ns        17693 ns        39520 bytes_per_second=15.5239M/s
isap_bench::isap_a_128_aead_decrypt/32/256        17682 ns        17681 ns        39574 bytes_per_second=15.5339M/s
isap_bench::isap_a_128_aead_encrypt/32/512        21037 ns        21037 ns        33284 bytes_per_second=24.6612M/s
isap_bench::isap_a_128_aead_decrypt/32/512        21023 ns        21023 ns        33296 bytes_per_second=24.678M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       27677 ns        27677 ns        25294 bytes_per_second=36.3874M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       27674 ns        27674 ns        25306 bytes_per_second=36.3914M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       40990 ns        40989 ns        17076 bytes_per_second=48.3941M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       41000 ns        40999 ns        17077 bytes_per_second=48.3827M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       67933 ns        67931 ns        10359 bytes_per_second=57.9527M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       68202 ns        68201 ns        10246 bytes_per_second=57.7233M/s
isap_bench::isap_k_128a_aead_encrypt/32/64         9649 ns         9649 ns        72547 bytes_per_second=9.48812M/s
isap_bench::isap_k_128a_aead_decrypt/32/64         9663 ns         9662 ns        72443 bytes_per_second=9.47521M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       11623 ns        11623 ns        60214 bytes_per_second=13.1281M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       11637 ns        11637 ns        60148 bytes_per_second=13.1122M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       15155 ns        15154 ns        46361 bytes_per_second=18.1239M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       15110 ns        15110 ns        46326 bytes_per_second=18.1772M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       22043 ns        22043 ns        31751 bytes_per_second=23.5359M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       22058 ns        22057 ns        31734 bytes_per_second=23.5204M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      35924 ns        35924 ns        19486 bytes_per_second=28.034M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      35938 ns        35937 ns        19478 bytes_per_second=28.0233M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048      64126 ns        64124 ns        10916 bytes_per_second=30.9344M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048      64147 ns        64146 ns        10914 bytes_per_second=30.924M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     120518 ns       120515 ns         5808 bytes_per_second=32.6661M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     120548 ns       120543 ns         5806 bytes_per_second=32.6586M/s
isap_bench::isap_k_128_aead_encrypt/32/64         70928 ns        70926 ns         9869 bytes_per_second=1.29081M/s
isap_bench::isap_k_128_aead_decrypt/32/64         70934 ns        70931 ns         9860 bytes_per_second=1.29073M/s
isap_bench::isap_k_128_aead_encrypt/32/128        73593 ns        73591 ns         9519 bytes_per_second=2.07347M/s
isap_bench::isap_k_128_aead_decrypt/32/128        73611 ns        73609 ns         9510 bytes_per_second=2.07295M/s
isap_bench::isap_k_128_aead_encrypt/32/256        78154 ns        78152 ns         8957 bytes_per_second=3.51439M/s
isap_bench::isap_k_128_aead_decrypt/32/256        78177 ns        78176 ns         8955 bytes_per_second=3.51334M/s
isap_bench::isap_k_128_aead_encrypt/32/512        87432 ns        87429 ns         8004 bytes_per_second=5.93392M/s
isap_bench::isap_k_128_aead_decrypt/32/512        87401 ns        87400 ns         8008 bytes_per_second=5.93594M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      105830 ns       105826 ns         6614 bytes_per_second=9.51635M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      105829 ns       105826 ns         6611 bytes_per_second=9.51637M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      143163 ns       143160 ns         4889 bytes_per_second=13.8561M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      143200 ns       143197 ns         4888 bytes_per_second=13.8525M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      217956 ns       217951 ns         3212 bytes_per_second=18.0626M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      217995 ns       217988 ns         3211 bytes_per_second=18.0595M/s
```

### On AWS Graviton2

```fish
2022-06-26T08:12:44+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.00, 0.08, 0.16
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   11.8 ns         11.8 ns     59568072 bytes_per_second=3.1703G/s
isap_bench::ascon_permutation<6>                   44.6 ns         44.6 ns     15696261 bytes_per_second=855.168M/s
isap_bench::ascon_permutation<12>                  94.0 ns         94.0 ns      7448191 bytes_per_second=405.833M/s
isap_bench::keccak_permutation<1>                  55.7 ns         55.7 ns     12568042 bytes_per_second=856.012M/s
isap_bench::keccak_permutation<8>                   389 ns          389 ns      1799601 bytes_per_second=122.564M/s
isap_bench::keccak_permutation<12>                  576 ns          576 ns      1216016 bytes_per_second=82.8382M/s
isap_bench::keccak_permutation<16>                  762 ns          762 ns       917148 bytes_per_second=62.5909M/s
isap_bench::keccak_permutation<20>                  966 ns          966 ns       724681 bytes_per_second=49.3553M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         4470 ns         4470 ns       156567 bytes_per_second=20.4837M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         4487 ns         4487 ns       155947 bytes_per_second=20.4051M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        5582 ns         5582 ns       125442 bytes_per_second=27.3352M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        5598 ns         5598 ns       125068 bytes_per_second=27.2584M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        7812 ns         7812 ns        89627 bytes_per_second=35.1592M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        7826 ns         7826 ns        89462 bytes_per_second=35.0945M/s
isap_bench::isap_a_128a_aead_encrypt/32/512       12253 ns        12253 ns        57132 bytes_per_second=42.3422M/s
isap_bench::isap_a_128a_aead_decrypt/32/512       12265 ns        12265 ns        56997 bytes_per_second=42.3006M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      21138 ns        21138 ns        33122 bytes_per_second=47.6442M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      21154 ns        21153 ns        33097 bytes_per_second=47.6083M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      38906 ns        38905 ns        17984 bytes_per_second=50.9865M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      38916 ns        38915 ns        17980 bytes_per_second=50.9733M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      74471 ns        74470 ns         9402 bytes_per_second=52.8635M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      74533 ns        74531 ns         9397 bytes_per_second=52.8204M/s
isap_bench::isap_a_128_aead_encrypt/32/64         25998 ns        25998 ns        26930 bytes_per_second=3.52151M/s
isap_bench::isap_a_128_aead_decrypt/32/64         26010 ns        26010 ns        26923 bytes_per_second=3.51995M/s
isap_bench::isap_a_128_aead_encrypt/32/128        27503 ns        27503 ns        25456 bytes_per_second=5.5481M/s
isap_bench::isap_a_128_aead_decrypt/32/128        27511 ns        27511 ns        25451 bytes_per_second=5.54647M/s
isap_bench::isap_a_128_aead_encrypt/32/256        30512 ns        30512 ns        22947 bytes_per_second=9.00178M/s
isap_bench::isap_a_128_aead_decrypt/32/256        30518 ns        30518 ns        22941 bytes_per_second=8.9999M/s
isap_bench::isap_a_128_aead_encrypt/32/512        36528 ns        36527 ns        19168 bytes_per_second=14.2032M/s
isap_bench::isap_a_128_aead_decrypt/32/512        36540 ns        36539 ns        19164 bytes_per_second=14.1984M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       48553 ns        48552 ns        14412 bytes_per_second=20.7424M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       48569 ns        48569 ns        14411 bytes_per_second=20.7351M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       72615 ns        72614 ns         9640 bytes_per_second=27.3177M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       72622 ns        72620 ns         9619 bytes_per_second=27.3155M/s
isap_bench::isap_a_128_aead_encrypt/32/4096      120816 ns       120814 ns         5796 bytes_per_second=32.5852M/s
isap_bench::isap_a_128_aead_decrypt/32/4096      120789 ns       120786 ns         5797 bytes_per_second=32.5929M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        20498 ns        20498 ns        34154 bytes_per_second=4.46643M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        20518 ns        20517 ns        34125 bytes_per_second=4.46225M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       24656 ns        24656 ns        28396 bytes_per_second=6.18861M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       24671 ns        24670 ns        28370 bytes_per_second=6.18512M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       31944 ns        31944 ns        21917 bytes_per_second=8.59809M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       31966 ns        31965 ns        21909 bytes_per_second=8.5924M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       46524 ns        46523 ns        15049 bytes_per_second=11.1514M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       46534 ns        46533 ns        15038 bytes_per_second=11.149M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      75685 ns        75683 ns         9251 bytes_per_second=13.3065M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      75705 ns        75703 ns         9248 bytes_per_second=13.303M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048     135007 ns       135006 ns         5186 bytes_per_second=14.693M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048     135038 ns       135035 ns         5185 bytes_per_second=14.6898M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     253685 ns       253683 ns         2760 bytes_per_second=15.5184M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     253689 ns       253684 ns         2759 bytes_per_second=15.5184M/s
isap_bench::isap_k_128_aead_encrypt/32/64        148372 ns       148370 ns         4713 bytes_per_second=631.866k/s
isap_bench::isap_k_128_aead_decrypt/32/64        148396 ns       148395 ns         4712 bytes_per_second=631.761k/s
isap_bench::isap_k_128_aead_encrypt/32/128       153871 ns       153870 ns         4549 bytes_per_second=1015.47k/s
isap_bench::isap_k_128_aead_decrypt/32/128       153888 ns       153887 ns         4549 bytes_per_second=1015.36k/s
isap_bench::isap_k_128_aead_encrypt/32/256       163488 ns       163478 ns         4283 bytes_per_second=1.68009M/s
isap_bench::isap_k_128_aead_decrypt/32/256       163493 ns       163492 ns         4283 bytes_per_second=1.67995M/s
isap_bench::isap_k_128_aead_encrypt/32/512       182682 ns       182675 ns         3833 bytes_per_second=2.84001M/s
isap_bench::isap_k_128_aead_decrypt/32/512       182696 ns       182695 ns         3832 bytes_per_second=2.8397M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      221041 ns       221037 ns         3167 bytes_per_second=4.55616M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      221056 ns       221054 ns         3167 bytes_per_second=4.55581M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      299183 ns       299177 ns         2339 bytes_per_second=6.63032M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      299269 ns       299267 ns         2340 bytes_per_second=6.62833M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      455622 ns       455602 ns         1537 bytes_per_second=8.64081M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      455639 ns       455636 ns         1537 bytes_per_second=8.64016M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-06-26T12:10:42+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.22, 2.30, 2.09
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   4.66 ns         4.66 ns    150606298 bytes_per_second=7.99572G/s
isap_bench::ascon_permutation<6>                   25.0 ns         25.0 ns     28107370 bytes_per_second=1.48914G/s
isap_bench::ascon_permutation<12>                  45.3 ns         45.3 ns     15591207 bytes_per_second=842.945M/s
isap_bench::keccak_permutation<1>                  38.5 ns         38.5 ns     18104744 bytes_per_second=1.20933G/s
isap_bench::keccak_permutation<8>                   307 ns          306 ns      2266729 bytes_per_second=155.626M/s
isap_bench::keccak_permutation<12>                  461 ns          461 ns      1522941 bytes_per_second=103.412M/s
isap_bench::keccak_permutation<16>                  650 ns          646 ns      1089596 bytes_per_second=73.8475M/s
isap_bench::keccak_permutation<20>                  836 ns          825 ns       866465 bytes_per_second=57.7894M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         2546 ns         2520 ns       280221 bytes_per_second=36.3316M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2496 ns         2469 ns       291929 bytes_per_second=37.0794M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        3023 ns         3003 ns       225080 bytes_per_second=50.8185M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        3207 ns         3178 ns       227338 bytes_per_second=48.0148M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4437 ns         4403 ns       158906 bytes_per_second=62.3736M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4344 ns         4316 ns       158964 bytes_per_second=63.6439M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        6988 ns         6911 ns        97153 bytes_per_second=75.0653M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        7680 ns         7578 ns       101823 bytes_per_second=68.4572M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      11459 ns        11397 ns        53232 bytes_per_second=88.3625M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      11087 ns        11070 ns        61685 bytes_per_second=90.9778M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      20549 ns        20522 ns        34125 bytes_per_second=96.6607M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      20448 ns        20426 ns        34060 bytes_per_second=97.1119M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      39218 ns        39184 ns        17918 bytes_per_second=100.469M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      41514 ns        41070 ns        17937 bytes_per_second=95.8558M/s
isap_bench::isap_a_128_aead_encrypt/32/64         13308 ns        13209 ns        53181 bytes_per_second=6.93093M/s
isap_bench::isap_a_128_aead_decrypt/32/64         13142 ns        13098 ns        48801 bytes_per_second=6.99004M/s
isap_bench::isap_a_128_aead_encrypt/32/128        13553 ns        13548 ns        50854 bytes_per_second=11.2628M/s
isap_bench::isap_a_128_aead_decrypt/32/128        15178 ns        14836 ns        50304 bytes_per_second=10.2848M/s
isap_bench::isap_a_128_aead_encrypt/32/256        16453 ns        16377 ns        42951 bytes_per_second=16.7714M/s
isap_bench::isap_a_128_aead_decrypt/32/256        16222 ns        16195 ns        43256 bytes_per_second=16.9594M/s
isap_bench::isap_a_128_aead_encrypt/32/512        18535 ns        18519 ns        37043 bytes_per_second=28.0152M/s
isap_bench::isap_a_128_aead_decrypt/32/512        18992 ns        18886 ns        37141 bytes_per_second=27.4694M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       24690 ns        24591 ns        27837 bytes_per_second=40.9538M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       24552 ns        24456 ns        26591 bytes_per_second=41.1794M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       36340 ns        36299 ns        19007 bytes_per_second=54.6472M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       37025 ns        36835 ns        19031 bytes_per_second=53.8517M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       61743 ns        61488 ns        10881 bytes_per_second=64.025M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       61934 ns        61859 ns        11142 bytes_per_second=63.6414M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        17656 ns        17553 ns        39928 bytes_per_second=5.21566M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        17320 ns        17299 ns        39432 bytes_per_second=5.29233M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       21038 ns        21010 ns        32599 bytes_per_second=7.26265M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       21226 ns        21204 ns        32503 bytes_per_second=7.19627M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       27833 ns        27772 ns        25088 bytes_per_second=9.88961M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       27381 ns        27333 ns        25311 bytes_per_second=10.0486M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       40480 ns        40434 ns        17273 bytes_per_second=12.8307M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       40945 ns        40788 ns        17328 bytes_per_second=12.7194M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      67781 ns        67525 ns         9852 bytes_per_second=14.9141M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      69663 ns        69524 ns        10026 bytes_per_second=14.4855M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048     121428 ns       121208 ns         5723 bytes_per_second=16.3656M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048     120820 ns       120695 ns         5692 bytes_per_second=16.4352M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     232192 ns       231664 ns         3042 bytes_per_second=16.9934M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     226828 ns       226572 ns         3080 bytes_per_second=17.3754M/s
isap_bench::isap_k_128_aead_encrypt/32/64        126093 ns       126000 ns         5434 bytes_per_second=744.049k/s
isap_bench::isap_k_128_aead_decrypt/32/64        127197 ns       127117 ns         5392 bytes_per_second=737.507k/s
isap_bench::isap_k_128_aead_encrypt/32/128       159141 ns       134861 ns         4856 bytes_per_second=1.13144M/s
isap_bench::isap_k_128_aead_decrypt/32/128       132097 ns       132006 ns         5248 bytes_per_second=1.15592M/s
isap_bench::isap_k_128_aead_encrypt/32/256       140463 ns       140303 ns         4843 bytes_per_second=1.95761M/s
isap_bench::isap_k_128_aead_decrypt/32/256       140596 ns       140527 ns         4879 bytes_per_second=1.95448M/s
isap_bench::isap_k_128_aead_encrypt/32/512       156515 ns       156438 ns         4400 bytes_per_second=3.31632M/s
isap_bench::isap_k_128_aead_decrypt/32/512       157533 ns       157390 ns         4423 bytes_per_second=3.29626M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      191687 ns       191563 ns         3620 bytes_per_second=5.25717M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      190969 ns       190890 ns         3615 bytes_per_second=5.27572M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      261217 ns       261097 ns         2655 bytes_per_second=7.59735M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      262864 ns       262307 ns         2644 bytes_per_second=7.56228M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      401578 ns       401373 ns         1734 bytes_per_second=9.80826M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      403449 ns       403179 ns         1734 bytes_per_second=9.76431M/s
```

## Usage

Starting to use ISAP C++ API is as easy as including proper header files in your program and letting your compiler know where it can find these header files, which is `./include` directory.

Here I've implemented full ISAP specification ( as submitted to NIST LWC final round call, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists) ) as zero-dependency, header-only C++ library. Following AEAD schemes can be used by importing respective header files, while you can also find usage examples in linked files

AEAD Scheme | Header | Example
--- | --- | ---
ISAP-A-128A | `./include/isap_a_128a.hpp` | [isap_a_128a.cpp](https://github.com/itzmeanjan/isap/blob/afe3ae6/example/isap_a_128a.cpp)
ISAP-A-128 | `./include/isap_a_128.hpp` | [isap_a_128.cpp](https://github.com/itzmeanjan/isap/blob/afe3ae6/example/isap_a_128.cpp)
ISAP-K-128A | `./include/isap_k_128a.hpp` | [isap_k_128a.cpp](https://github.com/itzmeanjan/isap/blob/afe3ae6/example/isap_k_128a.cpp)
ISAP-K-128 | `./include/isap_k_128.hpp` | [isap_k_128.cpp](https://github.com/itzmeanjan/isap/blob/afe3ae6/example/isap_k_128.cpp)

Note, all these AEAD schemes expose same interface to users i.e.

---

`encrypt(...)`

**Input :**

- 16 -bytes secret key
- 16 -bytes public message nonce
- N -bytes associated data | N >= 0
- M -bytes plain text | M >= 0

**Output :**

- 16 -bytes authentication tag
- M -bytes cipher text | M >= 0

> Avoid reusing same nonce under same secret key. 

---

`decrypt(...)`

**Input :**

- 16 -bytes secret key
- 16 -bytes public message nonce
- 16 -bytes authentication tag
- N -bytes associated data | N >= 0
- M -bytes cipher text | M >= 0

**Output :**

- Boolean verification flag
- M -bytes plain text | M >= 0

> Ensure presence of truth value in verification flag, before consuming decrypted bytes.

These AEAD schemes are different based on what underlying permutation ( say whether `ascon` or `keccak-p[400]` ) they use and how many rounds of those are applied.
