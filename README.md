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
2022-06-20T17:32:05+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.10, 0.03, 0.01
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::isap_a_128a_aead_encrypt/32/64         2498 ns         2498 ns       280075 bytes_per_second=36.644M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2512 ns         2512 ns       278677 bytes_per_second=36.4508M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        3138 ns         3138 ns       223048 bytes_per_second=48.6265M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        3151 ns         3151 ns       222185 bytes_per_second=48.4209M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4413 ns         4413 ns       158607 bytes_per_second=62.2367M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4429 ns         4429 ns       158001 bytes_per_second=62.0193M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        6987 ns         6987 ns        99901 bytes_per_second=74.2497M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        7005 ns         7004 ns        99998 bytes_per_second=74.0678M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      12128 ns        12127 ns        57748 bytes_per_second=83.0416M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      12146 ns        12146 ns        57633 bytes_per_second=82.914M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      22469 ns        22468 ns        31155 bytes_per_second=88.286M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      22448 ns        22447 ns        31183 bytes_per_second=88.3707M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      42972 ns        42971 ns        16284 bytes_per_second=91.6151M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      43020 ns        43018 ns        16283 bytes_per_second=91.5134M/s
isap_bench::isap_a_128_aead_encrypt/32/64         14868 ns        14868 ns        47067 bytes_per_second=6.15769M/s
isap_bench::isap_a_128_aead_decrypt/32/64         14867 ns        14867 ns        47079 bytes_per_second=6.15818M/s
isap_bench::isap_a_128_aead_encrypt/32/128        15702 ns        15702 ns        44572 bytes_per_second=9.71776M/s
isap_bench::isap_a_128_aead_decrypt/32/128        15710 ns        15709 ns        44563 bytes_per_second=9.71322M/s
isap_bench::isap_a_128_aead_encrypt/32/256        17371 ns        17371 ns        40290 bytes_per_second=15.8117M/s
isap_bench::isap_a_128_aead_decrypt/32/256        17397 ns        17397 ns        40262 bytes_per_second=15.7878M/s
isap_bench::isap_a_128_aead_encrypt/32/512        20780 ns        20780 ns        33685 bytes_per_second=24.9665M/s
isap_bench::isap_a_128_aead_decrypt/32/512        20786 ns        20786 ns        33675 bytes_per_second=24.959M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       27557 ns        27556 ns        25400 bytes_per_second=36.5465M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       27560 ns        27559 ns        25403 bytes_per_second=36.5424M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       41475 ns        41474 ns        16875 bytes_per_second=47.8282M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       41127 ns        41127 ns        17010 bytes_per_second=48.2326M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       68807 ns        68806 ns        10174 bytes_per_second=57.2153M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       68595 ns        68595 ns        10205 bytes_per_second=57.3918M/s
```

### On AWS Graviton2

```fish
2022-06-20T17:33:59+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.36, 0.10, 0.04
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::isap_a_128a_aead_encrypt/32/64         4485 ns         4485 ns       156132 bytes_per_second=20.4115M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         4497 ns         4497 ns       155729 bytes_per_second=20.3607M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        5596 ns         5596 ns       125147 bytes_per_second=27.269M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        5606 ns         5606 ns       124876 bytes_per_second=27.2204M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        7821 ns         7821 ns        89416 bytes_per_second=35.1184M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        7838 ns         7837 ns        89267 bytes_per_second=35.0454M/s
isap_bench::isap_a_128a_aead_encrypt/32/512       12263 ns        12263 ns        57054 bytes_per_second=42.3077M/s
isap_bench::isap_a_128a_aead_decrypt/32/512       12275 ns        12275 ns        57025 bytes_per_second=42.2651M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      21146 ns        21145 ns        33096 bytes_per_second=47.6262M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      21164 ns        21164 ns        33085 bytes_per_second=47.5855M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      38920 ns        38919 ns        17986 bytes_per_second=50.9684M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      38925 ns        38924 ns        17984 bytes_per_second=50.9619M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      74457 ns        74452 ns         9402 bytes_per_second=52.8764M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      74467 ns        74466 ns         9399 bytes_per_second=52.8664M/s
isap_bench::isap_a_128_aead_encrypt/32/64         25957 ns        25957 ns        26969 bytes_per_second=3.52712M/s
isap_bench::isap_a_128_aead_decrypt/32/64         25974 ns        25974 ns        26950 bytes_per_second=3.52483M/s
isap_bench::isap_a_128_aead_encrypt/32/128        27448 ns        27448 ns        25494 bytes_per_second=5.55914M/s
isap_bench::isap_a_128_aead_decrypt/32/128        27461 ns        27461 ns        25490 bytes_per_second=5.55659M/s
isap_bench::isap_a_128_aead_encrypt/32/256        30455 ns        30455 ns        22986 bytes_per_second=9.01862M/s
isap_bench::isap_a_128_aead_decrypt/32/256        30476 ns        30476 ns        22974 bytes_per_second=9.01231M/s
isap_bench::isap_a_128_aead_encrypt/32/512        36478 ns        36477 ns        19190 bytes_per_second=14.2226M/s
isap_bench::isap_a_128_aead_decrypt/32/512        36483 ns        36483 ns        19186 bytes_per_second=14.2203M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       48498 ns        48498 ns        14434 bytes_per_second=20.7655M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       48515 ns        48515 ns        14429 bytes_per_second=20.7583M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       72564 ns        72562 ns         9646 bytes_per_second=27.3374M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       72574 ns        72573 ns         9645 bytes_per_second=27.333M/s
isap_bench::isap_a_128_aead_encrypt/32/4096      120686 ns       120682 ns         5800 bytes_per_second=32.621M/s
isap_bench::isap_a_128_aead_decrypt/32/4096      120695 ns       120694 ns         5800 bytes_per_second=32.6178M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-06-21T07:56:43+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.78, 1.93, 1.99
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::isap_a_128a_aead_encrypt/32/64         2517 ns         2485 ns       278107 bytes_per_second=36.8464M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2553 ns         2515 ns       277670 bytes_per_second=36.4089M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        3186 ns         3154 ns       210416 bytes_per_second=48.3736M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        3094 ns         3072 ns       227454 bytes_per_second=49.6644M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4425 ns         4394 ns       164809 bytes_per_second=62.501M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4286 ns         4259 ns       164161 bytes_per_second=64.4903M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        6695 ns         6657 ns       104984 bytes_per_second=77.9294M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        6786 ns         6737 ns       101483 bytes_per_second=77.0046M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      11318 ns        11300 ns        62915 bytes_per_second=89.1219M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      11951 ns        11849 ns        58641 bytes_per_second=84.9915M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      22181 ns        21984 ns        31531 bytes_per_second=90.2292M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      22978 ns        22582 ns        32944 bytes_per_second=87.8429M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      40813 ns        40669 ns        17240 bytes_per_second=96.8003M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      41865 ns        41548 ns        17261 bytes_per_second=94.7533M/s
isap_bench::isap_a_128_aead_encrypt/32/64         14375 ns        13820 ns        50083 bytes_per_second=6.62442M/s
isap_bench::isap_a_128_aead_decrypt/32/64         13372 ns        13342 ns        50934 bytes_per_second=6.86195M/s
isap_bench::isap_a_128_aead_encrypt/32/128        14727 ns        14622 ns        49257 bytes_per_second=10.4353M/s
isap_bench::isap_a_128_aead_decrypt/32/128        14974 ns        14852 ns        48791 bytes_per_second=10.2742M/s
isap_bench::isap_a_128_aead_encrypt/32/256        16046 ns        15938 ns        43132 bytes_per_second=17.2327M/s
isap_bench::isap_a_128_aead_decrypt/32/256        15629 ns        15541 ns        44924 bytes_per_second=17.6736M/s
isap_bench::isap_a_128_aead_encrypt/32/512        19686 ns        19394 ns        36001 bytes_per_second=26.7498M/s
isap_bench::isap_a_128_aead_decrypt/32/512        19633 ns        19347 ns        35838 bytes_per_second=26.816M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       24448 ns        24431 ns        27735 bytes_per_second=41.2209M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       24467 ns        24446 ns        28455 bytes_per_second=41.1961M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       36470 ns        36439 ns        19182 bytes_per_second=54.4369M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       36774 ns        36744 ns        19131 bytes_per_second=53.9854M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       60544 ns        60514 ns        11127 bytes_per_second=65.056M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       61678 ns        61528 ns        10933 bytes_per_second=63.9838M/s
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
