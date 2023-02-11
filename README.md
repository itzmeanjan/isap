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

Each of these four AEAD schemes offer following functionalities

Routine | What does it do ?
--- | --:
`encrypt` | Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, authenticated encryption algorithm computes M -bytes cipher text along with 16 -bytes authentication tag s.t. N, M >= 0
`decrypt` | Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, verified decryption algorithm computes M -bytes plain text along with boolean verification flag denoting success status of authenticity, integrity check s.t. N, M >= 0

> **Note** Associated data is never encrypted i.e. AEAD provides secrecy only for plain text but integrity for both cipher text & associated data.

> **Warning** Avoid reusing same nonce under same secret key.

> **Note** If boolean verification flag returned from decryption routine holds false value then plain text bytes are never attempted to be decrypted. That's because of the fact --- ISAP performs authentication tag verification first and only in case that is successful it attempts decryption.

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
g++ (Homebrew GCC 12.2.0) 12.2.0

$ clang++ --version
Apple clang version 14.0.0 (clang-1400.0.29.202)
```

- System development utilities such as `make`, `cmake`, `python3`, `unzip` and `wget`

```fish
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.25.2

$ python3 --version
Python 3.10.10

$ unzip -v
UnZip 6.00 of 20 April 2009, by Info-ZIP

$ wget --version
GNU Wget 1.21.3 built on darwin22.1.0.
```

- Install Python3 dependencies using

```fish
# Must have pip installed, if pip is not available you can try following on Debian/ Ubuntu
# sudo apt-get install python3-pip

python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking ISAP on CPU targets, install `google-benchmark` globally; follow [here](https://github.com/google/benchmark/tree/0ce66c0#installation) for how to.

## Testing

For testing functional correctness of ISAP implementation, I make use of ISAP Known Answer Tests ( KATs ) submitted to NIST Light Weight Cryptography Competition's final round call. 

Given secret key, nonce, associated data & plain text, I check whether computed cipher text and authentication tag matches what's provided in specific KAT. Along with that I also attempt to decrypt cipher text back to plain text, while ensuring that it can be verifiably decrypted.

For executing the tests, issue

```fish
make
```

## Benchmarking

For benchmarking ISAP implementation on CPU targets, issue

```fish
make benchmark
```

> **Warning** Your CPU may have scaling enabled, for disabling that check [here](https://github.com/google/benchmark/blob/0ce66c0/docs/user_guide.md#disabling-cpu-frequency-scaling)

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( Compiled with Clang )

```fish
2023-02-11T08:45:45+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.11, 1.89, 1.96
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   4.19 ns         4.19 ns    165294720 bytes_per_second=8.89142G/s
isap_bench::ascon_permutation<6>                   23.7 ns         23.7 ns     29427468 bytes_per_second=1.57244G/s
isap_bench::ascon_permutation<12>                  45.9 ns         45.9 ns     15265810 bytes_per_second=831.842M/s
isap_bench::keccak_permutation<1>                  42.0 ns         42.0 ns     16647839 bytes_per_second=1.10898G/s
isap_bench::keccak_permutation<8>                   334 ns          333 ns      2073417 bytes_per_second=142.984M/s
isap_bench::keccak_permutation<12>                  501 ns          501 ns      1350517 bytes_per_second=95.1938M/s
isap_bench::keccak_permutation<16>                  670 ns          670 ns      1021182 bytes_per_second=71.2197M/s
isap_bench::keccak_permutation<20>                  835 ns          835 ns       824296 bytes_per_second=57.1209M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         2105 ns         2104 ns       329441 bytes_per_second=43.5211M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2118 ns         2117 ns       329536 bytes_per_second=43.2487M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        2708 ns         2706 ns       256933 bytes_per_second=56.3969M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        2736 ns         2726 ns       255245 bytes_per_second=55.9667M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        3910 ns         3899 ns       180598 bytes_per_second=70.4436M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        3885 ns         3883 ns       178589 bytes_per_second=70.7392M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        6246 ns         6242 ns       109592 bytes_per_second=83.1082M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        6256 ns         6250 ns       108899 bytes_per_second=83.0079M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      10944 ns        10937 ns        62696 bytes_per_second=92.079M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      10963 ns        10958 ns        62166 bytes_per_second=91.9001M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      20418 ns        20407 ns        34121 bytes_per_second=97.2024M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      20541 ns        20529 ns        34199 bytes_per_second=96.6265M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      39222 ns        39197 ns        17805 bytes_per_second=100.435M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      39546 ns        39513 ns        17851 bytes_per_second=99.6334M/s
isap_bench::isap_a_128_aead_encrypt/32/64         12825 ns        12820 ns        53666 bytes_per_second=7.14163M/s
isap_bench::isap_a_128_aead_decrypt/32/64         13638 ns        13586 ns        50369 bytes_per_second=6.7389M/s
isap_bench::isap_a_128_aead_encrypt/32/128        13628 ns        13620 ns        50953 bytes_per_second=11.203M/s
isap_bench::isap_a_128_aead_decrypt/32/128        13597 ns        13586 ns        50979 bytes_per_second=11.2308M/s
isap_bench::isap_a_128_aead_encrypt/32/256        15187 ns        15176 ns        45671 bytes_per_second=18.0984M/s
isap_bench::isap_a_128_aead_decrypt/32/256        15066 ns        15058 ns        45817 bytes_per_second=18.2396M/s
isap_bench::isap_a_128_aead_encrypt/32/512        18145 ns        18133 ns        37706 bytes_per_second=28.6115M/s
isap_bench::isap_a_128_aead_decrypt/32/512        18174 ns        18163 ns        38314 bytes_per_second=28.5631M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       24355 ns        24341 ns        28589 bytes_per_second=41.3736M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       24244 ns        24231 ns        28660 bytes_per_second=41.5616M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       36498 ns        36478 ns        19100 bytes_per_second=54.3796M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       36350 ns        36322 ns        19077 bytes_per_second=54.613M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       60919 ns        60900 ns        11196 bytes_per_second=64.6428M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       60678 ns        60620 ns        11152 bytes_per_second=64.9416M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        18668 ns        18660 ns        37236 bytes_per_second=4.90627M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        18529 ns        18519 ns        37059 bytes_per_second=4.94385M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       22815 ns        22799 ns        30714 bytes_per_second=6.69276M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       22610 ns        22599 ns        30568 bytes_per_second=6.7519M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       29827 ns        29815 ns        23375 bytes_per_second=9.21208M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       29807 ns        29789 ns        23374 bytes_per_second=9.22004M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       44277 ns        44242 ns        15841 bytes_per_second=11.7264M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       44022 ns        43988 ns        15799 bytes_per_second=11.7941M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      72972 ns        72912 ns         9437 bytes_per_second=13.8122M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      73282 ns        73230 ns         9606 bytes_per_second=13.7524M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048     131380 ns       131313 ns         5262 bytes_per_second=15.1062M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048     131033 ns       130971 ns         5208 bytes_per_second=15.1456M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     246820 ns       246732 ns         2791 bytes_per_second=15.9557M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     248281 ns       247999 ns         2814 bytes_per_second=15.8742M/s
isap_bench::isap_k_128_aead_encrypt/32/64        143033 ns       142518 ns         5047 bytes_per_second=657.81k/s
isap_bench::isap_k_128_aead_decrypt/32/64        136099 ns       136043 ns         5044 bytes_per_second=689.119k/s
isap_bench::isap_k_128_aead_encrypt/32/128       143498 ns       143409 ns         4854 bytes_per_second=1089.54k/s
isap_bench::isap_k_128_aead_decrypt/32/128       141048 ns       140983 ns         4872 bytes_per_second=1108.29k/s
isap_bench::isap_k_128_aead_encrypt/32/256       153301 ns       153169 ns         4546 bytes_per_second=1.79317M/s
isap_bench::isap_k_128_aead_decrypt/32/256       151099 ns       150963 ns         4594 bytes_per_second=1.81938M/s
isap_bench::isap_k_128_aead_encrypt/32/512       171353 ns       171252 ns         4029 bytes_per_second=3.02945M/s
isap_bench::isap_k_128_aead_decrypt/32/512       169892 ns       169752 ns         4085 bytes_per_second=3.05622M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      230412 ns       212757 ns         3325 bytes_per_second=4.73348M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      209167 ns       209044 ns         3350 bytes_per_second=4.81754M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      286222 ns       286096 ns         2419 bytes_per_second=6.93349M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      285025 ns       284868 ns         2433 bytes_per_second=6.96337M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      440289 ns       440103 ns         1585 bytes_per_second=8.94511M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      440478 ns       440231 ns         1590 bytes_per_second=8.9425M/s
```

## Usage

Starting to use ISAP C++ API is as easy as including proper header files in your program and letting your compiler know where it can find these header files, which is `./include` directory in this repository.

Here I've implemented full ISAP specification ( as submitted to NIST LWC final round call, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists) ) as zero-dependency, header-only C++ library. Following AEAD schemes can be used by importing respective header files, while you can also find usage examples in below table

AEAD Scheme | Respective Header | Example
--- | --- | ---
ISAP-A-128A | [./include/isap_a_128a.hpp](./include/isap_a_128a.hpp) | [isap_a_128a.cpp](./example/isap_a_128a.cpp)
ISAP-A-128 | [./include/isap_a_128.hpp](./include/isap_a_128.hpp) | [isap_a_128.cpp](./example/isap_a_128.cpp)
ISAP-K-128A | [./include/isap_k_128a.hpp](./include/isap_k_128a.hpp) | [isap_k_128a.cpp](./example/isap_k_128a.cpp)
ISAP-K-128 | [./include/isap_k_128.hpp](./include/isap_k_128.hpp) | [isap_k_128.cpp](./example/isap_k_128.cpp)

> **Note** You can just import `include/isap.hpp` which includes all `isap_{a,k}_128{a}.hpp` headers.

The interface that these AEAD schemes expose to users look like below

Routine | Input | Output
--- | --: | --:
`encrypt` | 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data s.t. N >= 0, M -bytes plain text s.t. M >= 0 | 16 -bytes authentication tag, M -bytes cipher text s.t. M >= 0
`decrypt` | 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data s.t. N >= 0, M -bytes cipher text s.t. M >= 0 | Boolean verification flag, M -bytes plain text s.t. M >= 0

> **Warning** Avoid reusing same nonce under same secret key. 

These AEAD schemes are different based on what underlying permutation ( say whether `ascon` or `keccak-p[400]` ) they use and how many rounds of those are applied.

```bash
$ g++ -Wall -std=c++20 -O3 -march=native -I ./include example/isap_a_128.cpp && ./a.out
ISAP-A-128 AEAD

Key          : c4cf08bfaa5b003f3e179a92a2d69f08
Nonce        : 03a6b07c1a41f92785acdfa53a3c0163
Data         : 5311325ebe357cc243cd4f847dda150ecfd434fba1271af5f291384e5098301f
Text         : da17ed022c4c260e76302501dd196674471058cd876720eb3215f86a1a9fe780
Ciphered     : b023a5eb8ac307e741bbf83c5dcfa0bf17d4c25db6895c333504171fa19bdf54
Tag          : f550b682cdfe42e7fb22868003dbc872
Deciphered   : da17ed022c4c260e76302501dd196674471058cd876720eb3215f86a1a9fe780

# ---

g++ -Wall -std=c++20 -O3 -march=native -I ./include example/isap_a_128a.cpp && ./a.out
ISAP-A-128A AEAD

Key          : 089dc67e6fb61f7ebb71e60e306837e9
Nonce        : 81b49eda969fd568462dea1712f73a65
Data         : 04f71996f3278d9de25634ab7a2d4691be4fc1014f91388032a029e2606b5356
Text         : 95304afd8fa04343c40e683cfb37e122866fd981dd877d4432b4e5e9939d14e5
Ciphered     : 33efaed5efbe5a3d10127f7eae4fb7b16498067bad17d92efee8c64c499c442f
Tag          : 5f50bc7f930e046288ff79edab3d4fe0
Deciphered   : 95304afd8fa04343c40e683cfb37e122866fd981dd877d4432b4e5e9939d14e5

# ---

g++ -Wall -std=c++20 -O3 -march=native -I ./include example/isap_k_128.cpp && ./a.out
ISAP-K-128 AEAD

Key          : f5d2c6030737e196bf4e8399cbcfa42d
Nonce        : 7461ab3b02f65eacae877167c9cc9b9e
Data         : 6c7a9dea487073bf293da800ea0b6730c19b09db940caf505304c5799eff98cc
Text         : 3ca67224924eee58f91e099b7e5b314574c241ccac93279c6e3d174e0cc2108b
Ciphered     : dfa8901c806d017d0d0b36cbe046ea754921a4cef8689cbcbcca10bc63e84104
Tag          : 44f51e49aca0146d96364c1a2130cd50
Deciphered   : 3ca67224924eee58f91e099b7e5b314574c241ccac93279c6e3d174e0cc2108b

# ---

g++ -Wall -std=c++20 -O3 -march=native -I ./include example/isap_k_128a.cpp && ./a.out
ISAP-K-128A AEAD

Key          : 27d1cf5b827b5f79498e7a872432aca7
Nonce        : 1b3d2785f58dcd59839c5bb47afd7f96
Data         : a696671d061dbcec1e7eefe1a061da7f0677ad8251ccaf4a4be975264a66cb91
Text         : 52b3ef2f8fb8696e1059f0fe10d084485fd3517d0c9970590ec5c2e5f1748389
Ciphered     : f622401d78f6f473e63402a77a97d3e0eccf2017cd7e5e00f338b9760237411f
Tag          : 1d10da32bb26efc388d3233e07e18a71
Deciphered   : 52b3ef2f8fb8696e1059f0fe10d084485fd3517d0c9970590ec5c2e5f1748389
```
