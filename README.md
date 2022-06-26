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
2022-06-24T09:03:25+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.24, 0.06, 0.02
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   6.83 ns         6.83 ns    102346075 bytes_per_second=5.45043G/s
isap_bench::ascon_permutation<6>                   28.4 ns         28.4 ns     24625129 bytes_per_second=1.31138G/s
isap_bench::ascon_permutation<12>                  54.7 ns         54.7 ns     12783053 bytes_per_second=697.62M/s
isap_bench::keccak_permutation<1>                  40.4 ns         40.4 ns     17369151 bytes_per_second=1.15346G/s
isap_bench::keccak_permutation<8>                   240 ns          240 ns      2917582 bytes_per_second=198.742M/s
isap_bench::keccak_permutation<12>                  338 ns          338 ns      2070655 bytes_per_second=141.113M/s
isap_bench::keccak_permutation<16>                  449 ns          449 ns      1560318 bytes_per_second=106.279M/s
isap_bench::keccak_permutation<20>                  562 ns          562 ns      1246480 bytes_per_second=84.8449M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         2536 ns         2536 ns       276146 bytes_per_second=36.1049M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2549 ns         2549 ns       274763 bytes_per_second=35.9227M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        3191 ns         3191 ns       219363 bytes_per_second=47.8193M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        3205 ns         3205 ns       218528 bytes_per_second=47.6131M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4497 ns         4497 ns       155462 bytes_per_second=61.0804M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4505 ns         4505 ns       155173 bytes_per_second=60.9739M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        7092 ns         7092 ns        98687 bytes_per_second=73.1503M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        7112 ns         7111 ns        98532 bytes_per_second=72.9521M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      12374 ns        12374 ns        56570 bytes_per_second=81.3863M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      12386 ns        12386 ns        56515 bytes_per_second=81.3069M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      22870 ns        22870 ns        30605 bytes_per_second=86.7358M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      22866 ns        22866 ns        30594 bytes_per_second=86.7523M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      43866 ns        43864 ns        15971 bytes_per_second=89.7497M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      43878 ns        43877 ns        15954 bytes_per_second=89.723M/s
isap_bench::isap_a_128_aead_encrypt/32/64         14926 ns        14926 ns        46895 bytes_per_second=6.13389M/s
isap_bench::isap_a_128_aead_decrypt/32/64         14941 ns        14941 ns        46856 bytes_per_second=6.12769M/s
isap_bench::isap_a_128_aead_encrypt/32/128        15767 ns        15767 ns        44426 bytes_per_second=9.67775M/s
isap_bench::isap_a_128_aead_decrypt/32/128        15791 ns        15791 ns        44316 bytes_per_second=9.66307M/s
isap_bench::isap_a_128_aead_encrypt/32/256        17467 ns        17466 ns        40078 bytes_per_second=15.7256M/s
isap_bench::isap_a_128_aead_decrypt/32/256        17486 ns        17485 ns        40035 bytes_per_second=15.7079M/s
isap_bench::isap_a_128_aead_encrypt/32/512        20848 ns        20847 ns        33575 bytes_per_second=24.8855M/s
isap_bench::isap_a_128_aead_decrypt/32/512        20864 ns        20863 ns        33550 bytes_per_second=24.8667M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       27604 ns        27603 ns        25360 bytes_per_second=36.4839M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       27620 ns        27618 ns        25349 bytes_per_second=36.4642M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       41104 ns        41102 ns        17053 bytes_per_second=48.261M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       41108 ns        41107 ns        17027 bytes_per_second=48.2555M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       68096 ns        68092 ns        10279 bytes_per_second=57.8153M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       68111 ns        68110 ns        10279 bytes_per_second=57.8004M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        13309 ns        13308 ns        52602 bytes_per_second=6.87945M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        13320 ns        13319 ns        52562 bytes_per_second=6.87378M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       16131 ns        16131 ns        43388 bytes_per_second=9.45923M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       16142 ns        16141 ns        43365 bytes_per_second=9.45345M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       21092 ns        21091 ns        33190 bytes_per_second=13.0222M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       21103 ns        21102 ns        33173 bytes_per_second=13.0158M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       31017 ns        31016 ns        22569 bytes_per_second=16.7268M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       31030 ns        31029 ns        22560 bytes_per_second=16.7197M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      50851 ns        50850 ns        13766 bytes_per_second=19.8049M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      50860 ns        50859 ns        13764 bytes_per_second=19.8015M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048      91214 ns        91212 ns         7673 bytes_per_second=21.7477M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048      91210 ns        91207 ns         7674 bytes_per_second=21.7487M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     171933 ns       171928 ns         4071 bytes_per_second=22.8977M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     171933 ns       171929 ns         4071 bytes_per_second=22.8976M/s
isap_bench::isap_k_128_aead_encrypt/32/64         94713 ns        94710 ns         7391 bytes_per_second=989.867k/s
isap_bench::isap_k_128_aead_decrypt/32/64         94643 ns        94641 ns         7398 bytes_per_second=990.588k/s
isap_bench::isap_k_128_aead_encrypt/32/128        98504 ns        98502 ns         7105 bytes_per_second=1.54909M/s
isap_bench::isap_k_128_aead_decrypt/32/128        98405 ns        98402 ns         7112 bytes_per_second=1.55066M/s
isap_bench::isap_k_128_aead_encrypt/32/256       105193 ns       105189 ns         6658 bytes_per_second=2.6111M/s
isap_bench::isap_k_128_aead_decrypt/32/256       105109 ns       105105 ns         6658 bytes_per_second=2.61317M/s
isap_bench::isap_k_128_aead_encrypt/32/512       118654 ns       118652 ns         5903 bytes_per_second=4.37245M/s
isap_bench::isap_k_128_aead_decrypt/32/512       118539 ns       118537 ns         5906 bytes_per_second=4.37669M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      145345 ns       145341 ns         4814 bytes_per_second=6.92907M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      145271 ns       145268 ns         4819 bytes_per_second=6.93256M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      199711 ns       199706 ns         3504 bytes_per_second=9.93283M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      199729 ns       199725 ns         3505 bytes_per_second=9.93186M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      308668 ns       308659 ns         2267 bytes_per_second=12.7544M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      308678 ns       308672 ns         2268 bytes_per_second=12.7539M/s
```

### On AWS Graviton2

```fish
2022-06-24T09:00:25+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.49, 0.17, 0.06
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   11.7 ns         11.7 ns     59560299 bytes_per_second=3.17139G/s
isap_bench::ascon_permutation<6>                   44.6 ns         44.6 ns     15697145 bytes_per_second=855.424M/s
isap_bench::ascon_permutation<12>                  94.0 ns         94.0 ns      7448751 bytes_per_second=405.936M/s
isap_bench::keccak_permutation<1>                  62.2 ns         62.2 ns     11249382 bytes_per_second=766.389M/s
isap_bench::keccak_permutation<8>                   515 ns          515 ns      1358867 bytes_per_second=92.5696M/s
isap_bench::keccak_permutation<12>                  770 ns          770 ns       909494 bytes_per_second=61.9564M/s
isap_bench::keccak_permutation<16>                 1020 ns         1020 ns       686089 bytes_per_second=46.7369M/s
isap_bench::keccak_permutation<20>                 1237 ns         1237 ns       565919 bytes_per_second=38.5512M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         4513 ns         4513 ns       155111 bytes_per_second=20.2879M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         4525 ns         4525 ns       154668 bytes_per_second=20.2324M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        5623 ns         5623 ns       124553 bytes_per_second=27.1345M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        5634 ns         5634 ns       124235 bytes_per_second=27.0832M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        7848 ns         7848 ns        89176 bytes_per_second=34.9977M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        7868 ns         7868 ns        88983 bytes_per_second=34.9085M/s
isap_bench::isap_a_128a_aead_encrypt/32/512       12291 ns        12291 ns        56931 bytes_per_second=42.2109M/s
isap_bench::isap_a_128a_aead_decrypt/32/512       12306 ns        12305 ns        56854 bytes_per_second=42.16M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      21174 ns        21174 ns        33063 bytes_per_second=47.5629M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      21191 ns        21191 ns        33038 bytes_per_second=47.524M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      38942 ns        38941 ns        17977 bytes_per_second=50.9391M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      38954 ns        38953 ns        17970 bytes_per_second=50.9235M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      74481 ns        74479 ns         9399 bytes_per_second=52.8577M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      74489 ns        74488 ns         9395 bytes_per_second=52.8509M/s
isap_bench::isap_a_128_aead_encrypt/32/64         26013 ns        26013 ns        26909 bytes_per_second=3.51955M/s
isap_bench::isap_a_128_aead_decrypt/32/64         26011 ns        26010 ns        26909 bytes_per_second=3.51993M/s
isap_bench::isap_a_128_aead_encrypt/32/128        27483 ns        27483 ns        25469 bytes_per_second=5.55203M/s
isap_bench::isap_a_128_aead_decrypt/32/128        27491 ns        27490 ns        25463 bytes_per_second=5.55059M/s
isap_bench::isap_a_128_aead_encrypt/32/256        30454 ns        30454 ns        22989 bytes_per_second=9.01877M/s
isap_bench::isap_a_128_aead_decrypt/32/256        30464 ns        30464 ns        22978 bytes_per_second=9.01594M/s
isap_bench::isap_a_128_aead_encrypt/32/512        36381 ns        36381 ns        19241 bytes_per_second=14.2601M/s
isap_bench::isap_a_128_aead_decrypt/32/512        36395 ns        36394 ns        19233 bytes_per_second=14.2551M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       48246 ns        48244 ns        14509 bytes_per_second=20.8747M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       48259 ns        48258 ns        14504 bytes_per_second=20.8687M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       71971 ns        71970 ns         9726 bytes_per_second=27.5621M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       71979 ns        71977 ns         9725 bytes_per_second=27.5595M/s
isap_bench::isap_a_128_aead_encrypt/32/4096      119417 ns       119416 ns         5862 bytes_per_second=32.9667M/s
isap_bench::isap_a_128_aead_decrypt/32/4096      119423 ns       119423 ns         5861 bytes_per_second=32.965M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        26548 ns        26548 ns        26363 bytes_per_second=3.44856M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        26562 ns        26562 ns        26357 bytes_per_second=3.44676M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       32360 ns        32360 ns        21631 bytes_per_second=4.71534M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       32376 ns        32375 ns        21621 bytes_per_second=4.71315M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       42548 ns        42547 ns        16452 bytes_per_second=6.45546M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       42562 ns        42561 ns        16448 bytes_per_second=6.45333M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       62918 ns        62918 ns        11124 bytes_per_second=8.24567M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       62934 ns        62933 ns        11122 bytes_per_second=8.2437M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024     103667 ns       103665 ns         6752 bytes_per_second=9.71475M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024     103680 ns       103678 ns         6751 bytes_per_second=9.71349M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048     186587 ns       186584 ns         3752 bytes_per_second=10.6314M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048     186606 ns       186603 ns         3751 bytes_per_second=10.6303M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     352445 ns       352436 ns         1986 bytes_per_second=11.1701M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     352460 ns       352449 ns         1986 bytes_per_second=11.1698M/s
isap_bench::isap_k_128_aead_encrypt/32/64        191516 ns       191510 ns         3655 bytes_per_second=489.53k/s
isap_bench::isap_k_128_aead_decrypt/32/64        191538 ns       191528 ns         3655 bytes_per_second=489.484k/s
isap_bench::isap_k_128_aead_encrypt/32/128       199117 ns       199112 ns         3516 bytes_per_second=784.735k/s
isap_bench::isap_k_128_aead_decrypt/32/128       199123 ns       199122 ns         3515 bytes_per_second=784.696k/s
isap_bench::isap_k_128_aead_encrypt/32/256       212417 ns       212416 ns         3295 bytes_per_second=1.29302M/s
isap_bench::isap_k_128_aead_decrypt/32/256       212436 ns       212435 ns         3295 bytes_per_second=1.2929M/s
isap_bench::isap_k_128_aead_encrypt/32/512       239059 ns       239050 ns         2928 bytes_per_second=2.17025M/s
isap_bench::isap_k_128_aead_decrypt/32/512       239068 ns       239066 ns         2928 bytes_per_second=2.1701M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      292317 ns       292315 ns         2395 bytes_per_second=3.44519M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      292345 ns       292335 ns         2395 bytes_per_second=3.44495M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      400720 ns       400715 ns         1747 bytes_per_second=4.95026M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      400755 ns       400735 ns         1747 bytes_per_second=4.95002M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      617510 ns       617507 ns         1133 bytes_per_second=6.37526M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      617511 ns       617507 ns         1134 bytes_per_second=6.37526M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-06-24T13:05:27+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.91, 2.07, 2.15
-------------------------------------------------------------------------------------------------------
Benchmark                                             Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------------------
isap_bench::ascon_permutation<1>                   4.63 ns         4.63 ns    137327605 bytes_per_second=8.05435G/s
isap_bench::ascon_permutation<6>                   25.7 ns         25.6 ns     28171962 bytes_per_second=1.45751G/s
isap_bench::ascon_permutation<12>                  49.4 ns         48.7 ns     14675391 bytes_per_second=782.949M/s
isap_bench::keccak_permutation<1>                  39.9 ns         39.7 ns     17469036 bytes_per_second=1.17434G/s
isap_bench::keccak_permutation<8>                   333 ns          330 ns      2252658 bytes_per_second=144.371M/s
isap_bench::keccak_permutation<12>                  478 ns          476 ns      1389137 bytes_per_second=100.227M/s
isap_bench::keccak_permutation<16>                  609 ns          609 ns      1122029 bytes_per_second=78.3257M/s
isap_bench::keccak_permutation<20>                  774 ns          773 ns       894980 bytes_per_second=61.7132M/s
isap_bench::isap_a_128a_aead_encrypt/32/64         2295 ns         2293 ns       304007 bytes_per_second=39.9247M/s
isap_bench::isap_a_128a_aead_decrypt/32/64         2301 ns         2298 ns       304764 bytes_per_second=39.8406M/s
isap_bench::isap_a_128a_aead_encrypt/32/128        2896 ns         2891 ns       238422 bytes_per_second=52.7876M/s
isap_bench::isap_a_128a_aead_decrypt/32/128        2884 ns         2883 ns       241968 bytes_per_second=52.9317M/s
isap_bench::isap_a_128a_aead_encrypt/32/256        4055 ns         4053 ns       173251 bytes_per_second=67.766M/s
isap_bench::isap_a_128a_aead_decrypt/32/256        4049 ns         4046 ns       171816 bytes_per_second=67.8795M/s
isap_bench::isap_a_128a_aead_encrypt/32/512        6384 ns         6381 ns       106678 bytes_per_second=81.3034M/s
isap_bench::isap_a_128a_aead_decrypt/32/512        6382 ns         6378 ns       107638 bytes_per_second=81.3393M/s
isap_bench::isap_a_128a_aead_encrypt/32/1024      10971 ns        10967 ns        62245 bytes_per_second=91.8278M/s
isap_bench::isap_a_128a_aead_decrypt/32/1024      11007 ns        11001 ns        62401 bytes_per_second=91.5447M/s
isap_bench::isap_a_128a_aead_encrypt/32/2048      20567 ns        20551 ns        34301 bytes_per_second=96.5237M/s
isap_bench::isap_a_128a_aead_decrypt/32/2048      20387 ns        20366 ns        34122 bytes_per_second=97.4005M/s
isap_bench::isap_a_128a_aead_encrypt/32/4096      39082 ns        39059 ns        17766 bytes_per_second=100.789M/s
isap_bench::isap_a_128a_aead_decrypt/32/4096      39160 ns        39124 ns        17897 bytes_per_second=100.622M/s
isap_bench::isap_a_128_aead_encrypt/32/64         12920 ns        12908 ns        52971 bytes_per_second=7.09257M/s
isap_bench::isap_a_128_aead_decrypt/32/64         12913 ns        12902 ns        53367 bytes_per_second=7.09592M/s
isap_bench::isap_a_128_aead_encrypt/32/128        13677 ns        13671 ns        50618 bytes_per_second=11.1617M/s
isap_bench::isap_a_128_aead_decrypt/32/128        13690 ns        13681 ns        50957 bytes_per_second=11.1533M/s
isap_bench::isap_a_128_aead_encrypt/32/256        15151 ns        15143 ns        45569 bytes_per_second=18.1381M/s
isap_bench::isap_a_128_aead_decrypt/32/256        15106 ns        15099 ns        45336 bytes_per_second=18.1902M/s
isap_bench::isap_a_128_aead_encrypt/32/512        18155 ns        18142 ns        37710 bytes_per_second=28.5968M/s
isap_bench::isap_a_128_aead_decrypt/32/512        18195 ns        18182 ns        37259 bytes_per_second=28.5342M/s
isap_bench::isap_a_128_aead_encrypt/32/1024       24287 ns        24267 ns        28809 bytes_per_second=41.5002M/s
isap_bench::isap_a_128_aead_decrypt/32/1024       24389 ns        24360 ns        28726 bytes_per_second=41.3421M/s
isap_bench::isap_a_128_aead_encrypt/32/2048       36168 ns        36147 ns        19143 bytes_per_second=54.8773M/s
isap_bench::isap_a_128_aead_decrypt/32/2048       36280 ns        36258 ns        19019 bytes_per_second=54.7087M/s
isap_bench::isap_a_128_aead_encrypt/32/4096       60532 ns        60487 ns        11274 bytes_per_second=65.0844M/s
isap_bench::isap_a_128_aead_decrypt/32/4096       61136 ns        61086 ns        11281 bytes_per_second=64.446M/s
isap_bench::isap_k_128a_aead_encrypt/32/64        17151 ns        17141 ns        40655 bytes_per_second=5.34109M/s
isap_bench::isap_k_128a_aead_decrypt/32/64        17067 ns        17055 ns        39939 bytes_per_second=5.36809M/s
isap_bench::isap_k_128a_aead_encrypt/32/128       20768 ns        20752 ns        33295 bytes_per_second=7.35286M/s
isap_bench::isap_k_128a_aead_decrypt/32/128       20724 ns        20711 ns        33455 bytes_per_second=7.36742M/s
isap_bench::isap_k_128a_aead_encrypt/32/256       27136 ns        27126 ns        25445 bytes_per_second=10.1254M/s
isap_bench::isap_k_128a_aead_decrypt/32/256       27342 ns        27327 ns        25362 bytes_per_second=10.0508M/s
isap_bench::isap_k_128a_aead_encrypt/32/512       40599 ns        40562 ns        17303 bytes_per_second=12.7902M/s
isap_bench::isap_k_128a_aead_decrypt/32/512       40235 ns        40196 ns        17323 bytes_per_second=12.9068M/s
isap_bench::isap_k_128a_aead_encrypt/32/1024      65903 ns        65881 ns        10221 bytes_per_second=15.2864M/s
isap_bench::isap_k_128a_aead_decrypt/32/1024      66027 ns        65993 ns        10128 bytes_per_second=15.2605M/s
isap_bench::isap_k_128a_aead_encrypt/32/2048     118771 ns       118685 ns         5810 bytes_per_second=16.7136M/s
isap_bench::isap_k_128a_aead_decrypt/32/2048     119455 ns       119371 ns         5839 bytes_per_second=16.6174M/s
isap_bench::isap_k_128a_aead_encrypt/32/4096     224535 ns       224396 ns         3115 bytes_per_second=17.5438M/s
isap_bench::isap_k_128a_aead_decrypt/32/4096     223915 ns       223773 ns         3101 bytes_per_second=17.5927M/s
isap_bench::isap_k_128_aead_encrypt/32/64        125791 ns       125707 ns         5489 bytes_per_second=745.779k/s
isap_bench::isap_k_128_aead_decrypt/32/64        125646 ns       125603 ns         5471 bytes_per_second=746.4k/s
isap_bench::isap_k_128_aead_encrypt/32/128       130883 ns       130792 ns         5210 bytes_per_second=1.16664M/s
isap_bench::isap_k_128_aead_decrypt/32/128       131299 ns       131189 ns         5263 bytes_per_second=1.16311M/s
isap_bench::isap_k_128_aead_encrypt/32/256       139498 ns       139453 ns         4917 bytes_per_second=1.96953M/s
isap_bench::isap_k_128_aead_decrypt/32/256       139817 ns       139755 ns         4960 bytes_per_second=1.96529M/s
isap_bench::isap_k_128_aead_encrypt/32/512       156481 ns       156402 ns         4433 bytes_per_second=3.31709M/s
isap_bench::isap_k_128_aead_decrypt/32/512       157513 ns       157370 ns         4413 bytes_per_second=3.29669M/s
isap_bench::isap_k_128_aead_encrypt/32/1024      202944 ns       199982 ns         3626 bytes_per_second=5.03587M/s
isap_bench::isap_k_128_aead_decrypt/32/1024      190851 ns       190740 ns         3590 bytes_per_second=5.27987M/s
isap_bench::isap_k_128_aead_encrypt/32/2048      260141 ns       260021 ns         2659 bytes_per_second=7.62878M/s
isap_bench::isap_k_128_aead_decrypt/32/2048      260383 ns       260305 ns         2661 bytes_per_second=7.62045M/s
isap_bench::isap_k_128_aead_encrypt/32/4096      402613 ns       402320 ns         1735 bytes_per_second=9.78515M/s
isap_bench::isap_k_128_aead_decrypt/32/4096      405033 ns       404202 ns         1745 bytes_per_second=9.73961M/s
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
