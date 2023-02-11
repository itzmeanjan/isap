#!/bin/bash

# Script for ease of execution of Known Answer Tests against ISAP implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of ISAP
wget -O isap.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/isap.zip
# uncomress
unzip isap.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp isap/Implementations/crypto_aead/isapa128av20/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.isap_a_128a
cp isap/Implementations/crypto_aead/isapa128v20/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.isap_a_128
cp isap/Implementations/crypto_aead/isapk128av20/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.isap_k_128a
cp isap/Implementations/crypto_aead/isapk128v20/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.isap_k_128

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# ---

pushd wrapper/python

# run tests
mv ../../LWC_AEAD_KAT_128_128.txt.isap_a_128a LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k isap_a_128a_aead --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.isap_a_128 LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k isap_a_128_aead --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.isap_k_128a LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k isap_k_128a_aead --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.isap_k_128 LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k isap_k_128_aead --cache-clear -v

# clean up
rm LWC_AEAD_KAT_*.txt

popd

make clean

# ---
