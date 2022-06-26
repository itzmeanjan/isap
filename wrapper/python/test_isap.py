#!/usr/bin/python3

import isap
import numpy as np

u8 = np.uint8


def test_isap_a_128a_aead_kat():
    """
    Tests functional correctness of ISAP-A-128A implementation, using
    Known Answer Tests submitted along with final round submission of `isap` in NIST LWC
    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = isap.isap_a_128a_encrypt(key, nonce, ad, pt)
            flag, text = isap.isap_a_128a_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct), f"[ISAP-A-128A KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag), f"[ISAP-A-128A KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_isap_a_128_aead_kat():
    """
    Tests functional correctness of ISAP-A-128 implementation, using
    Known Answer Tests submitted along with final round submission of `isap` in NIST LWC
    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = isap.isap_a_128_encrypt(key, nonce, ad, pt)
            flag, text = isap.isap_a_128_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct), f"[ISAP-A-128 KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag), f"[ISAP-A-128 KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_isap_k_128a_aead_kat():
    """
    Tests functional correctness of ISAP-K-128A implementation, using
    Known Answer Tests submitted along with final round submission of `isap` in NIST LWC
    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = isap.isap_k_128a_encrypt(key, nonce, ad, pt)
            flag, text = isap.isap_k_128a_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct), f"[ISAP-K-128A KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag), f"[ISAP-K-128A KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_isap_k_128_aead_kat():
    """
    Tests functional correctness of ISAP-K-128 implementation, using
    Known Answer Tests submitted along with final round submission of `isap` in NIST LWC
    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = isap.isap_k_128_encrypt(key, nonce, ad, pt)
            flag, text = isap.isap_k_128_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct), f"[ISAP-K-128 KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag), f"[ISAP-K-128 KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


if __name__ == '__main__':
    print("Execute ISAP Known Answer Tests using `pytest` !")
