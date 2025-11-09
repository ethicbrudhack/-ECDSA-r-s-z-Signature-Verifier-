#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_r_s_z.py
Weryfikuje, czy podane r,s są poprawnym podpisem ECDSA na danym z (digest)
dla podanego pubkey (obsługuje 04..., 02..., 03...).
"""

import hashlib
from ecdsa import SECP256k1, VerifyingKey, util

# --- Dane wejściowe (wklej swoje) ---
r_hex = "642a1672db4db1fb8b9f7bf855614b59369d55bc4028d3b3e85b616cdc1ad348"
s_hex = "864145195db039847de1f4b0561202b7b03756a1cfedd63636bfda82d18a43e8"
z_hex = "dd37695b7387fb2198d0ed977411264e9841bf9e2322a9b6975c31aa44d8e405"
pubkey_hex = "0462a0a96e44ce7ea433cce33feba1410d2c3d3153e5892d17cb553948317214c62aae86778845feb39894ff52bf51b1e62a1229a49cd216e729df1b28b5047e55"
# ----------------------------------------------------------------

# parametry krzywej SECP256k1
_p = SECP256k1.curve.p()
_a = SECP256k1.curve.a()
_b = SECP256k1.curve.b()

def decompress_pubkey(compressed_bytes):
    """
    Zamienia skompresowany pubkey (0x02/0x03 + X) na 64-bajtowy X||Y.
    """
    prefix = compressed_bytes[0]
    if prefix not in (2, 3):
        raise ValueError("To nie jest skompresowany pubkey (02/03).")
    x = int.from_bytes(compressed_bytes[1:], byteorder="big")
    rhs = (pow(x, 3, _p) + (_a * x) + _b) % _p
    y = pow(rhs, (_p + 1) // 4, _p)
    if (y & 1) != (prefix & 1):
        y = (-y) % _p
    xb = x.to_bytes(32, "big")
    yb = y.to_bytes(32, "big")
    return xb + yb

def pubkey_to_verifying_key(pubkey_hex):
    pk = bytes.fromhex(pubkey_hex)
    if pk[0] == 4:
        if len(pk) != 65:
            raise ValueError("Nieprawidłowa długość nie-skompresowanego pubkey.")
        raw = pk[1:]
    elif pk[0] in (2,3):
        if len(pk) != 33:
            raise ValueError("Nieprawidłowa długość skompresowanego pubkey.")
        raw = decompress_pubkey(pk)
    else:
        raise ValueError("Nieznany format pubkey (oczekiwane 02/03/04 prefix).")
    vk = VerifyingKey.from_string(raw, curve=SECP256k1)
    return vk

def verify_signature(pubkey_hex, r_hex, s_hex, z_hex):
    vk = pubkey_to_verifying_key(pubkey_hex)
    r = int(r_hex, 16)
    s = int(s_hex, 16)
    z_bytes = bytes.fromhex(z_hex)
    if len(z_bytes) != 32:
        print("Uwaga: z nie ma długości 32 bajtów (może to być problem).")
    # DER-encoded signature, dodajemy rząd krzywej
    sig_der = util.sigencode_der(r, s, SECP256k1.order)
    try:
        ok = vk.verify_digest(sig_der, z_bytes, sigdecode=util.sigdecode_der)
        return bool(ok)
    except Exception:
        return False

if __name__ == "__main__":
    print("Weryfikacja ECDSA (r,s) dla z i podanego pubkey...")
    ok = verify_signature(pubkey_hex, r_hex, s_hex, z_hex)
    if ok:
        print("✅ Podpis (r,s) jest poprawny matematycznie dla podanego z i pubkey.")
    else:
        print("❌ Podpis (r,s) NIE weryfikuje się dla podanego z i pubkey.")
    print("\nUwaga: z musi być tym samym digest, który podpisano (w Bitcoinie to tzw. sighash).")
