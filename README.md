# ✅ ECDSA (r,s,z) Signature Verifier  
`verify_r_s_z.py`

> ⚙️ Verifies whether a given ECDSA `(r, s)` signature is mathematically valid  
> for a provided message hash (`z`) and public key on the SECP256k1 curve.

---

## 🚀 Overview

This tool verifies a **single ECDSA signature** composed of `r`, `s`, and `z` (digest)  
against a known **public key** in either compressed (`02` / `03`) or uncompressed (`04`) format.

It can be used to:
- Confirm whether recovered or extracted signature values are valid
- Test reconstructed `(r, s, z)` triples
- Check public key decompression correctness

---

## 🧩 Features

| Feature | Description |
|----------|-------------|
| 🔍 **Verifies ECDSA (r,s)** | Checks full mathematical validity over SECP256k1 |
| 🧠 **Supports compressed & uncompressed pubkeys** | Handles 02/03 and 04 formats |
| ⚙️ **Direct digest mode** | Works with pre-hashed message `z` |
| 🧮 **Internal curve math** | Computes decompressed `y` coordinate from compressed key |
| 🧾 **Simple, self-contained** | Pure Python, no network or blockchain dependency |

---

## 📥 Input Parameters

All values must be provided in **hexadecimal**.

| Parameter | Description |
|------------|-------------|
| `r_hex` | Signature R component |
| `s_hex` | Signature S component |
| `z_hex` | 32-byte message digest (hash of signed message) |
| `pubkey_hex` | Public key in hex (uncompressed 04..., or compressed 02/03...) |

---

### 🧪 Example Configuration

Inside the script:
```python
r_hex = "642a1672db4db1fb8b9f7bf855614b59369d55bc4028d3b3e85b616cdc1ad348"
s_hex = "864145195db039847de1f4b0561202b7b03756a1cfedd63636bfda82d18a43e8"
z_hex = "dd37695b7387fb2198d0ed977411264e9841bf9e2322a9b6975c31aa44d8e405"
pubkey_hex = "0462a0a96e44ce7ea433cce33feba1410d2c3d3153e5892d17cb553948317214c62aae86778845feb39894ff52bf51b1e62a1229a49cd216e729df1b28b5047e55"
⚙️ How It Works

Converts the public key:

If uncompressed (04): extracts X and Y directly

If compressed (02 / 03): reconstructs Y via elliptic curve arithmetic

Builds a VerifyingKey object for SECP256k1

Encodes (r, s) into DER format

Runs the mathematical ECDSA verification:

verify_digest(sig_der, z, sigdecode=util.sigdecode_der)


Prints whether the signature is valid ✅ or invalid ❌

🧮 Internal Mechanics
Public Key Decompression

If the public key is compressed:

prefix (02 or 03) + X


then:

y² ≡ x³ + 7 (mod p)
y = sqrt(y²) mod p


and parity of y (even/odd) is determined by the prefix.

Verification Equation

ECDSA verifies whether:

r ≡ (x₁ mod n)
where (x₁, y₁) = (u₁ * G + u₂ * Q)
u₁ = z * s⁻¹ mod n
u₂ = r * s⁻¹ mod n

🧩 Example Output
✅ Successful Verification
Verifying ECDSA (r,s) for z and pubkey...
✅ Signature (r,s) is mathematically valid for the given z and pubkey.

❌ Failed Verification
Verifying ECDSA (r,s) for z and pubkey...
❌ Signature (r,s) does NOT verify for the provided z and pubkey.

⚠️ Notes

z must be the exact 32-byte digest that was originally signed.
For Bitcoin, this is the sighash digest produced from the transaction serialization.

Invalid length of z will trigger a warning.

If verification fails, double-check endianness and digest computation.

⚡ Quick Usage
python3 verify_r_s_z.py


Output:

✅ Signature (r,s) is mathematically valid for the given z and pubkey.

🔒 Ethical Use

This tool is intended for cryptographic validation and research, not for key extraction.
It allows you to confirm integrity of reconstructed or extracted ECDSA components.

You may:

Validate your own signatures

Test deterministic ECDSA implementations

Verify forensic recovery results

You must not:

Use it to validate or manipulate third-party data without consent

Attempt unauthorized verification on private key materials

⚖️ Always operate within ethical and legal standards in cryptographic analysis.

🪪 License

MIT License
© 2025 — Author: [Ethicbrudhack]

💡 Summary

This verifier is the final step in your ECDSA analysis pipeline:
confirming that recovered (r, s, z) values indeed form a valid mathematical signature.

“Verification is the final proof of understanding.”
— [Ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
