# AnyLog-TPM Compatibility Guide

This document details all modifications made to ensure TPM-generated keys and signatures are fully compatible with AnyLog's cryptographic operations.

## Table of Contents
1. [RSA Key Size: 1024-bit](#1-rsa-key-size-1024-bit)
2. [Signature Format: Hex-Encoded Raw RSA Signature](#2-signature-format-hex-encoded-raw-rsa-signature)
3. [Padding Scheme: RSAPSS (PSS)](#3-padding-scheme-rsapss-pss)
4. [Hash Algorithm: SHA256](#4-hash-algorithm-sha256)
5. [Public Key Format: PEM with SubjectPublicKeyInfo](#5-public-key-format-pem-with-subjectpublickeyinfo)
6. [Public Key Usage in JSON](#6-public-key-usage-in-json)
7. [Complete Configuration Summary](#complete-configuration-summary)
8. [Comparison Table](#comparison-table)
9. [Verification Checklist](#verification-checklist)
10. [Example: Complete Workflow](#example-complete-workflow)
11. [OpenSSL TLS Keys and TPM References](#11-openssl-tls-keys-and-tpm-references)

---

## 1. RSA Key Size: 1024-bit

### Problem
- **TPM Default**: 2048-bit RSA keys
- **AnyLog Uses**: 1024-bit RSA keys
- **Impact**: Different key sizes = different signature lengths and incompatible keys

### Solution
Changed TPM key creation to use **1024-bit RSA keys by default** to match AnyLog.

### Implementation
```python
# tpm2_api.py - create_primary_key()
key_size: int = 1024  # Default changed from 2048 to 1024

# tpm2_api.py - create_key()
key_size: int = 1024  # Default changed from 2048 to 1024
```

### Key Characteristics
- **Key Size**: 1024 bits
- **DER Length**: ~162 bytes
- **Base64 Length**: ~216 characters
- **PEM Format**: Standard SubjectPublicKeyInfo format

### API Usage
```python
# Default (1024-bit, matches AnyLog)
result = tpm.create_key(parent_context="primary.ctx", key_type="rsa")

# Explicit 1024-bit
result = tpm.create_key(parent_context="primary.ctx", key_type="rsa", key_size=1024)

# 2048-bit (if needed for other purposes)
result = tpm.create_key(parent_context="primary.ctx", key_type="rsa", key_size=2048)
```

---

## 2. Signature Format: Hex-Encoded Raw RSA Signature

### Problem
- **TPM Default**: Base64-encoded TPMT_SIGNATURE structure (~262 bytes)
- **AnyLog Uses**: Hex-encoded raw RSA signature (256 hex chars = 128 bytes)
- **Impact**: Different formats, incompatible verification

### Solution
Extract raw RSA signature from TPMT_SIGNATURE structure and convert to hex format.

### TPMT_SIGNATURE Structure
```
Offset 0-1:   sigAlg (UINT16) = 0x0014 (RSASSA) or 0x0016 (RSAPSS)
Offset 2-3:   hashAlg (UINT16) = 0x000B (SHA256)
Offset 4-5:   signature size (UINT16, big-endian)
Offset 6+:    raw RSA signature value (128 bytes for 1024-bit key)
```

### Implementation
```python
# Extract raw signature from TPMT_SIGNATURE
sig_size = int.from_bytes(signature_data[4:6], 'big')
raw_signature = signature_data[6:6+sig_size]

# Convert to hex format (like regular keys)
signature_output = raw_signature.hex()
```

### Signature Characteristics
- **Format**: Hexadecimal string (lowercase)
- **Length**: 256 hex characters (128 bytes) for 1024-bit keys
- **Encoding**: Raw RSA signature bytes converted to hex
- **Example**: `"54ca17aeda5373b41bc64704e09f7638c40a5692..."`

### API Usage
```python
# Sign with hex format (default, matches AnyLog)
result = tpm.sign_data(
    context_file="loaded_key.ctx",
    data=base64_encoded_data,
    output_format="hex"  # Default
)
# result["signature"] = "54ca17aeda5373b41bc64704e09f7638c40a5692..."

# Sign with TPM format (original)
result = tpm.sign_data(
    context_file="loaded_key.ctx",
    data=base64_encoded_data,
    output_format="base64"  # TPMT_SIGNATURE format
)
```

---

## 3. Padding Scheme: RSAPSS (PSS)

### Problem
- **TPM Default**: RSASSA (PKCS1v1.5 padding)
- **AnyLog Uses**: RSAPSS (PSS padding)
- **Impact**: Incompatible padding schemes = verification failures

### Solution
Use `-s rsapss` flag in `tpm2_sign` command to use PSS padding.

---

## 11. OpenSSL TLS Keys and TPM References

### Important Distinction
- The existing AnyLog TPM flow produces TPM tool artifacts such as `.pub`, `.priv`, and `.ctx`
- Those files are suitable for `tpm2_*` commands and the current signing workflow
- They are not the same thing as an OpenSSL TLS private key input

### TLS-Specific Solution
For OpenSSL-based TLS, use the new `create_openssl_tls_key()` method. It generates a TPM-backed
OpenSSL-readable private key reference file that can be used for TLS runtimes expecting a key file.

### Example
```python
from tpm2_api import TPM2API

tpm = TPM2API()
result = tpm.create_openssl_tls_key(
    private_key_file="server-tpm-key.pem",
    public_key_file="server-tpm-key.pub.pem",
    key_type="rsa",
    key_size=2048,
)
```

### Notes
- The generated private key file is intended to be a `TSS2 PRIVATE KEY` reference file
- The raw private key is not exported from the TPM
- Using this file with Python `ssl.load_cert_chain()` still requires an OpenSSL runtime that loads the `tpm2` provider
- The TPM API now includes `initialize_openssl_tls_support()` and `create_ssl_context()` helpers to load the provider programmatically without requiring a pre-defined OpenSSL config file
- If provider-backed loading is unavailable in the Python runtime, terminate TLS in nginx or another TLS proxy

### Implementation
```python
cmd = [
    'tpm2_sign',
    '-c', context_file,
    '-g', 'sha256',
    '-s', 'rsapss',  # ← PSS padding to match AnyLog
    '-o', signature_file,
    temp_data_file
]
```

### Padding Details
- **Scheme**: RSAPSS (RSA Probabilistic Signature Scheme)
- **MGF**: MGF1 with SHA256
- **Salt Length**: MAX_LENGTH (matches AnyLog's `padding.PSS.MAX_LENGTH`)
- **Hash**: SHA256

### AnyLog Verification Code
```python
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

---

## 4. Hash Algorithm: SHA256

### Status
✅ **Already Correct** - Both TPM and AnyLog use SHA256

### Implementation
```python
# TPM signing
'-g', 'sha256'  # Hash algorithm

# AnyLog verification
hashes.SHA256()  # Hash algorithm
```

---

## 5. Public Key Format: PEM with SubjectPublicKeyInfo

### Problem
- **TPM Output**: May not be in exact format expected by `load_pem_public_key()`
- **AnyLog Uses**: `load_pem_public_key()` from cryptography library
- **Impact**: Public key loading failures

### Solution
Standardize TPM public keys to SubjectPublicKeyInfo format using cryptography library.

### Implementation
```python
# Load TPM public key
public_key = load_pem_public_key(public_key_data, backend=default_backend())

# Re-encode in standard SubjectPublicKeyInfo format
standardized_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

### Public Key Format
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw+XHcwcNs58VODILioo7a04o2
e/S6SPT1VXijTOVkcUnpPxgu276Ln6UaAlDw+g9qr0hxt87mibsyg13dbwcDwqnH
Juvc4hM3nrNqwwMsvSVBfEb++5Y6Yz+aXg4dXVbCFl3LtTFj4YoYb9EdFkthaDLF
FgXwd3pSP61qPh9AfQIDAQAB
-----END PUBLIC KEY-----
```

### Key Points
- **Format**: PEM (Privacy-Enhanced Mail)
- **Encoding**: SubjectPublicKeyInfo (standard X.509 format)
- **Headers**: Must include `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`
- **Compatibility**: Works with `load_pem_public_key()` from cryptography library

### API Usage
```python
# Read public key (automatically standardized)
result = tpm.read_public_key(
    context_file="loaded_key.ctx",
    output_format="pem",
    standardize=True  # Default - ensures compatibility
)

# Use public_key_text (has PEM headers)
public_key_pem = result["public_key_text"]
# Can be loaded directly with load_pem_public_key()
```

---

## 6. Public Key Usage in JSON

### Problem
When storing TPM public keys in JSON (like in signed policies), the public key must be in PEM format with headers to be loaded by `load_pem_public_key()`.

### Solution

#### Option 1: Use `public_key_text` (Recommended)
Always use the `public_key_text` field from the API response, which contains the full PEM format with headers:

```python
# When getting public key from TPM
result = get_public_key(key_name, output_format="pem")
if result.get("success"):
    # ✅ Use public_key_text (has PEM headers)
    public_key_pem = result.get("public_key_text")
    
    # Store this in your JSON
    member_data = {
        "id": "user_001",
        "type": "user",
        "name": "roy",
        "public_key": public_key_pem  # Full PEM format with headers
    }
```

#### Option 2: Convert Base64 to PEM
If you already have a base64 public key (without headers), convert it to PEM format:

```python
from tpm2_api import base64_to_pem_public_key

# If you have base64 public key from JSON
public_key_b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

# Convert to PEM format
public_key_pem = base64_to_pem_public_key(public_key_b64)

# Now you can load it
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

public_key = load_pem_public_key(
    public_key_pem.encode('ascii'),
    backend=default_backend()
)
```

### API Response Format
When calling `/tpm2/read-public-key` with `output_format="pem"`:

```json
{
  "success": true,
  "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",  // Base64 (for storage)
  "public_key_text": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",  // PEM format (for loading)
  "format": "pem",
  "standardized": true
}
```

**Important**: Always use `public_key_text` when you need to load the key with `load_pem_public_key()`.

---

## Complete Configuration Summary

### TPM Key Creation
```python
# Primary Key
tpm.create_primary_key(
    password=<password>,
    hierarchy="o",
    context_file="primary.ctx",
    key_size=1024  # 1024-bit RSA
)

# Signing Key
tpm.create_key(
    parent_context="primary.ctx",
    key_type="rsa",
    key_size=1024  # 1024-bit RSA
)
```

### TPM Signing
```python
result = tpm.sign_data(
    context_file="loaded_key.ctx",
    data=base64_encoded_message,
    output_format="hex"  # Hex format like regular keys
)
# Uses: SHA256 hash, RSAPSS padding, hex output
```

### AnyLog Verification
```python
# Load public key
public_key = load_pem_public_key(
    public_key_pem.encode('ascii'),
    backend=default_backend()
)

# Verify signature
public_key.verify(
    bytes.fromhex(signature_hex),  # Convert hex to bytes
    message.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

---

## Comparison Table

| Aspect | AnyLog Regular Keys | TPM Keys (Before) | TPM Keys (After) |
|--------|---------------------|-------------------|-------------------|
| **Key Size** | 1024-bit | 2048-bit | ✅ 1024-bit |
| **Signature Format** | Hex string | Base64 TPMT_SIGNATURE | ✅ Hex string |
| **Signature Length** | 256 hex chars (128 bytes) | ~262 bytes base64 | ✅ 256 hex chars (128 bytes) |
| **Padding Scheme** | PSS | PKCS1v1.5 | ✅ PSS |
| **Hash Algorithm** | SHA256 | SHA256 | ✅ SHA256 |
| **Public Key Format** | PEM SubjectPublicKeyInfo | PEM (may vary) | ✅ PEM SubjectPublicKeyInfo |
| **Public Key Size** | ~162 bytes DER | ~294 bytes DER | ✅ ~162 bytes DER |

---

## Verification Checklist

When creating TPM keys for AnyLog compatibility, ensure:

- ✅ **Key Size**: 1024-bit RSA (`key_size=1024`)
- ✅ **Signature Format**: Hex string (`output_format="hex"`)
- ✅ **Padding Scheme**: RSAPSS (`-s rsapss` in tpm2_sign)
- ✅ **Hash Algorithm**: SHA256 (`-g sha256` in tpm2_sign)
- ✅ **Public Key Format**: PEM with SubjectPublicKeyInfo (`standardize=True`)
- ✅ **Public Key Headers**: Includes `-----BEGIN PUBLIC KEY-----` headers
- ✅ **Public Key Storage**: Use `public_key_text` field in JSON

---

## Example: Complete Workflow

```python
from tpm2_api import TPM2API
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# 1. Initialize TPM
tpm = TPM2API()

# 2. Create primary key (1024-bit)
result = tpm.create_primary_key(
    hierarchy="o",
    context_file="primary.ctx",
    key_size=1024  # Matches AnyLog
)

# 3. Create signing key (1024-bit)
result = tpm.create_key(
    parent_context="primary.ctx",
    key_type="rsa",
    key_size=1024  # Matches AnyLog
)

# 4. Load key
result = tpm.load_key(
    parent_context="primary.ctx",
    public_file="key.pub",
    private_file="key.priv",
    context_file="loaded_key.ctx"
)

# 5. Sign message (uses PSS padding, hex output)
message = '{"member": {"id": "user_001", ...}}'
encoded_message = base64.b64encode(message.encode()).decode()

result = tpm.sign_data(
    context_file="loaded_key.ctx",
    data=encoded_message,
    output_format="hex"  # Hex format like regular keys
)
signature_hex = result["signature"]

# 6. Get public key (standardized PEM format)
result = tpm.read_public_key(
    context_file="loaded_key.ctx",
    output_format="pem",
    standardize=True  # Ensures compatibility
)
public_key_pem = result["public_key_text"]

# 7. Verify signature (AnyLog code)
public_key = load_pem_public_key(
    public_key_pem.encode('ascii'),
    backend=default_backend()
)

public_key.verify(
    bytes.fromhex(signature_hex),
    message.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
# ✅ Verification succeeds!
```

---

## Notes

1. **Existing Keys**: If you have existing 2048-bit or PKCS1v1.5-signed keys, you'll need to recreate them with the new settings.

2. **Backward Compatibility**: The API still supports:
   - 2048-bit keys (via `key_size=2048`)
   - Base64 TPM format signatures (via `output_format="base64"`)
   - PKCS1v1.5 padding (by omitting `-s rsapss`)

3. **Default Behavior**: All new keys and signatures use AnyLog-compatible settings by default.

4. **Key Size Limitation**: 1024-bit keys are less secure than 2048-bit, but required for AnyLog compatibility. Consider the security implications for your use case.

---

## Files Modified

1. **tpm2_api.py**:
   - `create_primary_key()`: Added `key_size` parameter (default: 1024)
   - `create_key()`: Added `key_size` parameter (default: 1024)
   - `sign_data()`: Added `-s rsapss` flag, hex output format extraction
   - `read_public_key()`: Added standardization to SubjectPublicKeyInfo format
   - `verify_signature()`: Added hex signature format support

2. **tpm2_rest_api.py**:
   - `PrimaryKeyRequest`: Added `key_size` parameter
   - `CreateKeyRequest`: Added `key_size` parameter
   - `SignDataRequest`: Added `output_format` parameter
   - `ReadPublicKeyRequest`: Added `standardize` parameter
   - `VerifySignatureRequest`: Added `signature_format` parameter

---

## Summary

All TPM keys and signatures are now fully compatible with AnyLog's cryptographic operations:
- ✅ Same key size (1024-bit)
- ✅ Same signature format (hex)
- ✅ Same padding scheme (PSS)
- ✅ Same hash algorithm (SHA256)
- ✅ Same public key format (PEM SubjectPublicKeyInfo)

TPM-generated keys can now be used interchangeably with regular AnyLog keys!
