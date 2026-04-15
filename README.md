# TPM2 Python API - System Call Based Implementation
<!-- 
## Overview

This project provides a Python API for TPM2 operations using system calls to the `tpm2-tools` command-line utilities instead of the problematic `tpm2-pytss` Python library. This approach is much more reliable and works perfectly in Docker containers with software TPM emulators.

## Key Features

- **System Call Based**: Uses `tpm2-tools` command-line utilities instead of Python libraries
- **Docker Ready**: Works seamlessly in containers with swtpm (software TPM emulator)
- **REST API**: FastAPI-based REST interface for TPM2 operations
- **CLI Interface**: Command-line interface for direct TPM2 operations
- **No Complex Dependencies**: Eliminates the need for complex TPM2 Python library installations

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Python API    │    │   tpm2-tools    │
│   REST Server   │───▶│   (System Calls)│───▶│   (CLI Tools)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   swtpm         │
                       │   (TPM Emulator)│
                       └─────────────────┘
```

## Docker Setup

The project includes a complete Docker setup with:
- Ubuntu base image
- TPM2-TSS library (built from source)
- swtpm (software TPM emulator)
- tpm2-tools (command-line utilities)
- FastAPI and Python dependencies -->


## Key Features
- **REST API**: Access TPM2 functionality via a FastAPI-based REST API for easy integration with other services and automation.
- **CLI Interface**: Use the Python command-line interface (CLI) for direct TPM2 operations from the terminal or scripts.
- **Encrypted File Store**: Secure key-value storage with TPM2 encryption, allowing you to store and retrieve sensitive data in encrypted JSON files.



### Building and Running

```bash
# Build the Docker image
docker build -t tpm2-api .

# Run the container for REST API
docker run -d --name tpm2-test -p 8000:8000 tpm2-api python3 /opt/tpm2_rest_api.py

# Run the container for interactive CLI
# Start container and get a bash shell
docker run --rm -it tpm2-api bash
# With volume mount for file sharing
docker run --rm -it -v $(pwd):/workspace -w /workspace tpm2-api bash

# Delete the container and image
docker rm -f tpm2-test tpm2-cli 2>/dev/null; docker rmi -f tpm2-api 2>/dev/null
```

### Multiple TPM Instances

To run multiple independent TPM instances (e.g., for different nodes), use the `multiple-instances/` folder:

```bash
./multiple-instances/setup-multiple-instances.sh 5
docker-compose -f multiple-instances/docker-compose.instances.yaml up -d
```

See **[multiple-instances/README.md](multiple-instances/README.md)** for TPM instances. For AnyLog nodes, see **[multiple-nodes/README.md](multiple-nodes/README.md)**.

## API Endpoints

### Health Check
- `GET /health` - Check TPM2 connection and status

### TPM2 Operations
- `POST /tpm2/create-primary` - Create a primary key
- `POST /tpm2/create-key` - Create a key under a parent (supports RSA, ECC, AES128, AES256)
- `POST /tpm2/load-key` - Load a key into TPM context
- `POST /tpm2/make-persistent` - Make a key persistent
- `POST /tpm2/flush-context` - Flush TPM contexts
- `GET /tpm2/info` - Get TPM information
- `POST /tpm2/sign` - Sign data using a loaded key
- `POST /tpm2/verify` - Verify a signature
- `POST /tpm2/encrypt` - Encrypt data using a loaded RSA key
- `POST /tpm2/decrypt` - Decrypt data using a loaded RSA key
- `POST /tpm2/encrypt-aes` - Encrypt data using a loaded AES key
- `POST /tpm2/decrypt-aes` - Decrypt data using a loaded AES key
- `POST /tpm2/full-reset` - Complete TPM reset (clears all contexts, persistent objects, and authorizations)

### Encrypted File Store Endpoints
- `POST /tpm2/file-store/create` - Create a new encrypted file store (RSA)
- `POST /tpm2/file-store/store` - Store a key-value pair in the encrypted file store (RSA)
- `POST /tpm2/file-store/retrieve` - Retrieve a key-value pair from the encrypted file store (RSA)
- `POST /tpm2/file-store/list-keys` - List all keys in the encrypted file store (RSA)
- `POST /tpm2/file-store/delete` - Delete a key-value pair from the encrypted file store (RSA)

### AES Encrypted File Store Endpoints
- `POST /tpm2/file-store-aes/create` - Create a new encrypted file store (AES)
- `POST /tpm2/file-store-aes/store` - Store a key-value pair in the encrypted file store (AES)
- `POST /tpm2/file-store-aes/retrieve` - Retrieve a key-value pair from the encrypted file store (AES)
- `POST /tpm2/file-store-aes/list-keys` - List all keys in the encrypted file store (AES)
- `POST /tpm2/file-store-aes/delete` - Delete a key-value pair from the encrypted file store (AES)

### Convenience Endpoints
- `POST /tpm2/workflow/complete` - Execute complete workflow
- `POST /tpm2/upload-key` - Upload key files

## Usage Examples

### Create Primary Key
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"hierarchy": "o", "context_file": "primary.ctx", "password": "abc"}' \
  http://localhost:8000/tpm2/create-primary
```

### Create RSA Key
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"parent_context": "primary.ctx", "key_type": "rsa", "public_file": "rsa.pub", "private_file": "rsa.priv", "password": "abc"}' \
  http://localhost:8000/tpm2/create-key
```

### Create AES Key
```bash
# Create AES-128 key
curl -X POST -H "Content-Type: application/json" \
  -d '{"parent_context": "primary.ctx", "key_type": "aes128", "public_file": "aes128_key.ctx", "password": "abc"}' \
  http://localhost:8000/tpm2/create-key

# Create AES-256 key
curl -X POST -H "Content-Type: application/json" \
  -d '{"parent_context": "primary.ctx", "key_type": "aes256", "public_file": "aes256_key.ctx", "password": "abc"}' \
  http://localhost:8000/tpm2/create-key
```

### Load Key
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"parent_context": "primary.ctx", "public_file": "rsa.pub", "private_file": "rsa.priv", "context_file": "loaded_key.ctx", "password": "abc"}' \
  http://localhost:8000/tpm2/load-key
```

### Make Key Persistent (EvictControl)
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "loaded_key.ctx", "persistent_handle": "0x81010001", "password": "abc"}' \
  http://localhost:8000/tpm2/make-persistent
```

### Flush Contexts (when running out of memory)
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_type": "transient"}' \
  http://localhost:8000/tpm2/flush-context
```

### Full TPM Reset (CLI)
```bash
# ⚠️ WARNING: This performs a complete TPM reset!
python3 tpm2_cli.py full-reset
```

### Sign Data
```bash
# First, ensure you have a loaded key context
# Then sign data (data must be base64 encoded)
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "loaded_key.ctx", "data": "SGVsbG8gV29ybGQ=", "signature_file": "signature.sig", "password": "abc"}' \
  http://localhost:8000/tpm2/sign
```

### Verify Signature
```bash
# Verify a signature against the original data
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "loaded_key.ctx", "data": "SGVsbG8gV29ybGQ=", "signature": "base64_encoded_signature_here"}' \
  http://localhost:8000/tpm2/verify
```



### Encrypt Data
```bash
# Encrypt data using a loaded RSA key
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "loaded_key.ctx", "data": "SGVsbG8gV29ybGQ=", "encrypted_file": "encrypted.bin"}' \
  http://localhost:8000/tpm2/encrypt
```

### Decrypt Data
```bash
# Decrypt data using a loaded RSA key
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "loaded_key.ctx", "encrypted_data": "base64_encoded_encrypted_data", "decrypted_file": "decrypted.bin", "password": "abc"}' \
  http://localhost:8000/tpm2/decrypt
```

### Encrypt/Decrypt Data with AES
```bash
# Encrypt data using a loaded AES key
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "data": "base64_encoded_data", "encrypted_file": "encrypted_aes.bin", "password": "abc"}' \
  http://localhost:8000/tpm2/encrypt-aes

# Decrypt data using a loaded AES key
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "encrypted_data": "base64_encoded_encrypted_data", "decrypted_file": "decrypted_aes.bin", "password": "abc"}' \
  http://localhost:8000/tpm2/decrypt-aes
```

### Encrypted File Store Operations

#### Create Encrypted File Store
```bash
# Create a new encrypted file store
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json"}' \
  http://localhost:8000/tpm2/file-store/create
```

#### Store Key-Value Pair
```bash
# Store a simple string value
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json", "key": "username", "value": "john_doe", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store/store

# Store a complex object
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json", "key": "user_profile", "value": {"name": "John Doe", "email": "john@example.com"}, "password": "abc"}' \
  http://localhost:8000/tpm2/file-store/store
```

#### Retrieve Key-Value Pair
```bash
# Retrieve a stored value
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json", "key": "username", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store/retrieve
```

#### List All Keys
```bash
# List all keys in the encrypted file store
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store/list-keys
```

#### Delete Key-Value Pair
```bash
# Delete a key-value pair
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "encrypt_key.ctx", "store_name": "my_secure_store.json", "key": "username", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store/delete
```

### AES Encrypted File Store Operations

#### Create AES Encrypted File Store
```bash
# Create a new AES encrypted file store
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/create
```

#### Store Key-Value Pair (AES)
```bash
# Store a simple string value using AES
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "key": "username", "value": "john_doe", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/store

# Store a complex object using AES
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "key": "user_profile", "value": {"name": "John Doe", "email": "john@example.com"}, "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/store
```

#### Retrieve Key-Value Pair (AES)
```bash
# Retrieve a stored value using AES
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "key": "username", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/retrieve
```

#### List All Keys (AES)
```bash
# List all keys in the AES encrypted file store
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/list-keys
```

#### Delete Key-Value Pair (AES)
```bash
# Delete a key-value pair using AES
curl -X POST -H "Content-Type: application/json" \
  -d '{"context_file": "aes256_key.ctx", "store_name": "my_aes_secure_store.json", "key": "username", "password": "abc"}' \
  http://localhost:8000/tpm2/file-store-aes/delete
```

### Full TPM Reset
```bash
# ⚠️ WARNING: This performs a complete TPM reset!
# Clears all contexts, persistent objects, and authorizations
curl -X POST -H "Content-Type: application/json" \
  -d '{"password": "abc"}' \
  http://localhost:8000/tpm2/full-reset
```

### Complete Sign/Verify Workflow Example
```python
import base64
import requests
import json

# API base URL
base_url = "http://localhost:8000"

# 1. Create primary key
print("Creating primary key...")
response = requests.post(f"{base_url}/tpm2/create-primary", 
                        json={"hierarchy": "o", "context_file": "primary.ctx"})
print(json.dumps(response.json(), indent=2))

# 2. Create RSA key
print("\nCreating RSA key...")
response = requests.post(f"{base_url}/tpm2/create-key",
                        json={"parent_context": "primary.ctx", 
                              "key_type": "rsa", 
                              "public_file": "rsa.pub", 
                              "private_file": "rsa.priv"})
print(json.dumps(response.json(), indent=2))

# 3. Load the key
print("\nLoading key...")
response = requests.post(f"{base_url}/tpm2/load-key",
                        json={"parent_context": "primary.ctx",
                              "public_file": "rsa.pub",
                              "private_file": "rsa.priv",
                              "context_file": "loaded_key.ctx"})
print(json.dumps(response.json(), indent=2))

# 4. Prepare data to sign (base64 encode)
data_to_sign = "Hello, TPM2 World!"
encoded_data = base64.b64encode(data_to_sign.encode()).decode()
print(f"\nData to sign: {data_to_sign}")
print(f"Base64 encoded: {encoded_data}")

# 5. Sign the data
print("\nSigning data...")
response = requests.post(f"{base_url}/tpm2/sign",
                        json={"context_file": "loaded_key.ctx",
                              "data": encoded_data,
                              "signature_file": "signature.sig"})
sign_result = response.json()
print(json.dumps(sign_result, indent=2))

if sign_result.get("success"):
    signature = sign_result["signature"]
    print(f"Signature (base64): {signature}")
    
    # 6. Verify the signature
    print("\nVerifying signature...")
    response = requests.post(f"{base_url}/tpm2/verify",
                            json={"context_file": "loaded_key.ctx",
                                  "data": encoded_data,
                                  "signature": signature})
    verify_result = response.json()
    print(json.dumps(verify_result, indent=2))
    
    if verify_result.get("verified"):
        print("✅ Signature verification successful!")
    else:
        print("❌ Signature verification failed!")
else:
    print("❌ Signing failed!")
```

### Direct Python API Usage (without REST)
```python
from tpm2_api import TPM2API
import base64

# Initialize TPM2 API
tpm = TPM2API()

# Create primary key
result = tpm.create_primary_key()
print("Primary key created:", result["success"])

# Create and load RSA key
result = tpm.create_key("primary.ctx", "rsa", "rsa.pub", "rsa.priv")
print("RSA key created:", result["success"])

result = tpm.load_key("primary.ctx", "rsa.pub", "rsa.priv", "loaded_key.ctx")
print("Key loaded:", result["success"])

# Sign data
data = "Hello, TPM2!"
encoded_data = base64.b64encode(data.encode()).decode()

result = tpm.sign_data("loaded_key.ctx", encoded_data, "signature.sig")
if result["success"]:
    signature = result["signature"]
    print(f"Signature: {signature}")
    
    # Verify signature
    verify_result = tpm.verify_signature("loaded_key.ctx", encoded_data, signature)
    print(f"Verification: {verify_result['verified']}")
```

### Complete Encryption/Decryption Workflow Example
```python
import base64
import requests
import json

# API base URL
base_url = "http://localhost:8000"

# 1. Create primary key
print("Creating primary key...")
response = requests.post(f"{base_url}/tpm2/create-primary", 
                        json={"hierarchy": "o", "context_file": "primary.ctx"})
print(json.dumps(response.json(), indent=2))

# 2. Create encryption key
print("\nCreating encryption key...")
response = requests.post(f"{base_url}/tpm2/create-key",
                        json={"parent_context": "primary.ctx", 
                              "key_type": "rsa", 
                              "public_file": "encrypt_key.pub", 
                              "private_file": "encrypt_key.priv"})
print(json.dumps(response.json(), indent=2))

# 3. Load encryption key
print("\nLoading encryption key...")
response = requests.post(f"{base_url}/tpm2/load-key",
                        json={"parent_context": "primary.ctx",
                              "public_file": "encrypt_key.pub",
                              "private_file": "encrypt_key.priv",
                              "context_file": "encrypt_key.ctx"})
print(json.dumps(response.json(), indent=2))

# 4. Prepare data to encrypt (base64 encode)
data_to_encrypt = "Secret message for encryption!"
encoded_data = base64.b64encode(data_to_encrypt.encode()).decode()
print(f"\nData to encrypt: {data_to_encrypt}")
print(f"Base64 encoded: {encoded_data}")

# 5. Encrypt the data
print("\nEncrypting data...")
response = requests.post(f"{base_url}/tpm2/encrypt",
                        json={"context_file": "encrypt_key.ctx",
                              "data": encoded_data,
                              "encrypted_file": "encrypted.bin"})
encrypt_result = response.json()
print(json.dumps(encrypt_result, indent=2))

if encrypt_result.get("success"):
    encrypted_data = encrypt_result["encrypted_data"]
    print(f"Encrypted data (base64): {encrypted_data}")
    
    # 6. Decrypt the data
    print("\nDecrypting data...")
    response = requests.post(f"{base_url}/tpm2/decrypt",
                            json={"context_file": "encrypt_key.ctx",
                                  "encrypted_data": encrypted_data,
                                  "decrypted_file": "decrypted.bin"})
    decrypt_result = response.json()
    print(json.dumps(decrypt_result, indent=2))
    
    if decrypt_result.get("success"):
        decrypted_data = decrypt_result["decrypted_data"]
        original_data = base64.b64decode(decrypted_data).decode()
        print(f"✅ Decryption successful!")
        print(f"Original data: {data_to_encrypt}")
        print(f"Decrypted data: {original_data}")
        print(f"Match: {data_to_encrypt == original_data}")
    else:
        print("❌ Decryption failed!")
else:
    print("❌ Encryption failed!")
```

### Complete Encrypted File Store Workflow Example
```python
import base64
import requests
import json

# API base URL
base_url = "http://localhost:8000"

# 1. Create primary key
print("Creating primary key...")
response = requests.post(f"{base_url}/tpm2/create-primary", 
                        json={"hierarchy": "o", "context_file": "primary.ctx"})
print(json.dumps(response.json(), indent=2))

# 2. Create encryption key
print("\nCreating encryption key...")
response = requests.post(f"{base_url}/tpm2/create-key",
                        json={"parent_context": "primary.ctx", 
                              "key_type": "rsa", 
                              "public_file": "encrypt_key.pub", 
                              "private_file": "encrypt_key.priv"})
print(json.dumps(response.json(), indent=2))

# 3. Load encryption key
print("\nLoading encryption key...")
response = requests.post(f"{base_url}/tpm2/load-key",
                        json={"parent_context": "primary.ctx",
                              "public_file": "encrypt_key.pub",
                              "private_file": "encrypt_key.priv",
                              "context_file": "encrypt_key.ctx"})
print(json.dumps(response.json(), indent=2))

# 4. Create encrypted file store
print("\nCreating encrypted file store...")
response = requests.post(f"{base_url}/tpm2/file-store/create",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json"})
print(json.dumps(response.json(), indent=2))

# 5. Store various types of data
print("\nStoring data...")

# Store a string
response = requests.post(f"{base_url}/tpm2/file-store/store",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json",
                              "key": "username",
                              "value": "john_doe"})
print("String stored:", response.json()["success"])

# Store a complex object
user_data = {
    "name": "John Doe",
    "email": "john@example.com",
    "preferences": {"theme": "dark", "notifications": True}
}
response = requests.post(f"{base_url}/tpm2/file-store/store",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json",
                              "key": "user_profile",
                              "value": user_data})
print("Object stored:", response.json()["success"])

# 6. List all keys
print("\nListing all keys...")
response = requests.post(f"{base_url}/tpm2/file-store/list-keys",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json"})
result = response.json()
print(f"Total keys: {result['total_keys']}")
print(f"Keys: {result['keys']}")

# 7. Retrieve stored data
print("\nRetrieving data...")
response = requests.post(f"{base_url}/tpm2/file-store/retrieve",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json",
                              "key": "user_profile"})
result = response.json()
if result["success"]:
    print(f"Retrieved user profile: {result['value']}")

# 8. Update existing data
print("\nUpdating data...")
response = requests.post(f"{base_url}/tpm2/file-store/store",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json",
                              "key": "username",
                              "value": "john_doe_updated"})
print("Data updated:", response.json()["success"])

# 9. Delete a key
print("\nDeleting key...")
response = requests.post(f"{base_url}/tpm2/file-store/delete",
                        json={"context_file": "encrypt_key.ctx",
                              "store_name": "my_secure_store.json",
                              "key": "username"})
print("Key deleted:", response.json()["success"])

print("\n✅ Encrypted file store workflow completed!")
```
<!-- 
## Key Advantages

1. **Reliability**: No complex Python library dependencies
2. **Compatibility**: Works with any TPM2 implementation
3. **Simplicity**: Uses proven command-line tools
4. **Docker Friendly**: Perfect for containerized deployments
5. **Error Handling**: Better error messages and debugging
6. **Extensibility**: Easy to add new TPM2 operations -->

## Limitations

- **Memory Constraints**: Software TPM emulators have limited memory for object contexts
- **Performance**: System calls are slightly slower than direct library calls
- **File Management**: Requires careful management of context files

## Troubleshooting

### Out of Memory Errors
When you encounter "out of memory for object contexts" errors:
1. Flush all contexts: `POST /tpm2/flush-context` with `{"context_type": "transient"}` or `{"context_type": "all"}`
2. Retry your operation

### TCTI Configuration
The API supports both hardware TPM and software TPM (SWTPM). TCTI configuration priority:
1. Explicit parameter when creating `TPM2API()` instance
2. `TPM2_TCTI` environment variable (or `TSS2_TCTI`/`TPM2TOOLS_TCTI`)
3. Auto-detection of hardware TPM
4. Default to SWTPM: `swtpm:host=127.0.0.1,port=2321`

#### Hardware TPM Configuration
For hardware TPM on Ubuntu/Linux systems, the API will auto-detect and use:
- `/dev/tpmrm0` (TPM Resource Manager - preferred, no root required)
- `/dev/tpm0` (Direct device access - requires root or tss group)
- `tabrmd:` (TPM2 Access Broker daemon - if running)

**Manual Configuration:**
```bash
# Using environment variable (recommended)
export TPM2_TCTI="device:/dev/tpmrm0"
python3 tpm2_rest_api.py

# Or for tabrmd daemon
export TPM2_TCTI="tabrmd:"
python3 tpm2_rest_api.py
```

**In Python code:**
```python
from tpm2_api import TPM2API

# Auto-detect hardware TPM
tpm = TPM2API()

# Or specify explicitly
tpm = TPM2API("device:/dev/tpmrm0")
tpm = TPM2API("tabrmd:")
```

**Prerequisites for Hardware TPM:**
1. Install TPM2 tools: `sudo apt-get install tpm2-tools tpm2-abrmd`
2. Ensure user is in `tss` group: `sudo usermod -aG tss $USER` (then log out/in)
3. Verify TPM device exists: `ls -l /dev/tpm*`
4. (Optional) Start tabrmd daemon: `sudo systemctl start tpm2-abrmd`

**SSH to Remote Hardware TPM:**
When SSH'ing to a remote Ubuntu machine with hardware TPM:
1. Ensure TPM2 tools are installed on the remote machine
2. The API will auto-detect the hardware TPM when running on that machine
3. No special configuration needed - just run the API normally

## Development

### Local Development
```bash
# Install dependencies
pip install fastapi uvicorn pydantic python-multipart

# Run the API
python3 tpm2_rest_api.py
```

### Testing
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test complete workflow
curl -X POST -H "Content-Type: application/json" \
  -d '{"password": "abc"}' \
  http://localhost:8000/tpm2/workflow/complete
```

## Lockout Mode
- **DA Lockout Mode**:  
  If you encounter DA (Dictionary Attack) lockout mode (often indicated by errors related to TPM authorization or failed attempts), you will need to reset the lockout state. To do this, open a shell in the running container (e.g., using `docker exec -it <container_name> /bin/bash`) and run the following command to clear lockout and set a high maximum tries value:

  ```
  tpm2_dictionarylockout --setup-parameters --max-tries=4294967295 --clear-lockout
  ```

  This command clears any lockout and increases the allowed number of failed authorization attempts, greatly reducing the chance of future lockout events. Make sure you have the necessary TPM permissions inside the container to execute this command.

<!-- 
## Files Structure

- `tpm2_api.py` - Core TPM2 API using system calls
- `tpm2_rest_api.py` - FastAPI REST server
- `tpm2_cli.py` - Command-line interface
- `Dockerfile` - Docker container definition
- `entrypoint.sh` - Container startup script
- `requirements.txt` - Python dependencies

## Success Metrics

✅ **Primary Key Creation**: Working  
✅ **Key Creation**: Working  
✅ **Context Flushing**: Working  
✅ **TPM Information**: Working  
✅ **REST API**: Working  
✅ **Docker Container**: Working  
✅ **System Call Approach**: Working   -->
<!-- 
The system-call-based approach successfully eliminates the dependency issues with `tpm2-pytss` and provides a reliable, containerized TPM2 API solution.  -->
