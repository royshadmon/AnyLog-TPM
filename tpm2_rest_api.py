#!/usr/bin/env python3
"""
TPM2 REST API - FastAPI wrapper for TPM2 operations
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from typing import Any, Union
import uvicorn
import os

# Import our TPM2 API
from tpm2_api import TPM2API

# Initialize FastAPI app
app = FastAPI(
    title="TPM2 REST API",
    description="REST API for TPM2 operations supporting both hardware TPM and software TPM emulator",
    version="1.0.0"
)

# Initialize TPM2 API
# TCTI can be configured via TPM2_TCTI environment variable
# If not set, will auto-detect hardware TPM or use SWTPM default
try:
    tpm_api = TPM2API()
    print(f"TPM2 API initialized with TCTI: {tpm_api.tcti_name}")
except Exception as e:
    print(f"Warning: TPM2 API initialization failed: {e}")
    tpm_api = None

# Pydantic models for request/response
class PrimaryKeyRequest(BaseModel):
    hierarchy: str = "o"
    context_file: str = "primary.ctx"
    key_size: int = 1024  # RSA key size in bits (1024 or 2048, default: 1024 to match AnyLog)
    password: str

class CreateKeyRequest(BaseModel):
    parent_context: str
    key_type: str = "rsa"
    public_file: str = "key.pub"
    private_file: str = "key.priv"
    key_size: int = 1024  # RSA key size in bits (1024 or 2048, default: 1024 to match AnyLog)
    password: str

class ImportKeyRequest(BaseModel):
    parent_context: str
    key_type: str = "rsa"
    private_key_file: str  # External private key file (PEM format)
    public_file: str = "imported_key.pub"
    private_file: str = "imported_key.priv"
    password: str

class LoadKeyRequest(BaseModel):
    parent_context: str
    public_file: str
    private_file: str
    context_file: str = "loaded_key.ctx"
    password: str

class PersistentRequest(BaseModel):
    context_file: str
    persistent_handle: Union[int, str] = 0x81010001
    password: str
    
    @validator('persistent_handle', pre=True)
    def parse_persistent_handle(cls, v):
        if isinstance(v, int):
            return v
        elif isinstance(v, str):
            # Handle hexadecimal strings (e.g., "0x81010001")
            if v.startswith('0x') or v.startswith('0X'):
                try:
                    return int(v, 16)
                except ValueError:
                    raise ValueError(f"Invalid hexadecimal value: {v}")
            # Handle decimal strings
            else:
                try:
                    return int(v)
                except ValueError:
                    raise ValueError(f"Invalid integer value: {v}")
        else:
            raise ValueError(f"persistent_handle must be an integer or string, got {type(v)}")

class FlushContextRequest(BaseModel):
    context_type: str = "transient"

class SignDataRequest(BaseModel):
    context_file: str
    data: str  # base64 encoded data
    signature_file: str = "signature.sig"
    output_format: str = "hex"  # "hex" (like regular keys) or "base64" (TPM format)
    scheme: str = "rsapss"  # Preserve current behavior unless caller overrides it
    hash_alg: str = "sha256"  # Preserve current behavior unless caller overrides it
    input_kind: str = "message"  # "message" or "digest"
    password: str

class VerifySignatureRequest(BaseModel):
    context_file: str
    data: str  # base64 encoded data
    signature: str  # hex string (like regular keys) or base64 encoded TPM format
    signature_format: str = "auto"  # "hex", "base64", or "auto" (detect automatically)
    scheme: str = "rsapss"  # Preserve current behavior unless caller overrides it
    hash_alg: str = "sha256"  # Preserve current behavior unless caller overrides it
    input_kind: str = "message"  # "message" or "digest"

class ReadPublicKeyRequest(BaseModel):
    context_file: str
    output_format: str = "pem"  # 'pem' or 'der'
    standardize: bool = True  # Convert to standard SubjectPublicKeyInfo format for cryptography library

class EncryptDataRequest(BaseModel):
    context_file: str
    data: str  # base64 encoded data
    encrypted_file: str = "encrypted.bin"

class DecryptDataRequest(BaseModel):
    context_file: str
    encrypted_data: str  # base64 encoded encrypted data
    decrypted_file: str = "decrypted.bin"
    password: str

class FullResetRequest(BaseModel):
    password: str

class CompleteWorkFlow(BaseModel):
    password: str

class CreateFileStoreRequest(BaseModel):
    context_file: str
    store_name: str = "file_store.json"

class StoreKeyValueRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    value: Any  # Can be any JSON-serializable value
    password: str

class RetrieveKeyValueRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    password: str

class ListFileStoreKeysRequest(BaseModel):
    context_file: str
    store_name: str
    password: str

class DeleteKeyValueRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    password: str

class EncryptDataAESRequest(BaseModel):
    context_file: str
    data: str  # base64 encoded data
    encrypted_file: str = "encrypted_aes.bin"
    password: str

class DecryptDataAESRequest(BaseModel):
    context_file: str
    encrypted_data: str  # base64 encoded encrypted data
    decrypted_file: str = "decrypted_aes.bin"
    password: str

class CreateFileStoreAESRequest(BaseModel):
    context_file: str
    store_name: str = "file_store_aes.json"
    password: str

class StoreKeyValueAESRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    value: Any  # Can be any JSON-serializable value
    password: str

class RetrieveKeyValueAESRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    password: str

class ListFileStoreKeysAESRequest(BaseModel):
    context_file: str
    store_name: str
    password: str

class DeleteKeyValueAESRequest(BaseModel):
    context_file: str
    store_name: str
    key: str
    password: str

class DeleteFileRequest(BaseModel):
    file_path: str  # Relative path to file in working directory

class ListFilesRequest(BaseModel):
    directory: str = "."  # Relative path to directory to list (default: current directory)


# Health check endpoint
@app.get("/")
async def root():
    return {"message": "TPM2 REST API is running"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        info = tpm_api.get_tpm_info()
        return {
            "status": "healthy",
            "tpm_info": info
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"TPM2 health check failed: {e}")

# TPM2 operation endpoints
@app.post("/tpm2/create-primary")
async def create_primary_key(request: PrimaryKeyRequest):
    """Create a primary key in the specified hierarchy"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.create_primary_key(
            password=request.password,
            hierarchy=request.hierarchy,
            context_file=request.context_file,
            key_size=request.key_size
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/create-key")
async def create_key(request: CreateKeyRequest):
    """Create a key under the specified parent"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.create_key(
            parent_context=request.parent_context,
            password=request.password,
            key_type=request.key_type,
            public_file=request.public_file,
            private_file=request.private_file,
            key_size=request.key_size
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/import-key")
async def import_key(request: ImportKeyRequest):
    """Import an externally generated key into TPM format"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.import_key(
            parent_context=request.parent_context,
            key_type=request.key_type,
            private_key_file=request.private_key_file,
            password=request.password,
            public_file=request.public_file,
            private_file=request.private_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/load-key")
async def load_key(request: LoadKeyRequest):
    """Load a key into the TPM"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.load_key(
            parent_context=request.parent_context,
            public_file=request.public_file,
            private_file=request.private_file,
            password=request.password,
            context_file=request.context_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/make-persistent")
async def make_persistent(request: PersistentRequest):
    """Make a loaded key persistent"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.make_persistent(
            context_file=request.context_file,
            password=request.password,
            persistent_handle=request.persistent_handle
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/flush-context")
async def flush_context(request: FlushContextRequest):
    """Flush TPM contexts"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.flush_context(context_type=request.context_type)
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tpm2/info")
async def get_tpm_info():
    """Get TPM information"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.get_tpm_info()
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/sign")
async def sign_data(request: SignDataRequest):
    """Sign data using a loaded key"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.sign_data(
            context_file=request.context_file,
            data=request.data,
            password=request.password,
            signature_file=request.signature_file,
            output_format=request.output_format,
            scheme=request.scheme,
            hash_alg=request.hash_alg,
            input_kind=request.input_kind,
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/verify")
async def verify_signature(request: VerifySignatureRequest):
    """Verify a signature"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.verify_signature(
            context_file=request.context_file,
            data=request.data,
            signature=request.signature,
            signature_format=request.signature_format,
            scheme=request.scheme,
            hash_alg=request.hash_alg,
            input_kind=request.input_kind,
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/read-public-key")
async def read_public_key(request: ReadPublicKeyRequest):
    """Read the public key from a loaded key context"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.read_public_key(
            context_file=request.context_file,
            output_format=request.output_format,
            standardize=request.standardize
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/encrypt")
async def encrypt_data(request: EncryptDataRequest):
    """Encrypt data using a loaded RSA key"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.encrypt_data(
            context_file=request.context_file,
            data=request.data,
            encrypted_file=request.encrypted_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/decrypt")
async def decrypt_data(request: DecryptDataRequest):
    """Decrypt data using a loaded RSA key"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.decrypt_data(
            context_file=request.context_file,
            encrypted_data=request.encrypted_data,
            password=request.password,
            decrypted_file=request.decrypted_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/full-reset")
async def full_reset(request: FullResetRequest):
    """Perform a complete TPM reset - clears all contexts, persistent objects, and authorizations"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.full_reset(password=request.password)
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Convenience endpoint for the complete workflow
@app.post("/tpm2/workflow/complete")
async def complete_workflow(request: CompleteWorkFlow):
    """Execute the complete TPM2 workflow: create primary -> create key -> load -> make persistent"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        results = {}
        
        # Step 1: Create primary key
        print("Creating primary key...")
        result = tpm_api.create_primary_key(request.password)
        results["create_primary"] = result
        if not result["success"]:
            raise HTTPException(status_code=400, detail=f"Primary key creation failed: {result['error']}")
        
        # Step 2: Create RSA key
        print("Creating RSA key...")
        result = tpm_api.create_key("primary.ctx", request.password, "rsa", "rsa.pub", "rsa.priv")
        results["create_key"] = result
        if not result["success"]:
            raise HTTPException(status_code=400, detail=f"Key creation failed: {result['error']}")
        
        # Step 3: Load key
        print("Loading key...")
        result = tpm_api.load_key("primary.ctx", "rsa.pub", "rsa.priv", request.password, "rsa.ctx")
        results["load_key"] = result
        if not result["success"]:
            raise HTTPException(status_code=400, detail=f"Key loading failed: {result['error']}")
        
        # Step 4: Make persistent
        print("Making key persistent...")
        result = tpm_api.make_persistent("rsa.ctx", request.password)
        results["make_persistent"] = result
        if not result["success"]:
            raise HTTPException(status_code=400, detail=f"Making persistent failed: {result['error']}")
        
        return JSONResponse(content={
            "success": True,
            "message": "Complete workflow executed successfully",
            "results": results
        }, status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Encrypted File Store endpoints
@app.post("/tpm2/file-store/create")
async def create_file_store(request: CreateFileStoreRequest):
    """Create a new encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.create_encrypted_file_store(
            context_file=request.context_file,
            store_name=request.store_name
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store/store")
async def store_key_value(request: StoreKeyValueRequest):
    """Store a key-value pair in the encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.store_key_value(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            value=request.value,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store/retrieve")
async def retrieve_key_value(request: RetrieveKeyValueRequest):
    """Retrieve a key-value pair from the encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.retrieve_key_value(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store/list-keys")
async def list_file_store_keys(request: ListFileStoreKeysRequest):
    """List all keys in the encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.list_file_store_keys(
            context_file=request.context_file,
            store_name=request.store_name,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store/delete")
async def delete_key_value(request: DeleteKeyValueRequest):
    """Delete a key-value pair from the encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.delete_key_value(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# AES Encryption/Decryption endpoints
@app.post("/tpm2/encrypt-aes")
async def encrypt_data_aes(request: EncryptDataAESRequest):
    """Encrypt data using a loaded AES key"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.encrypt_data_aes(
            context_file=request.context_file,
            data=request.data,
            password=request.password,
            encrypted_file=request.encrypted_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/decrypt-aes")
async def decrypt_data_aes(request: DecryptDataAESRequest):
    """Decrypt data using a loaded AES key"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.decrypt_data_aes(
            context_file=request.context_file,
            encrypted_data=request.encrypted_data,
            password=request.password,
            decrypted_file=request.decrypted_file
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# AES Encrypted File Store endpoints
@app.post("/tpm2/file-store-aes/create")
async def create_file_store_aes(request: CreateFileStoreAESRequest):
    """Create a new AES encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.create_encrypted_file_store_aes(
            context_file=request.context_file,
            password=request.password,
            store_name=request.store_name
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store-aes/store")
async def store_key_value_aes(request: StoreKeyValueAESRequest):
    """Store a key-value pair in the AES encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.store_key_value_aes(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            value=request.value,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store-aes/retrieve")
async def retrieve_key_value_aes(request: RetrieveKeyValueAESRequest):
    """Retrieve a key-value pair from the AES encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.retrieve_key_value_aes(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store-aes/list-keys")
async def list_file_store_keys_aes(request: ListFileStoreKeysAESRequest):
    """List all keys in the AES encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.list_file_store_keys_aes(
            context_file=request.context_file,
            store_name=request.store_name,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tpm2/file-store-aes/delete")
async def delete_key_value_aes(request: DeleteKeyValueAESRequest):
    """Delete a key-value pair from the AES encrypted file store"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.delete_key_value_aes(
            context_file=request.context_file,
            store_name=request.store_name,
            key=request.key,
            password=request.password
        )
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# File upload endpoint for key files
@app.post("/tpm2/upload-key")
async def upload_key(
    public_file: UploadFile = File(...),
    private_file: UploadFile = File(...)
):
    """Upload public and private key files"""
    try:
        # Save uploaded files
        public_path = f"uploaded_{public_file.filename}"
        private_path = f"uploaded_{private_file.filename}"
        
        with open(public_path, "wb") as f:
            f.write(await public_file.read())
        
        with open(private_path, "wb") as f:
            f.write(await private_file.read())
        
        return {
            "success": True,
            "public_file": public_path,
            "private_file": private_path,
            "message": "Files uploaded successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tpm2/list-files")
async def list_files_get(directory: str = "."):
    """List files in the working directory (GET endpoint for easy testing)"""
    if tpm_api is None:
        return JSONResponse(
            content={"success": False, "error": "TPM2 API not available"},
            status_code=503
        )
    
    try:
        result = tpm_api.list_files(directory=directory)
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            return JSONResponse(
                content={"success": False, "error": result.get("error", "Unknown error")},
                status_code=400
            )
            
    except Exception as e:
        import traceback
        return JSONResponse(
            content={"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"},
            status_code=500
        )

@app.post("/tpm2/list-files")
async def list_files(request: ListFilesRequest = ListFilesRequest()):
    """List files in the working directory"""
    if tpm_api is None:
        return JSONResponse(
            content={"success": False, "error": "TPM2 API not available"},
            status_code=503
        )
    
    try:
        result = tpm_api.list_files(directory=request.directory)
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            # Return error in JSON format instead of raising HTTPException
            # This allows _make_request to parse the error properly
            return JSONResponse(
                content={"success": False, "error": result.get("error", "Unknown error")},
                status_code=400
            )
            
    except Exception as e:
        import traceback
        return JSONResponse(
            content={"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"},
            status_code=500
        )

@app.post("/tpm2/delete-file")
async def delete_file(request: DeleteFileRequest):
    """Delete a file from the working directory"""
    if tpm_api is None:
        raise HTTPException(status_code=503, detail="TPM2 API not available")
    
    try:
        result = tpm_api.delete_file(file_path=request.file_path)
        
        if result["success"]:
            return JSONResponse(content=result, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import sys
    
    # Get port from command line argument, environment variable, or default to 8000
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}. Using default port 8000.")
            port = 8000
    else:
        # Check environment variable if no command line argument
        port = int(os.environ.get("TPM2_API_PORT", "8000"))
    
    # Get host from environment variable, default to 0.0.0.0
    host = os.environ.get("TPM2_API_HOST", "0.0.0.0")
    
    print(f"Starting TPM2 REST API on {host}:{port}")
    print(f"Access the API at: http://localhost:{port}")
    print(f"Health check: http://localhost:{port}/health")
    
    # Run the FastAPI server
    uvicorn.run(
        "tpm2_rest_api:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    ) 



# 1. docker run command
#    ↓
# 2. entrypoint.sh starts
#    ↓
# 3. DBus starts
#    ↓
# 4. SWTPM starts (port 2321)
#    ↓
# 5. TPM2-ABRMD starts
#    ↓
# 6. Command line argument check
#    ↓
# 7. python3 /opt/tpm2_rest_api.py executes
#    ↓
# 8. uvicorn.run() starts FastAPI server
#    ↓
# 9. FastAPI listens on port 8000
