#!/usr/bin/env python3
"""
TPM2 Command Line Interface - Simple CLI wrapper for TPM2 operations
"""

import argparse
import json
import sys
from tpm2_api import TPM2API

def main():
    parser = argparse.ArgumentParser(description="TPM2 Command Line Interface")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Create primary key command
    primary_parser = subparsers.add_parser("create-primary", help="Create a primary key")
    primary_parser.add_argument("--hierarchy", default="o", help="TPM hierarchy (o/e/p)")
    primary_parser.add_argument("--output", "-o", default="primary.ctx", help="Output context file")
    primary_parser.add_argument("--password", default=None, help="Password for the primary key")
    
    # Create key command
    create_parser = subparsers.add_parser("create-key", help="Create a key under parent")
    create_parser.add_argument("--parent", "-p", required=True, help="Parent context file")
    create_parser.add_argument("--type", "-t", default="rsa", help="Key type (rsa/ecc)")
    create_parser.add_argument("--public", default="key.pub", help="Public key output file")
    create_parser.add_argument("--private", default="key.priv", help="Private key output file")
    create_parser.add_argument("--password", default=None, help="Password for the parent and created key")
    
    # Load key command
    load_parser = subparsers.add_parser("load-key", help="Load a key into TPM")
    load_parser.add_argument("--parent", "-p", required=True, help="Parent context file")
    load_parser.add_argument("--public", required=True, help="Public key file")
    load_parser.add_argument("--private", required=True, help="Private key file")
    load_parser.add_argument("--output", "-o", default="loaded_key.ctx", help="Output context file")
    load_parser.add_argument("--password", default=None, help="Password for the parent key")
    
    # Make persistent command
    persistent_parser = subparsers.add_parser("make-persistent", help="Make key persistent")
    persistent_parser.add_argument("--context", "-c", required=True, help="Key context file")
    persistent_parser.add_argument("--handle", default="0x81010001", help="Persistent handle")
    persistent_parser.add_argument("--password", default=None, help="Owner hierarchy password")
    
    # Flush context command
    flush_parser = subparsers.add_parser("flush-context", help="Flush TPM contexts")
    flush_parser.add_argument("--type", "-t", default="transient", 
                             choices=["transient", "loaded", "saved", "all"],
                             help="Context type to flush")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Get TPM information")
    
    # Workflow command
    workflow_parser = subparsers.add_parser("workflow", help="Execute complete workflow")
    workflow_parser.add_argument("--password", default=None, help="Password for the workflow keys")
    

    
    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    encrypt_parser.add_argument("--context", "-c", required=True, help="Key context file")
    encrypt_parser.add_argument("--data", "-d", required=True, help="Data to encrypt (base64 encoded)")
    encrypt_parser.add_argument("--output", "-o", default="encrypted.bin", help="Output encrypted file")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    decrypt_parser.add_argument("--context", "-c", required=True, help="Key context file")
    decrypt_parser.add_argument("--data", "-d", required=True, help="Encrypted data to decrypt (base64 encoded)")
    decrypt_parser.add_argument("--output", "-o", default="decrypted.bin", help="Output decrypted file")
    decrypt_parser.add_argument("--password", default=None, help="Password for the loaded key")
    
    # Full reset command
    reset_parser = subparsers.add_parser("full-reset", help="Perform complete TPM reset")
    reset_parser.add_argument("--password", default=None, help="Owner hierarchy password")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Initialize TPM2 API
        tpm = TPM2API()
        
        if args.command == "create-primary":
            result = tpm.create_primary_key(
                password=args.password,
                hierarchy=args.hierarchy,
                context_file=args.output,
            )
            
        elif args.command == "create-key":
            result = tpm.create_key(
                parent_context=args.parent,
                password=args.password,
                key_type=args.type,
                public_file=args.public,
                private_file=args.private
            )
            
        elif args.command == "load-key":
            result = tpm.load_key(
                parent_context=args.parent,
                public_file=args.public,
                private_file=args.private,
                password=args.password,
                context_file=args.output
            )
            
        elif args.command == "make-persistent":
            handle = int(args.handle, 16) if args.handle.startswith("0x") else int(args.handle)
            result = tpm.make_persistent(
                context_file=args.context,
                password=args.password,
                persistent_handle=handle
            )
            
        elif args.command == "flush-context":
            result = tpm.flush_context(context_type=args.type)
            
        elif args.command == "info":
            result = tpm.get_tpm_info()
            
        elif args.command == "workflow":
            print("Executing complete TPM2 workflow...")
            
            # Step 1: Create primary key
            print("1. Creating primary key...")
            result = tpm.create_primary_key(password=args.password)
            if not result["success"]:
                print(f"Error: {result['error']}")
                sys.exit(1)
            print(f"✓ Primary key created: {result['context_file']}")
            
            # Step 2: Create RSA key
            print("2. Creating RSA key...")
            result = tpm.create_key("primary.ctx", args.password, "rsa", "rsa.pub", "rsa.priv")
            if not result["success"]:
                print(f"Error: {result['error']}")
                sys.exit(1)
            print(f"✓ RSA key created: {result['public_file']}, {result['private_file']}")
            
            # Step 3: Load key
            print("3. Loading key...")
            result = tpm.load_key("primary.ctx", "rsa.pub", "rsa.priv", args.password,"rsa.ctx")
            if not result["success"]:
                print(f"Error: {result['error']}")
                sys.exit(1)
            print(f"✓ Key loaded: {result['context_file']}")
            
            # Step 4: Make persistent
            print("4. Making key persistent...")
            result = tpm.make_persistent("rsa.ctx", args.password)
            if not result["success"]:
                print(f"Error: {result['error']}")
                sys.exit(1)
            print(f"✓ Key made persistent: {result['persistent_handle']}")
            
            print("\n🎉 Complete workflow executed successfully!")
            print("Generated files:")
            print("  - primary.ctx (primary key context)")
            print("  - rsa.pub (public key)")
            print("  - rsa.priv (private key)")
            print("  - rsa.ctx (loaded key context)")
            print(f"  - Persistent handle: {result['persistent_handle']}")
            sys.exit(0)
            

            
        elif args.command == "encrypt":
            result = tpm.encrypt_data(
                context_file=args.context,
                data=args.data,
                encrypted_file=args.output
            )
            
        elif args.command == "decrypt":
            result = tpm.decrypt_data(
                context_file=args.context,
                encrypted_data=args.data,
                password=args.password,
                decrypted_file=args.output
            )
            
        elif args.command == "full-reset":
            print("⚠️  WARNING: This will perform a complete TPM reset!")
            print("   - All persistent keys will be removed")
            print("   - All contexts will be cleared")
            print("   - All authorizations will be reset")
            print("   - This action cannot be undone!")
            
            confirm = input("Are you sure you want to continue? (yes/no): ")
            if confirm.lower() != "yes":
                print("Reset cancelled.")
                sys.exit(0)
            
            result = tpm.full_reset(args.password)
        
        # Print result
        if result["success"]:
            print(json.dumps(result, indent=2))
            sys.exit(0)
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 
