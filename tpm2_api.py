#!/usr/bin/env python3
"""
TPM2 Python API - A simple interface for TPM2 operations using system calls
"""

import os
import json
import base64
import ctypes
import ctypes.util
import ssl
import subprocess
import tempfile
from typing import Dict, List, Optional, Any

TEMP_DECRYPTED_AES_FILE = "temp_decrypted_aes.json"
TPM2_RSA_SCHEMES = {"rsassa", "rsapss"}
TPM2_HASH_ALGORITHMS = {"sha256", "sha384", "sha512"}
TPM2_INPUT_KINDS = {"message", "digest"}
TPM2_SIGNATURE_ALG_IDS = {
    "rsassa": b"\x00\x14",
    "rsapss": b"\x00\x16",
}
TPM2_HASH_ALG_IDS = {
    "sha256": b"\x00\x0b",
    "sha384": b"\x00\x0c",
    "sha512": b"\x00\x0d",
}

def ensure_starts_with_newline(s: str) -> str:
    """
    Ensure the string starts with a newline character.
    If it already starts with '\n', return as-is; otherwise, prepend '\n'.
    """
    if s.startswith("\n"):
        return s
    return "\n" + s


def base64_to_pem_public_key(public_key_b64: str) -> str:
    """
    Convert a base64-encoded public key to PEM format with headers.
    This is useful when you have a base64 public key and need to load it
    with load_pem_public_key() from the cryptography library.
    
    Args:
        public_key_b64: Base64-encoded public key (without PEM headers)
        
    Returns:
        PEM-formatted public key string with headers
    """
    pem_lines = ["-----BEGIN PUBLIC KEY-----"]
    # Split base64 into 64-character lines
    for i in range(0, len(public_key_b64), 64):
        pem_lines.append(public_key_b64[i:i+64])
    pem_lines.append("-----END PUBLIC KEY-----")
    return "\n".join(pem_lines)


class TPM2API:
    """
    Python API for TPM2 operations using tpm2 command-line tools
    
    Supports both software TPM (SWTPM) and hardware TPM devices.
    The TCTI (TPM Command Transmission Interface) can be configured via:
    - Constructor parameter: tcti_name
    - Environment variable: TPM2_TCTI (takes precedence)
    - Auto-detection: If no TCTI is specified, will try hardware TPM first, then SWTPM
    """
    
    @staticmethod
    def _detect_hardware_tpm() -> Optional[str]:
        """
        Detect if a hardware TPM is available and return appropriate TCTI
        
        Returns:
            TCTI string if hardware TPM detected, None otherwise
        """
        # Check for TPM Resource Manager device (preferred, doesn't require root)
        if os.path.exists("/dev/tpmrm0"):
            return "device:/dev/tpmrm0"
        
        # Check for direct TPM device (requires root or tss group membership)
        if os.path.exists("/dev/tpm0"):
            return "device:/dev/tpm0"
        
        # Check if tabrmd daemon is available (recommended for production)
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tpm2-abrmd"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                return "tabrmd:"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        
        return None
    
    @staticmethod
    def _get_tcti_from_env() -> Optional[str]:
        """Get TCTI configuration from environment variable"""
        return os.environ.get("TPM2_TCTI") or os.environ.get("TSS2_TCTI") or os.environ.get("TPM2TOOLS_TCTI")
    
    def __init__(self, tcti_name: Optional[str] = None, skip_connection_test: bool = False):
        """
        Initialize TPM2 API
        
        Args:
            tcti_name: TCTI configuration. If None, will:
                      1. Check TPM2_TCTI environment variable
                      2. Try to auto-detect hardware TPM
                      3. Fall back to SWTPM default (swtpm:host=127.0.0.1,port=2321)
        
        Examples:
            # Use hardware TPM (auto-detected)
            tpm = TPM2API()
            
            # Use specific hardware TPM device
            tpm = TPM2API("device:/dev/tpmrm0")
            
            # Use tabrmd daemon
            tpm = TPM2API("tabrmd:")
            
            # Use SWTPM
            tpm = TPM2API("swtpm:host=127.0.0.1,port=2321")

            # Use OpenSSL TPM provider support without probing tpm2-tools
            tpm = TPM2API(skip_connection_test=True)
        """
        # Priority: explicit parameter > environment variable > auto-detect > default
        if tcti_name is not None:
            self.tcti_name = tcti_name
        else:
            env_tcti = self._get_tcti_from_env()
            if env_tcti:
                self.tcti_name = env_tcti
                print(f"Using TCTI from environment: {self.tcti_name}")
            else:
                # Try to auto-detect hardware TPM
                hw_tpm = self._detect_hardware_tpm()
                if hw_tpm:
                    self.tcti_name = hw_tpm
                    print(f"Auto-detected hardware TPM: {self.tcti_name}")
                else:
                    self.tcti_name = "swtpm:host=127.0.0.1,port=2321"
                    print(f"No hardware TPM detected, using SWTPM default: {self.tcti_name}")
        
        self._set_environment()
        self._openssl_provider_handles: List[int] = []
        self.skip_connection_test = skip_connection_test
        if not self.skip_connection_test:
            self._test_connection()

    @classmethod
    def for_ssl(cls, tcti_name: Optional[str] = None) -> "TPM2API":
        """
        Create a TPM2API instance for OpenSSL-provider-backed TLS operations.

        This mode skips the `tpm2_getcap` startup probe so it can be used on
        systems that have `tpm2-openssl` available but do not have the
        `tpm2-tools` CLI installed.
        """
        return cls(tcti_name=tcti_name, skip_connection_test=True)
    
    def _set_environment(self):
        """Set environment variables for TPM2 tools"""
        os.environ['TSS2_TCTI'] = self.tcti_name
        os.environ['TPM2TOOLS_TCTI'] = self.tcti_name
        print(f"Set TPM2 environment: TSS2_TCTI={self.tcti_name}")
    
    def _test_connection(self):
        """Test TPM2 connection"""
        try:
            result = self._run_command(['tpm2_getcap', 'properties-fixed'])
            if result['success']:
                print("TPM2 connection successful")
            else:
                raise Exception(f"TPM2 connection failed: {result['error']}")
        except Exception as e:
            raise Exception(f"Failed to connect to TPM: {e}")

    def _cleanup_temp_decrypted_file(self) -> None:
        """Remove the temporary decrypted AES file if it exists."""
        if os.path.exists(TEMP_DECRYPTED_AES_FILE):
            try:
                os.unlink(TEMP_DECRYPTED_AES_FILE)
            except OSError:
                pass
    
    def _run_command(self, cmd: List[str], input_data: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a TPM2 command and return the result
        
        Args:
            cmd: Command list to execute
            input_data: Optional input data for the command
            
        Returns:
            Dictionary with success status and output/error
        """
        try:
            # Add TCTI to command if not already present
            if '--tcti' not in ' '.join(cmd):
                cmd.extend(['--tcti', self.tcti_name])
            
            print(f"Running command: {' '.join(cmd)}")
            
            # Set environment variables for the subprocess
            env = os.environ.copy()
            env['TSS2_TCTI'] = self.tcti_name
            env['TPM2TOOLS_TCTI'] = self.tcti_name
            
            # Run the command
            if input_data:
                result = subprocess.run(
                    cmd,
                    input=input_data.encode(),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr.strip() or result.stdout.strip(),
                    "returncode": result.returncode
                }
                
        except FileNotFoundError:
            return {
                "success": False,
                "error": (
                    f"Command not found: {cmd[0]}. Install tpm2-tools and ensure it is on PATH."
                )
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_external_command(self, cmd: List[str], input_data: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a non-tpm2 command while preserving TPM-related environment variables.

        This is used for tools like OpenSSL TPM providers that need access to the
        same TPM connection but do not accept the tpm2-tools `--tcti` flag.

        Args:
            cmd: Command list to execute
            input_data: Optional input data for the command

        Returns:
            Dictionary with success status and output/error
        """
        try:
            print(f"Running command: {' '.join(cmd)}")

            env = os.environ.copy()
            env['TSS2_TCTI'] = self.tcti_name
            env['TPM2TOOLS_TCTI'] = self.tcti_name
            env.setdefault('TPM2OPENSSL_TCTI', self.tcti_name)

            if input_data:
                result = subprocess.run(
                    cmd,
                    input=input_data,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )

            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }

            return {
                "success": False,
                "error": result.stderr.strip() or result.stdout.strip(),
                "returncode": result.returncode
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _candidate_openssl_modules_dirs() -> List[str]:
        """
        Return likely OpenSSL provider module directories.

        These are only fallbacks. The safest path is still to pass modules_path
        explicitly when Python's OpenSSL is not using the same installation as
        the shell `openssl` command.
        """
        candidates: List[str] = []

        env_path = os.environ.get("OPENSSL_MODULES")
        if env_path:
            candidates.append(env_path)

        try:
            result = subprocess.run(
                ["openssl", "version", "-a"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "MODULESDIR:" in line:
                        modules_dir = line.split("MODULESDIR:", 1)[1].strip().strip('"')
                        if modules_dir:
                            candidates.append(modules_dir)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        candidates.extend([
            "/opt/homebrew/lib/ossl-modules",
            "/usr/local/lib/ossl-modules",
            "/usr/lib/ossl-modules",
            "/usr/lib64/ossl-modules",
        ])
        return candidates

    @classmethod
    def resolve_openssl_modules_path(cls, modules_path: Optional[str] = None) -> str:
        """
        Resolve a usable OpenSSL provider modules directory.

        Args:
            modules_path: Optional explicit modules directory

        Returns:
            Existing filesystem path to OpenSSL provider modules

        Raises:
            FileNotFoundError if no usable directory is found
        """
        if modules_path:
            if os.path.isdir(modules_path):
                return modules_path
            raise FileNotFoundError(f"OpenSSL modules directory not found: {modules_path}")

        for candidate in cls._candidate_openssl_modules_dirs():
            if candidate and os.path.isdir(candidate):
                return candidate

        searched = ", ".join(cls._candidate_openssl_modules_dirs())
        raise FileNotFoundError(
            "Could not locate an OpenSSL provider modules directory. "
            f"Set OPENSSL_MODULES or pass modules_path explicitly. Searched: {searched}"
        )

    def initialize_openssl_tls_support(
        self,
        modules_path: Optional[str] = None,
        tcti_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Programmatically load the OpenSSL `default` and `tpm2` providers.

        This avoids requiring an openssl.cnf file before calling
        `ssl.SSLContext.load_cert_chain()` with a TPM-backed `TSS2 PRIVATE KEY`.

        Args:
            modules_path: Directory containing OpenSSL provider modules
            tcti_name: Optional TCTI override for provider-backed OpenSSL calls

        Returns:
            Dictionary describing the loaded providers and runtime details
        """
        try:
            if tcti_name:
                self.tcti_name = tcti_name
                self._set_environment()

            resolved_modules_path = self.resolve_openssl_modules_path(modules_path)
            os.environ["OPENSSL_MODULES"] = resolved_modules_path
            os.environ.setdefault("TPM2OPENSSL_TCTI", self.tcti_name)

            libcrypto_path = ctypes.util.find_library("crypto")
            if not libcrypto_path:
                return {"success": False, "error": "Unable to locate libcrypto for provider initialization"}

            libcrypto = ctypes.CDLL(libcrypto_path, mode=ctypes.RTLD_GLOBAL)

            libcrypto.OSSL_PROVIDER_set_default_search_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            libcrypto.OSSL_PROVIDER_set_default_search_path.restype = ctypes.c_int
            libcrypto.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            libcrypto.OSSL_PROVIDER_load.restype = ctypes.c_void_p
            libcrypto.OpenSSL_version.argtypes = [ctypes.c_int]
            libcrypto.OpenSSL_version.restype = ctypes.c_char_p

            if libcrypto.OSSL_PROVIDER_set_default_search_path(None, resolved_modules_path.encode("utf-8")) != 1:
                return {
                    "success": False,
                    "error": f"Failed to set OpenSSL provider search path to {resolved_modules_path}"
                }

            default_provider = libcrypto.OSSL_PROVIDER_load(None, b"default")
            if not default_provider:
                return {"success": False, "error": "Failed to load OpenSSL default provider"}

            tpm2_provider = libcrypto.OSSL_PROVIDER_load(None, b"tpm2")
            if not tpm2_provider:
                return {
                    "success": False,
                    "error": (
                        "Failed to load OpenSSL tpm2 provider. "
                        "Ensure tpm2-openssl is installed and the provider modules path matches "
                        "the OpenSSL build used by Python."
                    )
                }

            # Retain handles for the life of this object so the providers remain loaded.
            self._openssl_provider_handles = [default_provider, tpm2_provider]

            openssl_runtime = libcrypto.OpenSSL_version(0)
            openssl_runtime_text = openssl_runtime.decode("utf-8") if openssl_runtime else "unknown"

            return {
                "success": True,
                "providers": ["default", "tpm2"],
                "modules_path": resolved_modules_path,
                "tcti_name": self.tcti_name,
                "python_ssl_openssl_version": ssl.OPENSSL_VERSION,
                "libcrypto_version": openssl_runtime_text,
                "action": "openssl_tls_support_initialized",
            }
        except AttributeError as e:
            return {
                "success": False,
                "error": (
                    "This OpenSSL build does not expose the provider APIs required for "
                    f"programmatic TPM provider loading: {e}"
                )
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_ssl_context(
        self,
        certfile: str,
        keyfile: str,
        password: Optional[str] = None,
        modules_path: Optional[str] = None,
        purpose: str = "server",
        cafile: Optional[str] = None,
    ) -> ssl.SSLContext:
        """
        Create an SSLContext that can consume a TPM-backed OpenSSL key file.

        Args:
            certfile: PEM certificate file matching the TPM-backed key
            keyfile: TPM-backed `TSS2 PRIVATE KEY` file
            password: Optional passphrase protecting the key reference file
            modules_path: Optional OpenSSL provider modules directory
            purpose: 'server' or 'client'
            cafile: Optional CA bundle for client mode

        Returns:
            Configured ssl.SSLContext instance
        """
        init_result = self.initialize_openssl_tls_support(modules_path=modules_path)
        if not init_result["success"]:
            raise RuntimeError(init_result["error"])

        normalized_purpose = purpose.lower()
        if normalized_purpose == "server":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=password)
        elif normalized_purpose == "client":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if cafile:
                context.load_verify_locations(cafile=cafile)
            else:
                context.load_default_certs()
        else:
            raise ValueError("purpose must be 'server' or 'client'")

        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    
    def create_primary_key(self, password: str, hierarchy: str = "o", context_file: str = "primary.ctx",
                          key_size: int = 1024) -> Dict[str, Any]:
        """
        Create a primary key in the specified hierarchy
        
        Args:
            hierarchy: TPM hierarchy ('o' for owner, 'e' for endorsement, 'p' for platform)
            context_file: File to save the primary key context
            key_size: RSA key size in bits (1024 or 2048, default: 1024 to match AnyLog)
            
        Returns:
            Dictionary with key information
        """
        try:
            # Validate key size
            if key_size not in [1024, 2048]:
                return {"success": False, "error": f"Unsupported key size: {key_size}. Use 1024 or 2048"}
            
            key_alg = f"rsa{key_size}"
            cmd = [
                'tpm2_createprimary',
                '-C', hierarchy,
                '-c', context_file,
                '-G', key_alg,
                '-g', 'sha256',
                '-p', password
            ]
            
            result = self._run_command(cmd)
            
            if result['success']:
                # Parse the output to get key information
                output_lines = result['output'].split('\n')
                key_info = {}
                
                for line in output_lines:
                    if 'name:' in line:
                        key_info['name'] = line.split('name:')[1].strip()
                    elif 'qualified name:' in line:
                        key_info['qualified_name'] = line.split('qualified name:')[1].strip()
                
                return {
                    "success": True,
                    "context_file": context_file,
                    "hierarchy": hierarchy,
                    "key_info": key_info,
                    "action": "primary_key_created"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_openssl_tls_key(self, private_key_file: str = "server-tpm-key.pem",
                               public_key_file: Optional[str] = None, key_type: str = "rsa",
                               key_size: int = 2048, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a TPM-backed OpenSSL key reference file for TLS use.

        This method uses the OpenSSL TPM provider to generate a `TSS2 PRIVATE KEY`
        file that can later be used by OpenSSL-aware TLS stacks. The actual private
        key remains in the TPM; the output file is an OpenSSL-readable reference.

        Args:
            private_key_file: Output file for the TPM-backed TSS2 private key
            public_key_file: Optional output file for the PEM public key
            key_type: Supported values are 'rsa' and 'ecc'
            key_size: RSA key size in bits (2048 or 3072 recommended)
            password: Optional passphrase used to encrypt the generated key reference file

        Returns:
            Dictionary with result information
        """
        try:
            normalized_key_type = key_type.lower()
            if normalized_key_type == "rsa":
                if key_size not in [1024, 2048, 3072, 4096]:
                    return {
                        "success": False,
                        "error": f"Unsupported RSA key size: {key_size}. Use 1024, 2048, 3072, or 4096"
                    }
                algorithm = "RSA"
                pkeyopt = f"rsa_keygen_bits:{key_size}"
            elif normalized_key_type == "ecc":
                algorithm = "EC"
                pkeyopt = "ec_paramgen_curve:prime256v1"
            else:
                return {"success": False, "error": f"Unsupported key type: {key_type}. Use 'rsa' or 'ecc'"}

            if public_key_file is None:
                base_name, _ = os.path.splitext(private_key_file)
                public_key_file = f"{base_name}.pub.pem"

            gen_cmd = [
                'openssl',
                'genpkey',
                '-provider', 'tpm2',
                '-provider', 'default',
                '-algorithm', algorithm,
                '-pkeyopt', pkeyopt,
                '-out', private_key_file
            ]
            if password:
                gen_cmd.extend(['-aes-256-cbc', '-pass', f'pass:{password}'])

            gen_result = self._run_external_command(gen_cmd)
            if not gen_result["success"]:
                return {
                    "success": False,
                    "error": gen_result["error"],
                    "action": "openssl_tls_key_generation_failed"
                }

            pub_cmd = [
                'openssl',
                'pkey',
                '-provider', 'tpm2',
                '-provider', 'default',
                '-in', private_key_file,
                '-pubout',
                '-out', public_key_file
            ]
            if password:
                pub_cmd.extend(['-passin', f'pass:{password}'])

            pub_result = self._run_external_command(pub_cmd)
            if not pub_result["success"]:
                return {
                    "success": False,
                    "error": pub_result["error"],
                    "private_key_file": private_key_file,
                    "action": "openssl_tls_public_key_export_failed"
                }

            return {
                "success": True,
                "private_key_file": private_key_file,
                "public_key_file": public_key_file,
                "key_type": normalized_key_type,
                "key_size": key_size if normalized_key_type == "rsa" else None,
                "password_protected": bool(password),
                "action": "openssl_tls_key_created"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_self_signed_certificate(
        self,
        private_key_file: str,
        cert_file: str = "server-cert.pem",
        subject: str = "/CN=localhost",
        days: int = 365,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a self-signed certificate using a TPM-backed OpenSSL key reference.

        Args:
            private_key_file: TPM-backed OpenSSL private key reference file
            cert_file: Output certificate file
            subject: OpenSSL subject string, e.g. /CN=localhost
            days: Validity period
            password: Optional passphrase protecting the key reference file

        Returns:
            Dictionary with certificate generation result
        """
        try:
            cmd = [
                "openssl",
                "req",
                "-provider", "tpm2",
                "-provider", "default",
                "-key", private_key_file,
                "-new",
                "-x509",
                "-sha256",
                "-days", str(days),
                "-subj", subject,
                "-out", cert_file,
            ]
            if password:
                cmd.extend(["-passin", f"pass:{password}"])

            result = self._run_external_command(cmd)
            if not result["success"]:
                return {
                    "success": False,
                    "error": result["error"],
                    "action": "openssl_tls_self_signed_certificate_failed",
                }

            return {
                "success": True,
                "private_key_file": private_key_file,
                "cert_file": cert_file,
                "subject": subject,
                "days": days,
                "action": "openssl_tls_self_signed_certificate_created",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_openssl_tls_public_key(self, public_key_file: str) -> Dict[str, Any]:
        """
        Read the PEM public key generated alongside a TPM-backed OpenSSL TLS key.

        Args:
            public_key_file: Path to the PEM public key file

        Returns:
            Dictionary with PEM text and header-stripped base64 contents
        """
        try:
            if not os.path.exists(public_key_file):
                return {"success": False, "error": f"Public key file not found: {public_key_file}"}

            with open(public_key_file, "r", encoding="utf-8") as f:
                public_key_text = f.read().strip()

            if not public_key_text:
                return {"success": False, "error": f"Public key file is empty: {public_key_file}"}

            body_lines = []
            for line in public_key_text.splitlines():
                normalized = line.strip()
                if normalized and not normalized.startswith("-----BEGIN") and not normalized.startswith("-----END"):
                    body_lines.append(normalized)

            public_key_b64 = "".join(body_lines)

            return {
                "success": True,
                "public_key_file": public_key_file,
                "public_key_text": public_key_text,
                "public_key": public_key_b64,
                "format": "pem",
                "action": "openssl_tls_public_key_retrieved",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def sign_with_openssl_tls_key(
        self,
        private_key_file: str,
        data: str,
        password: Optional[str] = None,
        scheme: str = "rsassa",
        hash_alg: str = "sha256",
        input_kind: str = "message",
    ) -> Dict[str, Any]:
        """
        Sign data using a TPM-backed OpenSSL TLS key reference file.

        Args:
            private_key_file: Path to the TPM-backed OpenSSL private key reference file
            data: Base64 encoded input data
            password: Optional passphrase protecting the key reference file
            scheme: RSA signing scheme ("rsassa" or "rsapss")
            hash_alg: Hash algorithm to use
            input_kind: Currently supports "message" only

        Returns:
            Dictionary containing a hex-encoded signature
        """
        try:
            scheme = (scheme or "rsassa").lower()
            hash_alg = (hash_alg or "sha256").lower()
            input_kind = (input_kind or "message").lower()

            if scheme not in TPM2_RSA_SCHEMES:
                return {"success": False, "error": f"Unsupported signing scheme: {scheme}. Use one of {sorted(TPM2_RSA_SCHEMES)}"}

            if hash_alg not in TPM2_HASH_ALGORITHMS:
                return {"success": False, "error": f"Unsupported hash algorithm: {hash_alg}. Use one of {sorted(TPM2_HASH_ALGORITHMS)}"}

            if input_kind != "message":
                return {"success": False, "error": "OpenSSL TLS key signing currently supports input_kind='message' only"}

            decoded_data = base64.b64decode(data)

            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_data_file:
                temp_data_file.write(decoded_data)
                temp_data_path = temp_data_file.name

            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_sig_file:
                temp_sig_path = temp_sig_file.name

            try:
                cmd = [
                    'openssl',
                    'dgst',
                    f'-{hash_alg}',
                    '-provider', 'tpm2',
                    '-provider', 'default',
                    '-sign', private_key_file,
                    '-out', temp_sig_path,
                ]

                if scheme == "rsapss":
                    cmd.extend([
                        '-sigopt', 'rsa_padding_mode:pss',
                        '-sigopt', 'rsa_pss_saltlen:-1',
                    ])
                else:
                    cmd.extend(['-sigopt', 'rsa_padding_mode:pkcs1'])

                if password:
                    cmd.extend(['-passin', f'pass:{password}'])

                cmd.append(temp_data_path)

                result = self._run_external_command(cmd)
                if not result["success"]:
                    return {
                        "success": False,
                        "error": result["error"],
                        "action": "openssl_tls_sign_failed"
                    }

                with open(temp_sig_path, 'rb') as f:
                    signature_bytes = f.read()

                return {
                    "success": True,
                    "private_key_file": private_key_file,
                    "signature": signature_bytes.hex(),
                    "signature_format": "hex",
                    "scheme": scheme,
                    "hash_alg": hash_alg,
                    "input_kind": input_kind,
                    "action": "openssl_tls_data_signed",
                }
            finally:
                try:
                    os.unlink(temp_data_path)
                except OSError:
                    pass
                try:
                    os.unlink(temp_sig_path)
                except OSError:
                    pass
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_key(self, parent_context: str, password: str, key_type: str = "rsa",
                   public_file: str = "key.pub", private_file: str = "key.priv",
                   key_size: int = 1024) -> Dict[str, Any]:
        """
        Create a key under the specified parent
        
        Args:
            parent_context: Parent key context file
            key_type: Type of key ('rsa', 'ecc', 'aes128', 'aes256')
            public_file: File to save the public key (for RSA/ECC) or key context (for AES)
            private_file: File to save the private key (for RSA/ECC) or not used (for AES)
            key_size: RSA key size in bits (1024 or 2048, default: 1024 to match AnyLog)
                      Only used when key_type is 'rsa'
            
        Returns:
            Dictionary with key information
        """
        try:
            # For AES keys, prepare filenames before command creation
            aes_pub_file = None
            aes_priv_file = None
            if key_type.lower() in ["aes128", "aes256"]:
                # Generate appropriate filenames from the context file name
                if public_file.endswith('.ctx'):
                    aes_pub_file = public_file.replace('.ctx', '.pub')
                    aes_priv_file = public_file.replace('.ctx', '.priv')
                else:
                    aes_pub_file = public_file + '.pub'
                    aes_priv_file = (private_file if private_file != "key.priv" else public_file + '.priv')
            
            if key_type.lower() == "rsa":
                # Validate key size
                if key_size not in [1024, 2048]:
                    return {"success": False, "error": f"Unsupported RSA key size: {key_size}. Use 1024 or 2048"}
                key_alg = f"rsa{key_size}"
                cmd = [
                    'tpm2_create',
                    '-C', parent_context,
                    '-P', password,
                    '-G', key_alg,
                    '-u', public_file,
                    '-r', private_file,
                    '-p', password
                ]
            elif key_type.lower() == "ecc":
                key_alg = "ecc256"
                cmd = [
                    'tpm2_create',
                    '-C', parent_context,
                    '-P', password,
                    '-G', key_alg,
                    '-u', public_file,
                    '-r', private_file,
                    '-p', password
                ]
            elif key_type.lower() in ["aes128", "aes256"]:
                # For AES keys, we use tpm2_create to create a symmetric key with proper attributes
                # This ensures the key can be used with tpm2_encryptdecrypt
                key_size = "128" if key_type.lower() == "aes128" else "256"
                # Create the AES key as a child key (not primary) with proper attributes
                # We need to create public/private key files, then load it
                cmd = [
                    'tpm2_create',
                    '-C', parent_context,
                    '-P', password,
                    '-G', f'aes{key_size}',
                    '-u', aes_pub_file,  # Public portion
                    '-r', aes_priv_file, # Private portion
                    '-p', password
                ]
            else:
                return {"success": False, "error": f"Unsupported key type: {key_type}"}
            
            result = self._run_command(cmd)
            
            if result['success']:
                if key_type.lower().startswith("aes"):
                    # For AES keys, we need to load them after creation to get a context file
                    # Ensure context file ends with .ctx
                    context_file = public_file if public_file.endswith('.ctx') else public_file + '.ctx'
                    
                    # Load the AES key to create a context file
                    load_result = self.load_key(
                        parent_context,
                        aes_pub_file,
                        aes_priv_file,
                        password,
                        context_file
                    )
                    
                    if load_result['success']:
                        # Collect recovery material so clients can securely back up the AES key blobs
                        recovery_material = {}
                        try:
                            with open(aes_pub_file, 'rb') as f:
                                recovery_material['public_blob_b64'] = base64.b64encode(f.read()).decode()
                        except Exception as e:
                            recovery_material['public_blob_error'] = str(e)
                        
                        try:
                            with open(aes_priv_file, 'rb') as f:
                                recovery_material['private_blob_b64'] = base64.b64encode(f.read()).decode()
                        except Exception as e:
                            recovery_material['private_blob_error'] = str(e)
                        
                        if recovery_material:
                            recovery_material.update({
                                "public_file": aes_pub_file,
                                "private_file": aes_priv_file
                            })
                        
                        return {
                            "success": True,
                            "context_file": context_file,  # Context file for AES key
                            "public_file": aes_pub_file,
                            "private_file": aes_priv_file,
                            "key_type": key_type,
                            "parent_context": parent_context,
                            "action": "aes_key_created",
                            "recovery_material": recovery_material
                        }
                    else:
                        # Return the creation success but note load failed
                        return {
                            "success": True,
                            "public_file": aes_pub_file,
                            "private_file": aes_priv_file,
                            "context_file": None,
                            "warning": f"AES key created but failed to load: {load_result.get('error', 'Unknown error')}",
                            "key_type": key_type,
                            "parent_context": parent_context,
                            "action": "aes_key_created_not_loaded"
                        }
                else:
                    return {
                        "success": True,
                        "public_file": public_file,
                        "private_file": private_file,
                        "key_type": key_type,
                        "parent_context": parent_context,
                        "action": "key_created"
                    }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def load_key(self, parent_context: str, public_file: str, private_file: str, password: str,
                 context_file: str = "loaded_key.ctx") -> Dict[str, Any]:
        """
        Load a key into TPM context
        
        Args:
            parent_context: Parent key context file
            public_file: Public key file
            private_file: Private key file
            context_file: File to save the loaded key context
            
        Returns:
            Dictionary with result
        """
        try:
            cmd = [
                'tpm2_load',
                '-C', parent_context,
                '-P', password,
                '-u', public_file,
                '-r', private_file,
                '-c', context_file
            ]
            
            result = self._run_command(cmd)
            
            if result['success']:
                return {
                    "success": True,
                    "context_file": context_file,
                    "parent_context": parent_context,
                    "action": "key_loaded"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def import_key(self, parent_context: str, key_type: str, private_key_file: str, password: str,
                   public_file: str = "imported_key.pub", private_file: str = "imported_key.priv") -> Dict[str, Any]:
        """
        Import an externally generated key into TPM format
        
        Args:
            parent_context: Parent key context file
            key_type: Type of key ('rsa', 'ecc')
            private_key_file: File containing the external private key (PEM format)
            public_file: File to save the TPM-formatted public key
            private_file: File to save the TPM-formatted private key
            
        Returns:
            Dictionary with result
        """
        try:
            if key_type.lower() == "rsa":
                key_alg = "rsa2048"
            elif key_type.lower() == "ecc":
                key_alg = "ecc256"
            else:
                return {"success": False, "error": f"Unsupported key type for import: {key_type}"}
            
            cmd = [
                'tpm2_import',
                '-C', parent_context,
                '-P', password,
                '-G', key_alg,
                '-i', private_key_file,
                '-u', public_file,
                '-r', private_file,
                '-p', password
            ]
            
            result = self._run_command(cmd)
            
            if result['success']:
                return {
                    "success": True,
                    "public_file": public_file,
                    "private_file": private_file,
                    "key_type": key_type,
                    "parent_context": parent_context,
                    "action": "key_imported"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def make_persistent(self, context_file: str, password: str, persistent_handle: int = 0x81010001) -> Dict[str, Any]:
        """
        Make a key persistent in TPM
        
        Args:
            context_file: Key context file
            persistent_handle: Persistent handle to use
            
        Returns:
            Dictionary with result
        """
        try:
            cmd = [
                'tpm2_evictcontrol',
                '-C', 'o',
                '-P', password,
                '-c', context_file,
                str(persistent_handle)
            ]
            
            result = self._run_command(cmd)
            
            if result['success']:
                return {
                    "success": True,
                    "persistent_handle": hex(persistent_handle),
                    "context_file": context_file,
                    "action": "key_persisted"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def flush_context(self, context_type: str = "transient") -> Dict[str, Any]:
        """
        Flush TPM contexts
        
        Args:
            context_type: Type of contexts to flush ('transient', 'loaded', 'saved', 'all')
            
        Returns:
            Dictionary with result
        """
        try:
            if context_type == "transient":
                cmd = ['tpm2_flushcontext', '-t']
            elif context_type == "loaded":
                cmd = ['tpm2_flushcontext', '-l']
            elif context_type == "saved":
                cmd = ['tpm2_flushcontext', '-s']
            elif context_type == "all":
                cmd = ['tpm2_flushcontext', '-t', '-l', '-s']
            else:
                return {"success": False, "error": f"Invalid context type: {context_type}"}
            result = self._run_command(cmd)
            
            if result['success']:
                return {
                    "success": True,
                    "flushed_type": context_type,
                    "action": "contexts_flushed"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_tpm_info(self) -> Dict[str, Any]:
        """
        Get TPM information
        
        Returns:
            Dictionary with TPM information
        """
        try:
            # Get TPM properties
            result = self._run_command(['tpm2_getcap', 'properties-fixed'])
            
            if result['success']:
                # Parse properties
                properties = {}
                for line in result['output'].split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        properties[key.strip()] = value.strip()
                
                return {
                    "success": True,
                    "tcti": self.tcti_name,
                    "properties": properties,
                    "action": "tpm_info_retrieved"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def sign_data(
        self,
        context_file: str,
        data: str,
        password: str,
        signature_file: str = "signature.sig",
        output_format: str = "hex",
        scheme: str = "rsapss",
        hash_alg: str = "sha256",
        input_kind: str = "message",
    ) -> Dict[str, Any]:
        """
        Sign data using a loaded key
        
        Args:
            context_file: Key context file
            data: Data to sign (base64 encoded)
            signature_file: File to save the signature
            output_format: Output format for signature - "hex" (like regular keys) or "base64" (TPM format)
                          Default: "hex" to match regular key signature format
            scheme: TPM signing scheme (default: "rsapss" to preserve current behavior)
            hash_alg: TPM hash algorithm (default: "sha256" to preserve current behavior)
            input_kind: Whether data is a "message" or precomputed "digest"
            
        Returns:
            Dictionary with result containing signature in the requested format
        """
        try:
            scheme = (scheme or "rsapss").lower()
            hash_alg = (hash_alg or "sha256").lower()
            input_kind = (input_kind or "message").lower()
            output_format = (output_format or "hex").lower()

            if scheme not in TPM2_RSA_SCHEMES:
                return {"success": False, "error": f"Unsupported signing scheme: {scheme}. Use one of {sorted(TPM2_RSA_SCHEMES)}"}

            if hash_alg not in TPM2_HASH_ALGORITHMS:
                return {"success": False, "error": f"Unsupported hash algorithm: {hash_alg}. Use one of {sorted(TPM2_HASH_ALGORITHMS)}"}

            if input_kind not in TPM2_INPUT_KINDS:
                return {"success": False, "error": f"Unsupported input kind: {input_kind}. Use one of {sorted(TPM2_INPUT_KINDS)}"}

            if output_format not in ["hex", "base64"]:
                return {"success": False, "error": f"Unsupported output format: {output_format}. Use 'hex' or 'base64'"}

            # Decode base64 data
            decoded_data = base64.b64decode(data)
            
            # Create temporary file for data
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                temp_file.write(decoded_data)
                temp_data_file = temp_file.name
            
            try:
                # Use message input by default to preserve current behavior.
                cmd = [
                    'tpm2_sign',
                    '-c', context_file,
                    '-g', hash_alg,
                    '-s', scheme,
                    '-o', signature_file,
                    '-p', password,
                ]

                if input_kind == "digest":
                    cmd.extend(['-d', temp_data_file])
                else:
                    cmd.append(temp_data_file)
                
                result = self._run_command(cmd)
                
                if result['success']:
                    # Read signature file
                    with open(signature_file, 'rb') as f:
                        signature_data = f.read()
                    
                    # Extract raw RSA signature from TPMT_SIGNATURE structure
                    # TPMT_SIGNATURE format:
                    # - 2 bytes: sigAlg (UINT16) = 0x0014 (TPM_ALG_RSASSA) or 0x0016 (TPM_ALG_RSAPSS)
                    # - 2 bytes: hashAlg (UINT16) = 0x000B (TPM_ALG_SHA256)
                    # - 2 bytes: signature size (UINT16, big-endian)
                    # - N bytes: raw RSA signature value
                    raw_signature = None
                    if len(signature_data) >= 6:
                        # sig_alg = int.from_bytes(signature_data[0:2], 'big')  # 0x0016 for RSAPSS, 0x0014 for RSASSA
                        sig_size = int.from_bytes(signature_data[4:6], 'big')
                        if len(signature_data) >= 6 + sig_size:
                            raw_signature = signature_data[6:6+sig_size]
                    
                    # Format signature based on requested format
                    if output_format == "hex" and raw_signature:
                        # Convert to hex format like regular keys
                        signature_output = raw_signature.hex()
                    else:
                        # Return base64 encoded TPM format (original behavior)
                        signature_output = base64.b64encode(signature_data).decode()
                    
                    return {
                        "success": True,
                        "signature": signature_output,
                        "signature_file": signature_file,
                        "signature_format": output_format,
                        "scheme": scheme,
                        "hash_alg": hash_alg,
                        "input_kind": input_kind,
                        "raw_signature_length": len(raw_signature) if raw_signature else None,
                        "action": "data_signed"
                    }
                else:
                    return result
                    
            finally:
                # Clean up temporary file
                os.unlink(temp_data_file)
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def read_public_key(self, context_file: str, output_format: str = "pem",
                       standardize: bool = True) -> Dict[str, Any]:
        """
        Read the public key from a loaded key context
        
        Args:
            context_file: Key context file
            output_format: Output format ('pem' or 'der', default: 'pem')
            standardize: If True, convert to standard SubjectPublicKeyInfo format 
                        compatible with cryptography library (default: True)
            
        Returns:
            Dictionary with public key data (base64 encoded) or error
        """
        try:
            if output_format not in ["pem", "der"]:
                return {"success": False, "error": f"Unsupported format: {output_format}. Use 'pem' or 'der'"}
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{output_format}") as temp_file:
                temp_output_file = temp_file.name
            
            try:
                # tpm2_readpublic -c context_file -f format -o output_file
                cmd = [
                    'tpm2_readpublic',
                    '-c', context_file,
                    '-f', output_format,
                    '-o', temp_output_file
                ]
                
                result = self._run_command(cmd)
                
                if result['success']:
                    # Read the public key file
                    with open(temp_output_file, 'rb') as f:
                        public_key_data = f.read()
                    
                    # Standardize the format if requested (for compatibility with cryptography library)
                    if standardize and output_format == "pem":
                        try:
                            # Try to load and re-encode using cryptography library
                            # This ensures it's in the exact format expected by load_pem_public_key
                            from cryptography.hazmat.primitives import serialization
                            from cryptography.hazmat.primitives.serialization import load_pem_public_key
                            from cryptography.hazmat.backends import default_backend
                            
                            # Load the TPM public key
                            public_key = load_pem_public_key(public_key_data, backend=default_backend())
                            
                            # Re-encode in standard SubjectPublicKeyInfo format
                            # This matches the format used by regular keys
                            standardized_pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            
                            public_key_data = standardized_pem
                            
                        except Exception:
                            # If standardization fails, use original format
                            # This allows fallback if cryptography library has issues
                            pass
                    
                    # Return as base64 encoded string
                    public_key_b64 = base64.b64encode(public_key_data).decode()
                    
                    # For PEM format, also return as text for convenience
                    public_key_text = None
                    if output_format == "pem":
                        try:
                            public_key_text = public_key_data.decode('utf-8')
                            # Ensure it has PEM headers (in case it's just base64 content)
                            if public_key_text and not public_key_text.strip().startswith('-----BEGIN'):
                                # Convert base64 to PEM format
                                pem_lines = ["-----BEGIN PUBLIC KEY-----"]
                                # Split base64 into 64-character lines
                                for i in range(0, len(public_key_b64), 64):
                                    pem_lines.append(public_key_b64[i:i+64])
                                pem_lines.append("-----END PUBLIC KEY-----")
                                public_key_text = "\n".join(pem_lines)
                        except UnicodeDecodeError:
                            # If decode fails, construct PEM from base64
                            pem_lines = ["-----BEGIN PUBLIC KEY-----"]
                            for i in range(0, len(public_key_b64), 64):
                                pem_lines.append(public_key_b64[i:i+64])
                            pem_lines.append("-----END PUBLIC KEY-----")
                            public_key_text = "\n".join(pem_lines)
                    
                    return {
                        "success": True,
                        "public_key": public_key_b64,  # Base64 encoded (for storage)
                        "public_key_text": public_key_text,  # Full PEM format with headers (for load_pem_public_key)
                        "format": output_format,
                        "standardized": standardize,
                        "context_file": context_file
                    }
                else:
                    return result
                    
            finally:
                # Clean up temporary file
                if os.path.exists(temp_output_file):
                    os.unlink(temp_output_file)
                    
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_signature(
        self,
        context_file: str,
        data: str,
        signature: str,
        signature_format: str = "auto",
        scheme: str = "rsapss",
        hash_alg: str = "sha256",
        input_kind: str = "message",
    ) -> Dict[str, Any]:
        """
        Verify a signature
        
        Args:
            context_file: Key context file
            data: Original data (base64 encoded)
            signature: Signature to verify (hex string or base64 encoded TPM format)
            signature_format: Format of signature - "hex", "base64", or "auto" (detect automatically)
                            Default: "auto" - detects hex vs base64 format
            scheme: TPM signing scheme used to create the signature
            hash_alg: TPM hash algorithm used to create the signature
            input_kind: Whether data is a "message" or precomputed "digest"
            
        Returns:
            Dictionary with verification result
        """
        try:
            scheme = (scheme or "rsapss").lower()
            hash_alg = (hash_alg or "sha256").lower()
            input_kind = (input_kind or "message").lower()
            signature_format = (signature_format or "auto").lower()

            if scheme not in TPM2_RSA_SCHEMES:
                return {"success": False, "error": f"Unsupported signing scheme: {scheme}. Use one of {sorted(TPM2_RSA_SCHEMES)}"}

            if hash_alg not in TPM2_HASH_ALGORITHMS:
                return {"success": False, "error": f"Unsupported hash algorithm: {hash_alg}. Use one of {sorted(TPM2_HASH_ALGORITHMS)}"}

            if input_kind not in TPM2_INPUT_KINDS:
                return {"success": False, "error": f"Unsupported input kind: {input_kind}. Use one of {sorted(TPM2_INPUT_KINDS)}"}

            # Decode base64 data
            decoded_data = base64.b64decode(data)
            
            # Detect signature format if auto
            if signature_format == "auto":
                # Try to detect: hex strings are typically longer and only contain 0-9a-f
                # Base64 strings are shorter and may contain +, /, = characters
                if all(c in '0123456789abcdefABCDEF' for c in signature) and len(signature) > 100:
                    signature_format = "hex"
                else:
                    signature_format = "base64"
            
            # Decode signature based on format
            if signature_format == "hex":
                # Convert hex to bytes (raw RSA signature)
                raw_signature = bytes.fromhex(signature)
                
                # Reconstruct TPMT_SIGNATURE structure:
                # - 2 bytes: sigAlg
                # - 2 bytes: hashAlg
                # - 2 bytes: signature size (UINT16, big-endian)
                # - N bytes: raw RSA signature value
                sig_alg = TPM2_SIGNATURE_ALG_IDS[scheme]
                hash_alg_id = TPM2_HASH_ALG_IDS[hash_alg]
                sig_size = len(raw_signature).to_bytes(2, 'big')
                tpm_signature = sig_alg + hash_alg_id + sig_size + raw_signature
                decoded_signature = tpm_signature
            else:
                # Base64 encoded TPM format (original behavior)
                decoded_signature = base64.b64decode(signature)
            
            # Create temporary files
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_data_file:
                temp_data_file.write(decoded_data)
                temp_data_path = temp_data_file.name
            
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_sig_file:
                temp_sig_file.write(decoded_signature)
                temp_sig_path = temp_sig_file.name
            
            try:
                cmd = [
                    'tpm2_verifysignature',
                    '-c', context_file,
                    '-g', hash_alg,
                    '-s', temp_sig_path
                ]

                if input_kind == "digest":
                    cmd.extend(['-d', temp_data_path])
                else:
                    cmd.extend(['-m', temp_data_path])
                
                result = self._run_command(cmd)
                
                if result['success']:
                    return {
                        "success": True,
                        "verified": True,
                        "scheme": scheme,
                        "hash_alg": hash_alg,
                        "input_kind": input_kind,
                        "action": "signature_verified"
                    }
                else:
                    return {
                        "success": False,
                        "verified": False,
                        "error": result['error']
                    }
                    
            finally:
                # Clean up temporary files
                os.unlink(temp_data_path)
                os.unlink(temp_sig_path)
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def encrypt_data(self, context_file: str, data: str, encrypted_file: str = "encrypted.bin") -> Dict[str, Any]:
        """
        Encrypt data using a loaded RSA key
        
        Args:
            context_file: Key context file (RSA key)
            data: Data to encrypt (base64 encoded)
            encrypted_file: File to save the encrypted data
            
        Returns:
            Dictionary with encryption result
        """
        try:
            # Decode base64 data
            decoded_data = base64.b64decode(data)
            
            # Create temporary file for data
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                temp_file.write(decoded_data)
                temp_data_file = temp_file.name
            
            try:
                cmd = [
                    'tpm2_rsaencrypt',
                    '-c', context_file,
                    '-o', encrypted_file,
                    temp_data_file
                ]
                
                result = self._run_command(cmd)
                
                if result['success']:
                    # Read encrypted file
                    with open(encrypted_file, 'rb') as f:
                        encrypted_data = f.read()
                    
                    return {
                        "success": True,
                        "encrypted_data": base64.b64encode(encrypted_data).decode(),
                        "encrypted_file": encrypted_file,
                        "action": "data_encrypted"
                    }
                else:
                    return result
                    
            finally:
                # Clean up temporary file
                os.unlink(temp_data_file)
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_data(self, context_file: str, encrypted_data: str, password: str, decrypted_file: str = "decrypted.bin") -> Dict[str, Any]:
        """
        Decrypt data using a loaded RSA key
        
        Args:
            context_file: Key context file (RSA key)
            encrypted_data: Encrypted data to decrypt (base64 encoded)
            decrypted_file: File to save the decrypted data
            
        Returns:
            Dictionary with decryption result
        """
        try:
            # Decode base64 encrypted data
            decoded_encrypted = base64.b64decode(encrypted_data)
            
            # Create temporary file for encrypted data
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                temp_file.write(decoded_encrypted)
                temp_encrypted_file = temp_file.name
            
            try:
                cmd = [
                    'tpm2_rsadecrypt',
                    '-c', context_file,
                    '-o', decrypted_file,
                    '-p', password,
                    temp_encrypted_file
                ]
                
                result = self._run_command(cmd)
                
                if result['success']:
                    # Read decrypted file
                    with open(decrypted_file, 'rb') as f:
                        decrypted_data = f.read()
                    
                    return {
                        "success": True,
                        "decrypted_data": base64.b64encode(decrypted_data).decode(),
                        "decrypted_file": decrypted_file,
                        "action": "data_decrypted"
                    }
                else:
                    return result
                    
            finally:
                # Clean up temporary file
                os.unlink(temp_encrypted_file)
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def encrypt_data_aes(self, context_file: str, data: str, password: str, encrypted_file: str = "encrypted_aes.bin") -> Dict[str, Any]:
        """
        Encrypt data using a loaded AES key
        
        Args:
            context_file: Key context file (AES key)
            data: Data to encrypt (base64 encoded)
            encrypted_file: File to save the encrypted data
            
        Returns:
            Dictionary with encryption result
        """
        try:
            # Decode base64 data with proper padding handling
            try:
                decoded_data = base64.b64decode(data, validate=True)
            except Exception:
                # If decoding fails due to padding, add padding and retry
                padding_needed = 4 - (len(data) % 4)
                if padding_needed != 4:
                    decoded_data = base64.b64decode(data + '=' * padding_needed, validate=True)
                else:
                    raise ValueError(f"Invalid base64-encoded string: number of data characters ({len(data)}) cannot be processed")
            
            # Create temporary file for data
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                temp_file.write(decoded_data)
                temp_data_file = temp_file.name
            
            try:
                # Use --pad for PKCS7 padding to ensure proper block alignment
                # Encryption is the default, so no flag needed for that
                # Specify CFB mode explicitly (default for AES in TPM2)
                cmd = [
                    'tpm2_encryptdecrypt',
                    '-c', context_file,
                    '--mode', 'cfb',  # Explicitly specify CFB mode for AES
                    '--pad',  # Enable PKCS7 padding for AES block ciphers
                    '-o', encrypted_file,
                    '-p', password,
                    temp_data_file,
                ]
                
                result = self._run_command(cmd)
                
                if result['success']:
                    # Read encrypted file
                    with open(encrypted_file, 'rb') as f:
                        encrypted_data = f.read()
                    
                    return {
                        "success": True,
                        "encrypted_data": base64.b64encode(encrypted_data).decode(),
                        "encrypted_file": encrypted_file,
                        "action": "data_encrypted_aes"
                    }
                else:
                    return result
                    
            finally:
                # Clean up temporary file
                os.unlink(temp_data_file)
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_data_aes(self, context_file: str, encrypted_data: str, password: str, decrypted_file: str = "decrypted_aes.bin") -> Dict[str, Any]:
        """
        Decrypt data using a loaded AES key
        
        Args:
            context_file: Key context file (AES key)
            encrypted_data: Encrypted data to decrypt (base64 encoded)
            decrypted_file: File to save the decrypted data
            
        Returns:
            Dictionary with decryption result
        """
        if not os.path.exists(context_file):
            return {
                "success": False,
                "error": f"AES context file '{context_file}' does not exist; AES key is not loaded"
            }

        # Confirm TPM can read the context before attempting decryption
        ctx_check = self._run_command(['tpm2_readpublic', '-c', context_file])
        if not ctx_check.get("success"):
            return {
                "success": False,
                "error": (
                    f"AES context '{context_file}' is not valid (failed to read context: "
                    f"{ctx_check.get('error', 'Unknown error')})"
                )
            }

        try:
            # Decode base64 encrypted data with proper padding handling
            # Base64 strings must be multiples of 4 characters
            try:
                decoded_encrypted = base64.b64decode(encrypted_data, validate=True)
            except Exception:
                # If decoding fails due to padding, add padding and retry
                padding_needed = 4 - (len(encrypted_data) % 4)
                if padding_needed != 4:
                    decoded_encrypted = base64.b64decode(encrypted_data + '=' * padding_needed, validate=True)
                else:
                    raise ValueError(f"Invalid base64-encoded string: number of data characters ({len(encrypted_data)}) cannot be processed")

            # Create temporary file for encrypted data
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                temp_file.write(decoded_encrypted)
                temp_encrypted_file = temp_file.name

            try:
                # Use -d or --decrypt for decryption
                # Input file should be the last argument
                # Specify CFB mode explicitly to match encryption
                cmd = [
                    'tpm2_encryptdecrypt',
                    '-c', context_file,
                    '-d',  # Decrypt mode
                    '--mode', 'cfb',  # Explicitly specify CFB mode for AES
                    '-o', decrypted_file,
                    '-p', password,
                    temp_encrypted_file  # Input file as last argument
                ]

                result = self._run_command(cmd)

                if result['success']:
                    # Read decrypted file
                    with open(decrypted_file, 'rb') as f:
                        decrypted_data = f.read()

                    return {
                        "success": True,
                        "decrypted_data": base64.b64encode(decrypted_data).decode(),
                        "decrypted_file": decrypted_file,
                        "action": "data_decrypted_aes"
                    }
                else:
                    return result

            finally:
                # Clean up temporary file
                os.unlink(temp_encrypted_file)

        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_encrypted_file_store(self, context_file: str, store_name: str = "file_store.json") -> Dict[str, Any]:
        """
        Create a new encrypted file store with an empty JSON structure
        
        Args:
            context_file: Key context file (RSA key) for encryption
            store_name: Name of the encrypted file store
            
        Returns:
            Dictionary with creation result
        """
        try:
            # Create empty JSON structure
            empty_store = {}
            json_data = json.dumps(empty_store, indent=2)
            
            # Encrypt the empty JSON
            result = self.encrypt_data(context_file, base64.b64encode(json_data.encode()).decode(), store_name)
            
            if result['success']:
                return {
                    "success": True,
                    "store_name": store_name,
                    "message": "Encrypted file store created successfully",
                    "action": "file_store_created"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def store_key_value(self, context_file: str, store_name: str, key: str, value: Any, password: str) -> Dict[str, Any]:
        """
        Store a key-value pair in the encrypted file store
        
        Args:
            context_file: Key context file (RSA key) for encryption/decryption
            store_name: Name of the encrypted file store
            key: Key to store
            value: Value to store (will be JSON serialized)
            
        Returns:
            Dictionary with storage result
        """
        try:
            # Step 1: Decrypt the existing file store
            if os.path.exists(store_name):
                # Read encrypted file
                with open(store_name, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data
                decrypt_result = self.decrypt_data(
                    context_file, 
                    base64.b64encode(encrypted_data).decode(),
                    password,
                    "temp_decrypted.json"
                )
                
                if not decrypt_result['success']:
                    return decrypt_result
                
                # Parse the decrypted JSON
                with open("temp_decrypted.json", 'r') as f:
                    store_data = json.load(f)
            else:
                # Create new empty store
                store_data = {}
            
            # Step 2: Add/modify the key-value pair
            store_data[key] = value
            
            # Step 3: Re-encrypt the updated data
            json_data = json.dumps(store_data, indent=2)
            encrypt_result = self.encrypt_data(
                context_file, 
                base64.b64encode(json_data.encode()).decode(), 
                store_name
            )
            
            # Clean up temporary file
            if os.path.exists("temp_decrypted.json"):
                os.unlink("temp_decrypted.json")
            
            if encrypt_result['success']:
                return {
                    "success": True,
                    "key": key,
                    "value": value,
                    "store_name": store_name,
                    "message": f"Key '{key}' stored successfully",
                    "action": "key_value_stored"
                }
            else:
                return encrypt_result
                
        except Exception as e:
            # Clean up temporary file on error
            if os.path.exists("temp_decrypted.json"):
                os.unlink("temp_decrypted.json")
            return {"success": False, "error": str(e)}

    def retrieve_key_value(self, context_file: str, store_name: str, key: str, password: str) -> Dict[str, Any]:
        """
        Retrieve a key-value pair from the encrypted file store
        
        Args:
            context_file: Key context file (RSA key) for decryption
            store_name: Name of the encrypted file store
            key: Key to retrieve
            
        Returns:
            Dictionary with retrieval result
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"File store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypt_result = self.decrypt_data(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                "temp_decrypted.json"
            )
            
            if not decrypt_result['success']:
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and retrieve the key
            with open("temp_decrypted.json", 'r') as f:
                store_data = json.load(f)
            
            # Clean up temporary file
            os.unlink("temp_decrypted.json")
            
            if key in store_data:
                return {
                    "success": True,
                    "key": key,
                    "value": store_data[key],
                    "store_name": store_name,
                    "action": "key_value_retrieved"
                }
            else:
                return {
                    "success": False,
                    "error": f"Key '{key}' not found in file store",
                    "available_keys": list(store_data.keys())
                }
                
        except Exception as e:
            # Clean up temporary file on error
            if os.path.exists("temp_decrypted.json"):
                os.unlink("temp_decrypted.json")
            return {"success": False, "error": str(e)}

    def list_file_store_keys(self, context_file: str, store_name: str, password: str) -> Dict[str, Any]:
        """
        List all keys in the encrypted file store
        
        Args:
            context_file: Key context file (RSA key) for decryption
            store_name: Name of the encrypted file store
            
        Returns:
            Dictionary with list of keys
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"File store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypt_result = self.decrypt_data(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                "temp_decrypted.json"
            )
            
            if not decrypt_result['success']:
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and get all keys
            with open("temp_decrypted.json", 'r') as f:
                store_data = json.load(f)
            
            # Clean up temporary file
            os.unlink("temp_decrypted.json")
            
            return {
                "success": True,
                "keys": list(store_data.keys()),
                "total_keys": len(store_data),
                "store_name": store_name,
                "action": "keys_listed"
            }
                
        except Exception as e:
            # Clean up temporary file on error
            if os.path.exists("temp_decrypted.json"):
                os.unlink("temp_decrypted.json")
            return {"success": False, "error": str(e)}

    def delete_key_value(self, context_file: str, store_name: str, key: str, password: str) -> Dict[str, Any]:
        """
        Delete a key-value pair from the encrypted file store
        
        Args:
            context_file: Key context file (RSA key) for encryption/decryption
            store_name: Name of the encrypted file store
            key: Key to delete
            
        Returns:
            Dictionary with deletion result
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"File store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypt_result = self.decrypt_data(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                "temp_decrypted.json"
            )
            
            if not decrypt_result['success']:
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and delete the key
            with open("temp_decrypted.json", 'r') as f:
                store_data = json.load(f)
            
            if key not in store_data:
                # Clean up temporary file
                os.unlink("temp_decrypted.json")
                return {
                    "success": False,
                    "error": f"Key '{key}' not found in file store",
                    "available_keys": list(store_data.keys())
                }
            
            # Store the value before deletion for response
            deleted_value = store_data[key]
            del store_data[key]
            
            # Step 3: Re-encrypt the updated data
            json_data = json.dumps(store_data, indent=2)
            encrypt_result = self.encrypt_data(
                context_file, 
                base64.b64encode(json_data.encode()).decode(), 
                store_name
            )
            
            # Clean up temporary file
            os.unlink("temp_decrypted.json")
            
            if encrypt_result['success']:
                return {
                    "success": True,
                    "key": key,
                    "deleted_value": deleted_value,
                    "store_name": store_name,
                    "message": f"Key '{key}' deleted successfully",
                    "action": "key_value_deleted"
                }
            else:
                return encrypt_result
                
        except Exception as e:
            # Clean up temporary file on error
            if os.path.exists("temp_decrypted.json"):
                os.unlink("temp_decrypted.json")
            return {"success": False, "error": str(e)}

    def create_encrypted_file_store_aes(self, context_file: str, password: str, store_name: str = "file_store_aes.json") -> Dict[str, Any]:
        """
        Create a new encrypted file store using AES encryption
        
        Args:
            context_file: Key context file (AES key) for encryption
            store_name: Name of the encrypted file store
            
        Returns:
            Dictionary with creation result
        """
        try:
            # Create empty JSON structure
            empty_store = {}
            json_data = json.dumps(empty_store, indent=2)
            
            # Encrypt the empty JSON using AES
            result = self.encrypt_data_aes(context_file, base64.b64encode(json_data.encode()).decode(), password, store_name)
            
            if result['success']:
                return {
                    "success": True,
                    "store_name": store_name,
                    "message": "AES encrypted file store created successfully",
                    "action": "aes_file_store_created"
                }
            else:
                return result
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    def store_key_value_aes(self, context_file: str, store_name: str, key: str, value: Any, password: str) -> Dict[str, Any]:
        """
        Store a key-value pair in the AES encrypted file store
        
        Args:
            context_file: Key context file (AES key) for encryption/decryption
            store_name: Name of the encrypted file store
            key: Key to store
            value: Value to store (will be JSON serialized)
            
        Returns:
            Dictionary with storage result
        """
        try:
            # Step 1: Decrypt the existing file store
            if os.path.exists(store_name):
                # Read encrypted file
                with open(store_name, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data using AES
                decrypt_result = self.decrypt_data_aes(
                    context_file, 
                    base64.b64encode(encrypted_data).decode(),
                    password,
                    TEMP_DECRYPTED_AES_FILE
                )
                
                if not decrypt_result['success']:
                    self._cleanup_temp_decrypted_file()
                    return decrypt_result
                
                # Parse the decrypted JSON
                with open(TEMP_DECRYPTED_AES_FILE, 'r') as f:
                    store_data = json.load(f)
            else:
                # Create new empty store
                store_data = {}
            
            # Step 2: Add/modify the key-value pair
            store_data[key] = value
            
            # Step 3: Re-encrypt the updated data using AES
            json_data = json.dumps(store_data, indent=2)
            encrypt_result = self.encrypt_data_aes(
                context_file, 
                base64.b64encode(json_data.encode()).decode(), 
                password,
                store_name
            )
            
            # Clean up temporary file
            self._cleanup_temp_decrypted_file()
            
            if encrypt_result['success']:
                return {
                    "success": True,
                    "key": key,
                    "value": value,
                    "store_name": store_name,
                    "message": f"Key '{key}' stored successfully using AES",
                    "action": "key_value_stored_aes"
                }
            else:
                return encrypt_result
                
        except Exception as e:
            # Clean up temporary file on error
            self._cleanup_temp_decrypted_file()
            return {"success": False, "error": str(e)}

    def retrieve_key_value_aes(self, context_file: str, store_name: str, key: str, password: str) -> Dict[str, Any]:
        """
        Retrieve a key-value pair from the AES encrypted file store
        
        Args:
            context_file: Key context file (AES key) for decryption
            store_name: Name of the encrypted file store
            key: Key to retrieve
            
        Returns:
            Dictionary with retrieval result
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"AES file store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data using AES
            decrypt_result = self.decrypt_data_aes(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                TEMP_DECRYPTED_AES_FILE
            )
            
            if not decrypt_result['success']:
                self._cleanup_temp_decrypted_file()
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and retrieve the key
            with open(TEMP_DECRYPTED_AES_FILE, 'r') as f:
                store_data = json.load(f)
            
            # Clean up temporary file
            self._cleanup_temp_decrypted_file()
            
            if key in store_data:
                return {
                    "success": True,
                    "key": key,
                    "value": store_data[key],
                    "store_name": store_name,
                    "action": "key_value_retrieved_aes"
                }
            else:
                return {
                    "success": False,
                    "error": f"Key '{key}' not found in AES file store",
                    "available_keys": list(store_data.keys())
                }
                
        except Exception as e:
            # Clean up temporary file on error
            self._cleanup_temp_decrypted_file()
            return {"success": False, "error": str(e)}

    def list_file_store_keys_aes(self, context_file: str, store_name: str, password: str) -> Dict[str, Any]:
        """
        List all keys in the AES encrypted file store
        
        Args:
            context_file: Key context file (AES key) for decryption
            store_name: Name of the encrypted file store
            
        Returns:
            Dictionary with list of keys
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"AES file store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data using AES
            decrypt_result = self.decrypt_data_aes(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                TEMP_DECRYPTED_AES_FILE
            )
            
            if not decrypt_result['success']:
                self._cleanup_temp_decrypted_file()
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and get all keys
            with open(TEMP_DECRYPTED_AES_FILE, 'r') as f:
                store_data = json.load(f)
            
            # Clean up temporary file
            self._cleanup_temp_decrypted_file()
            
            return {
                "success": True,
                "keys": list(store_data.keys()),
                "total_keys": len(store_data),
                "store_name": store_name,
                "action": "keys_listed_aes"
            }
                
        except Exception as e:
            # Clean up temporary file on error
            self._cleanup_temp_decrypted_file()
            return {"success": False, "error": str(e)}

    def delete_key_value_aes(self, context_file: str, store_name: str, key: str, password: str) -> Dict[str, Any]:
        """
        Delete a key-value pair from the AES encrypted file store
        
        Args:
            context_file: Key context file (AES key) for encryption/decryption
            store_name: Name of the encrypted file store
            key: Key to delete
            
        Returns:
            Dictionary with deletion result
        """
        try:
            if not os.path.exists(store_name):
                return {"success": False, "error": f"AES file store '{store_name}' does not exist"}
            
            # Step 1: Read and decrypt the file store
            with open(store_name, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data using AES
            decrypt_result = self.decrypt_data_aes(
                context_file, 
                base64.b64encode(encrypted_data).decode(),
                password,
                TEMP_DECRYPTED_AES_FILE
            )

            if not decrypt_result['success']:
                self._cleanup_temp_decrypted_file()
                return decrypt_result
            
            # Step 2: Parse the decrypted JSON and delete the key
            with open(TEMP_DECRYPTED_AES_FILE, 'r') as f:
                store_data = json.load(f)
            
            if key not in store_data:
                # Clean up temporary file
                self._cleanup_temp_decrypted_file()
                return {
                    "success": False,
                    "error": f"Key '{key}' not found in AES file store",
                    "available_keys": list(store_data.keys())
                }
            
            # Store the value before deletion for response
            deleted_value = store_data[key]
            del store_data[key]
            
            # Step 3: Re-encrypt the updated data using AES
            json_data = json.dumps(store_data, indent=2)
            encrypt_result = self.encrypt_data_aes(
                context_file, 
                base64.b64encode(json_data.encode()).decode(), 
                password,
                store_name
            )
            
            # Clean up temporary file
            self._cleanup_temp_decrypted_file()
            
            if encrypt_result['success']:
                return {
                    "success": True,
                    "key": key,
                    "deleted_value": deleted_value,
                    "store_name": store_name,
                    "message": f"Key '{key}' deleted successfully from AES store",
                    "action": "key_value_deleted_aes"
                }
            else:
                return encrypt_result
                
        except Exception as e:
            # Clean up temporary file on error
            self._cleanup_temp_decrypted_file()
            return {"success": False, "error": str(e)}

    def full_reset(self, password: str) -> Dict[str, Any]:
        """
        Perform a complete TPM reset - clears all contexts, persistent objects, and authorizations
        
        Returns:
            Dictionary with reset result
        """
        try:
            results = {}
            
            # Step 1: Clear all persistent objects (common handles)
            print("Clearing persistent objects...")
            persistent_handles = [
                0x81010001, 0x81010002, 0x81010003, 0x81010004, 0x81010005,
                0x81010006, 0x81010007, 0x81010008, 0x81010009, 0x8101000A,
                0x8101000B, 0x8101000C, 0x8101000D, 0x8101000E, 0x8101000F,
                0x81010010, 0x81010011, 0x81010012, 0x81010013, 0x81010014
            ]
            
            cleared_persistent = []
            for handle in persistent_handles:
                try:
                    cmd = ['tpm2_evictcontrol', '-C', 'o', '-P', password, '-c', str(handle)]
                    result = self._run_command(cmd)
                    if result['success']:
                        cleared_persistent.append(hex(handle))
                    # Don't fail if handle doesn't exist - that's expected
                except Exception:
                    # Ignore errors for non-existent handles
                    pass
            
            results["cleared_persistent"] = cleared_persistent
            
            # Step 2: Clear all contexts
            print("Clearing all contexts...")
            flush_result = self.flush_context("all")
            results["flush_contexts"] = flush_result
            
            # Step 3: Clear owner authorization
            print("Clearing owner authorization...")
            try:
                cmd = ['tpm2_clear', '-c', 'o']
                result = self._run_command(cmd)
                results["clear_owner"] = result
            except Exception as e:
                results["clear_owner"] = {"success": False, "error": str(e)}
            
            # Step 4: Clear endorsement authorization
            print("Clearing endorsement authorization...")
            try:
                cmd = ['tpm2_clear', '-c', 'e']
                result = self._run_command(cmd)
                results["clear_endorsement"] = result
            except Exception as e:
                results["clear_endorsement"] = {"success": False, "error": str(e)}
            
            # Step 5: Clear platform authorization
            print("Clearing platform authorization...")
            try:
                cmd = ['tpm2_clear', '-c', 'p']
                result = self._run_command(cmd)
                results["clear_platform"] = result
            except Exception as e:
                results["clear_platform"] = {"success": False, "error": str(e)}
            
            return {
                "success": True,
                "message": "TPM full reset completed",
                "results": results,
                "action": "tpm_full_reset"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        """
        List files in the working directory.
        
        Args:
            directory: Relative path to directory to list (default: current directory)
            
        Returns:
            Dictionary with list of files
        """
        try:
            # Ensure the path is relative and within working directory for security
            if os.path.isabs(directory) or ".." in directory:
                return {
                    "success": False,
                    "error": f"Invalid directory path: {directory}. Only relative paths within working directory are allowed."
                }
            
            # Normalize the path
            normalized_dir = os.path.normpath(directory)
            
            # Get current working directory for debugging
            cwd = os.getcwd()
            
            # Check if directory exists
            if not os.path.exists(normalized_dir):
                return {
                    "success": False,
                    "error": f"Directory '{normalized_dir}' does not exist (current working directory: {cwd})"
                }
            
            if not os.path.isdir(normalized_dir):
                return {
                    "success": False,
                    "error": f"'{normalized_dir}' is not a directory"
                }
            
            # List all files in the directory
            files = []
            directories = []
            try:
                for item in os.listdir(normalized_dir):
                    item_path = os.path.join(normalized_dir, item)
                    if os.path.isfile(item_path):
                        files.append(item)
                    elif os.path.isdir(item_path):
                        directories.append(item)
            except PermissionError as e:
                return {
                    "success": False,
                    "error": f"Permission denied listing directory '{normalized_dir}': {str(e)}"
                }
            
            return {
                "success": True,
                "files": sorted(files),
                "directories": sorted(directories),
                "directory": normalized_dir,
                "current_working_directory": cwd,
                "total_files": len(files),
                "total_directories": len(directories)
            }
            
        except PermissionError as e:
            return {
                "success": False,
                "error": f"Permission denied: {str(e)}"
            }
        except Exception as e:
            import traceback
            error_detail = f"{str(e)}\nTraceback: {traceback.format_exc()}"
            return {
                "success": False,
                "error": f"Failed to list files: {error_detail}"
            }

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        """
        Delete a file from the working directory.
        
        Args:
            file_path: Relative path to the file in the working directory
            
        Returns:
            Dictionary with deletion result
        """
        try:
            # Ensure the path is relative and within working directory for security
            # Don't allow paths with .. to prevent directory traversal
            if os.path.isabs(file_path) or ".." in file_path:
                return {
                    "success": False,
                    "error": f"Invalid file path: {file_path}. Only relative paths within working directory are allowed."
                }
            
            # Normalize the path
            normalized_path = os.path.normpath(file_path)
            
            # Check if file exists
            if not os.path.exists(normalized_path):
                return {
                    "success": False,
                    "error": f"File '{normalized_path}' does not exist"
                }
            
            # Delete the file
            os.unlink(normalized_path)
            
            return {
                "success": True,
                "message": f"File '{normalized_path}' deleted successfully",
                "file_path": normalized_path,
                "action": "file_deleted"
            }
            
        except PermissionError as e:
            return {
                "success": False,
                "error": f"Permission denied: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to delete file: {str(e)}"
            }

# Example usage
if __name__ == "__main__":
    # Initialize TPM2 API
    tpm = TPM2API()
    
    # Create primary key
    print("Creating primary key...")
    result = tpm.create_primary_key(password="abc")
    print(json.dumps(result, indent=2))
    
    # Create RSA key
    print("\nCreating RSA key...")
    result = tpm.create_key("primary.ctx", "abc", "rsa", "rsa.pub", "rsa.priv")
    print(json.dumps(result, indent=2))
    
    # Load key
    print("\nLoading key...")
    result = tpm.load_key("primary.ctx", "rsa.pub", "rsa.priv", "abc", "rsa.ctx")
    print(json.dumps(result, indent=2))
    
    # Make persistent
    print("\nMaking key persistent...")
    result = tpm.make_persistent("rsa.ctx", "abc")
    print(json.dumps(result, indent=2)) 
