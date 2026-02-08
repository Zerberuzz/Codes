from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
import os
import argparse
import getpass

def generate_key_pair():
    key_size = 2048
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    public_key = private_key.public_key()
    return private_key, public_key

def load_certificate(cert_path):
    """Load certificate from .cer file"""
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        # Try loading as DER format first
        try:
            cert = serialization.load_der_x509_certificate(cert_data)
            print(f"Successfully loaded certificate in DER format from {cert_path}")
            return cert.public_key()
        except Exception as der_error:
            print(f"DER format failed: {der_error}")
        
        # Try loading as PEM format
        try:
            cert = load_pem_x509_certificate(cert_data)
            print(f"Successfully loaded certificate in PEM format from {cert_path}")
            return cert.public_key()
        except Exception as pem_error:
            print(f"PEM format failed: {pem_error}")
        
        # Try converting DER binary to PEM format
        try:
            # Assume it's raw DER, wrap it in PEM headers
            pem_data = b'-----BEGIN CERTIFICATE-----\n'
            import base64
            pem_data += base64.b64encode(cert_data)
            pem_data += b'\n-----END CERTIFICATE-----'
            cert = load_pem_x509_certificate(pem_data)
            print(f"Successfully loaded certificate by converting DER to PEM from {cert_path}")
            return cert.public_key()
        except Exception as convert_error:
            print(f"DER to PEM conversion failed: {convert_error}")
        
        return None
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return None

def load_private_key(key_path, password=None):
    """Load private key from .key file"""
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        # Try loading as DER format first
        try:
            private_key = serialization.load_der_private_key(
                key_data, 
                password=password
            )
        except:
            # If DER fails, try PEM format
            private_key = serialization.load_pem_private_key(
                key_data, 
                password=password
            )
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def encrypt(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(encrypted_message, private_key):
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return f"Decrypted message: {decrypted_message}"
    except ValueError:
        return "Decryption failed"
    
def sign(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify(signature, message, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Message verified successfully"
    except InvalidSignature:
        return "Invalid signature" 

def main(cert_path=None, key_path=None, password=None):
    """Run demo using generated keys and then load external keys provided by caller.

    Parameters:
    - cert_path: absolute path to the .cer file
    - key_path: absolute path to the private .key file
    - password: password for the private key (str or bytes), or None
    """
    # Demonstrate generated keys first
    print("=== Using Generated Keys ===")
    

    if not cert_path or not key_path:
        print("\nNo certificate or key path provided; skipping external keys test.")
        return

    print("\n=== Loading External Keys ===")
    # Load certificate and private key from files
    public_key_loaded = load_certificate(cert_path)
    private_key_loaded = load_private_key(key_path, password=password)
    
    if public_key_loaded and private_key_loaded:
        print("Successfully loaded certificate and private key")
        print(f"Certificate path: {cert_path}")
        print(f"Private key path: {key_path}")
        
        # Test with loaded keys
        test_message = b"test with loaded keys"
        print("\n--------------------Testing with Loaded Keys----------------------")
        try:
            encrypted = encrypt(test_message, public_key_loaded)
            print("Message encrypted successfully")
            
            signature_loaded = sign(test_message, private_key_loaded)
            print("Message signed successfully")
            
            verified_loaded = verify(signature_loaded, test_message, public_key_loaded)
            print(f"Signature verification: {verified_loaded}")
            
            decrypted = decrypt(encrypted, private_key_loaded)
            print(f"Decryption result: {decrypted}")
        except Exception as e:
            print(f"Error during operations: {e}")
    else:
        print("Could not load keys from files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA demo using certificate and private key files")
    parser.add_argument("--cert", "-c", help="Absolute path to .cer certificate file",
                        default="/home/euro/Codes/keys/xoji740919u48.cer")
    parser.add_argument("--key", "-k", help="Absolute path to private .key file",
                        default="/home/euro/Codes/keys/Claveprivada_FIEL_XOJI740919U48_20230118_122738.key")
    parser.add_argument("--password", "-p", help="Private key password (insecure on CLI). If omitted, no password is used",
                        default=None)
    parser.add_argument("--prompt-password", action="store_true",
                        help="Prompt securely for the private key password instead of passing on CLI")

    args = parser.parse_args()

    pwd = None
    if args.prompt_password:
        pwd = getpass.getpass("Private key password: ")
        if pwd == "":
            pwd = None
    else:
        pwd = args.password

    main(cert_path=args.cert, key_path=args.key, password=pwd.encode('utf-8'))