from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
import os

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
        except:
            # If DER fails, try PEM format
            cert = load_pem_x509_certificate(cert_data)
        return cert.public_key()
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

def main():
    keys_directory = "/home/euro/Codes/keys"
    
    # Define the key and certificate paths
    cert_path = os.path.join(keys_directory, "xoji740919u48.cer")
    key_path = os.path.join(keys_directory, "Claveprivada_FIEL_XOJI740919U48_20230118_122738.key")
    
    print("=== Using Generated Keys ===")
    # Generate a key pair for demonstration
    generate_key_pair()
    private_key, public_key = generate_key_pair()
    message = b"hello"
    print("--------------------------Encrypting------------------------")
    encrypted_message = encrypt(message, public_key)
    print("--------------------Signing--------------------------------")
    signature = sign(message, private_key)
    print(f"Encrypted text: {encrypted_message.hex()}, and signature: {signature.hex()}")
    print("--------------------Verifying signature----------------------")
    verified = verify(signature, message, public_key)
    print(verified)
    decrypted_message = decrypt(encrypted_message, private_key)
    print(decrypted_message)
    
    print("\n=== Loading External Keys ===")
    # Load certificate and private key from files
    public_key_loaded = load_certificate(cert_path)
    private_key_loaded = load_private_key(key_path)
    
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
    main()