# RSA Cryptography Demo

This program demonstrates RSA encryption, decryption, signing, and verification using certificate and private key files.

## Prerequisites

Install the required dependency:

```bash
pip install cryptography
```

## Execution Instructions

### Basic Execution

Run the program with default certificate and key paths:

```bash
python program.py
```

**Note:** The default paths are set to `/home/euro/Codes/keys/xoji740919u48.cer` and `/home/euro/Codes/keys/Claveprivada_FIEL_XOJI740919U48_20230118_122738.key`. You'll need to provide custom paths if these files don't exist on your system.

### With Custom Certificate and Key Paths

Specify custom paths to your certificate and private key files:

```bash
python program.py --cert /path/to/certificate.cer --key /path/to/private.key
```

Or use short flags:

```bash
python program.py -c /path/to/certificate.cer -k /path/to/private.key
```

### With Password Protection

If your private key is password-protected, pass the password via the command line:

```bash
python program.py --cert /path/to/certificate.cer --key /path/to/private.key --password "your_password"
```

Or use short flags:

```bash
python program.py -c /path/to/certificate.cer -k /path/to/private.key -p "your_password"
```

### Prompt for Password Securely

For better security, prompt for the password interactively instead of passing it on the command line:

```bash
python program.py --cert /path/to/certificate.cer --key /path/to/private.key --prompt-password
```

This will ask you to enter the password securely without displaying it on the screen.

## Program Usage Example

With the files in the `keys/` directory:

```bash
python program.py --cert keys/CSD_XOJI740919U48_20230118134910/CSD_XOJI740919U48_20230118_134910.sdg --key keys/Renovacion_FIEL_XOJI740919U48_20230118_122738.ren --prompt-password
```

## Program Output

The program will:
1. Load the certificate and private key from the specified paths
2. Perform test encryption/decryption operations
3. Perform test signing/verification operations
4. Display success/error messages for each operation
