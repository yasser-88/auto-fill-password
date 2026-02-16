
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.json"

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=600_000,      # High = secure against brute force
    )
    return kdf.derive(master_password.encode())

def encrypt_data(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext with AES-GCM. Returns nonce + ciphertext."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext  # Store together

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt AES-GCM data. Expects nonce + ciphertext."""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def create_vault(master_password: str, entries: list) :
    """Create a new vault file. Fails if a vault already exists."""
    
    # 🔒 Prevent accidental overwrite
    if os.path.exists(VAULT_FILE):
        raise FileExistsError(
            f"Vault file '{VAULT_FILE}' already exists! "
            "Delete it first if you want to create a new one."
        )
    
    try:
        salt = os.urandom(16)
        key = derive_key(master_password, salt)

        encrypted_entries = []
        for entry in entries:
            encrypted_pass = encrypt_data(entry['password'], key)
            encrypted_entries.append({
                'domain': entry['domain'],
                'username': entry['username'],
                'encrypted_password': encrypted_pass.hex()
            })

        vault = {
            'version': 1,
            'salt': salt.hex(),
            'entries': encrypted_entries
        }

        # Write to file
        with open(VAULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(vault, f, indent=2)

    except OSError as e:
        raise RuntimeError(f"Failed to save vault: {e}")

def load_vault(master_password: str) -> list:
    """Load and decrypt the vault from the fixed vault file."""
    try:
        with open(VAULT_FILE, 'r', encoding='utf-8') as f:
            vault_data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Vault file '{VAULT_FILE}' not found. Create a new vault first.")

    try:
        vault = json.loads(vault_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Vault file is corrupted or invalid: {e}")

    salt = bytes.fromhex(vault['salt'])
    key = derive_key(master_password, salt)

    entries = []
    for item in vault['entries']:
        encrypted_pass = bytes.fromhex(item['encrypted_password'])
        password = decrypt_data(encrypted_pass, key)
        entries.append({
            'domain': item['domain'],
            'username': item['username'],
            'password': password
        })
    return entries

