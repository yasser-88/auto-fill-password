
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === Key Derivation ===
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=600_000,      # High = secure against brute force
    )
    return kdf.derive(master_password.encode())

# === Encryption ===
def encrypt_data(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext with AES-GCM. Returns nonce + ciphertext."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext  # Store together

# === Decryption ===
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt AES-GCM data. Expects nonce + ciphertext."""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

# === Vault Structure ===
def create_vault(master_password: str, entries: list) -> bytes:
    """Create an encrypted vault file from a list of entries."""
    salt = os.urandom(16)  # New random salt
    key = derive_key(master_password, salt)
    
    # Encrypt each password
    encrypted_entries = []
    for entry in entries:
        encrypted_pass = encrypt_data(entry['password'], key)
        encrypted_entries.append({
            'domain': entry['domain'],
            'username': entry['username'],
            'encrypted_password': encrypted_pass.hex()  # Store as hex for JSON
        })
    
    # Build vault with header
    vault = {
        'version': 1,
        'salt': salt.hex(),  # Store salt in header
        'entries': encrypted_entries
    }
    return json.dumps(vault, indent =2).encode('utf-8')

def load_vault(vault_data: bytes, master_password: str) -> list:
    """Load and decrypt vault."""
    vault = json.loads(vault_data.decode('utf-8'))
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

def load_entries(vault_data: bytes )-> list:
    """Load and decrypt vault."""
    vault = json.loads(vault_data.decode('utf-8'))    
    entries = []
    return vault['entries']
   
def verify_exitence(vault:list , url : str) -> bool:
    """Load and decrypt vault."""
    for item in vault:
        if item['domain'] == url:
            return True
    return False