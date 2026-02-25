
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.json")

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(master_password.encode())

def encrypt_data(plaintext: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def create_vault(master_password: str, entries: list) :
    
    if os.path.exists(VAULT_FILE):
        raise FileExistsError(
            f"Vault file '{VAULT_FILE}' already exists! "
            "Delete it first if you want to create a new one."
        )
    
    write_vault(master_password, entries)


def write_vault(master_password: str, entries: list):
    try:
        salt = os.urandom(16)
        key = derive_key(master_password, salt)

        encrypted_entries = []
        for entry in entries:
            encrypted_domain = encrypt_data(entry['domain'], key)
            encrypted_user = encrypt_data(entry['username'], key)
            encrypted_pass = encrypt_data(entry['password'], key)
            encrypted_entries.append({
                'encrypted_domain': encrypted_domain.hex(),
                'encrypted_username': encrypted_user.hex(),
                'encrypted_password': encrypted_pass.hex()
            })

        vault = {
            'version': 2,
            'salt': salt.hex(),
            'entries': encrypted_entries
        }

        with open(VAULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(vault, f, indent=2)

    except OSError as e:
        raise RuntimeError(f"Failed to save vault: {e}")

def load_vault(master_password: str) -> list:
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

    version = vault.get('version', 1)
    entries = []
    for item in vault['entries']:
        encrypted_pass = bytes.fromhex(item['encrypted_password'])
        password = decrypt_data(encrypted_pass, key)

        if version >= 2:
            domain = decrypt_data(bytes.fromhex(item['encrypted_domain']), key)
            username = decrypt_data(bytes.fromhex(item['encrypted_username']), key)
        else:
            domain = item['domain']
            username = item['username']

        entries.append({
            'domain': domain,
            'username': username,
            'password': password
        })
    return entries

