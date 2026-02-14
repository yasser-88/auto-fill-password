import os
import json
from getpass import getpass
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import derive_key, create_vault, load_vault


VAULT_FILE = "vault.json"

def main():
    print("🔐 Password Vault Tester")
    master_pass = input("Enter master password: ")

    # Load existing vault or start fresh
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            try:
                entries = load_vault(f.read(), master_pass)
                print(f"✅ Loaded {len(entries)} logins from '{VAULT_FILE}'")
            except Exception as e:
                print(f"❌ Failed to load vault: {e}")
                return
    else:
        entries = []
        print("🆕 No vault found. Starting fresh.")

    while True:
        print("\n--- MENU ---")
        print("1. Add new login")
        print("2. View all logins")
        print("3. Search for a domain")
        print("4. Quit")
        choice = input("Select option (1-3): ").strip()

        if choice == "1":
            domain = input("Domain (e.g., github.com): ").strip()
            username = input("Username/email: ").strip()
            password = getpass("Password (leave empty to generate): ")
            
            if not password:
                import secrets
                password = secrets.token_urlsafe(16)
                print(f"✨ Generated: {password}")
            
            entries.append({
                "domain": domain,
                "username": username,
                "password": password
            })
            
            # Save vault
            try:
                vault_bytes = create_vault(master_pass, entries)
                with open(VAULT_FILE, "wb") as f:
                    f.write(vault_bytes)
                print("✅ Login saved!")
            except Exception as e:
                print(f"❌ Save failed: {e}")

        elif choice == "2":
            if not entries:
                print("📭 No logins to display.")
            else:
                print("\n--- YOUR LOGINS ---")
                for i, e in enumerate(entries, 1):
                    print(f"{i}. Domain: {e['domain']}")
                    print(f"   Username: {e['username']}")
                    print(f"   Password: {e['password']}\n")
        elif choice == "3":
              while True:
                  search_domain = input("Enter domain to search (or 'q' to quit): ").strip()
                  if search_domain.lower() == 'q':
                      break
                  found = [e for e in entries if search_domain.lower() in e['domain'].lower()]
                  if not found:
                      print("🔍 No matching logins found.")
                  else:
                      print(f"\n--- FOUND {len(found)} LOGINS ---")
                      for i, e in enumerate(found, 1):
                          print(f"{i}. Domain: {e['domain']}")
                          print(f"   Username: {e['username']}")
                          print(f"   Password: {e['password']}\n")
        elif choice == "4":
            print("🔒 Goodbye!")
            break
        else:
            print("⚠️ Invalid option. Try again.")

if __name__ == "__main__":
    main()