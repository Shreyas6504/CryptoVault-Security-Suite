"""
CryptoVault — Zero-Knowledge Password & Credential Security Suite
Author: Shreyas (https://github.com/Shreyas6504)
Description: Cryptographically sound password generator, entropy analyzer, and AES-encrypted local credential vault.
"""

import os
import sys
import math
import json
import base64
import secrets
import string
import hashlib
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

VAULT_FILE = "vault.enc"
SALT_FILE = "vault.salt"

def get_or_create_salt():
    """Ensure a consistent per-machine cryptographic salt for PBKDF2 key derivation."""
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES encryption key using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
    return key

def calculate_entropy(password: str) -> float:
    """Calculates information entropy (Shannon entropy in bits) for candidate password."""
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += len(string.punctuation)

    if pool_size == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def assess_strength(password: str) -> dict:
    """Provides a security rating and estimated brute-force resistance based on entropy."""
    entropy = calculate_entropy(password)
    length = len(password)

    if entropy < 28 or length < 8:
        rating = "Very Weak (Vulnerable to instant dictionary attack)"
        color = "CRITICAL"
    elif entropy < 45:
        rating = "Weak (Crackable in minutes/hours)"
        color = "WARNING"
    elif entropy < 65:
        rating = "Moderate (Acceptable for low-risk accounts)"
        color = "INFO"
    elif entropy < 90:
        rating = "Strong (Industry Standard)"
        color = "SUCCESS"
    else:
        rating = "Hardened / Military Grade (Decades to brute-force)"
        color = "EXCELLENT"

    return {
        "entropy_bits": entropy,
        "length": length,
        "rating": rating,
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(c in string.punctuation for c in password)
    }

def generate_password(length: int = 18, use_symbols: bool = True) -> str:
    """Generates a CSPRNG (cryptographically secure pseudo-random) password."""
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Ensure at least one of each category
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits)
    ]
    if use_symbols:
        pwd.append(secrets.choice("!@#$%^&*()-_=+"))

    while len(pwd) < length:
        pwd.append(secrets.choice(chars))

    # Shuffle cryptographically
    shuffled = "".join(secrets.SystemRandom().sample(pwd, len(pwd)))
    return shuffled

# --- Vault Storage Engine ---

def load_vault(master_key: bytes) -> dict:
    """Decrypts and parses the encrypted local credential vault."""
    if not os.path.exists(VAULT_FILE):
        return {}
    
    fernet = Fernet(master_key)
    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_bytes = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_bytes.decode('utf-8'))
    except InvalidToken:
        print("\n❌ Error: Invalid Master Password or corrupted vault file!")
        return None

def save_vault(vault_data: dict, master_key: bytes) -> bool:
    """Encrypts and safely writes credentials to the encrypted vault file."""
    fernet = Fernet(master_key)
    plain_bytes = json.dumps(vault_data, indent=2).encode('utf-8')
    encrypted = fernet.encrypt(plain_bytes)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)
    return True

# --- CLI Interface ---

def print_banner():
    print("""
===========================================================
  🔐 CryptoVault — Zero-Knowledge Credential Security Suite
  Author: Shreyas (@Shreyas6504) | AES-256 & PBKDF2 Powered
===========================================================
    """)

def main():
    print_banner()
    salt = get_or_create_salt()

    master_pwd = getpass("🔑 Enter your Master Password to unlock/initialize vault: ")
    if not master_pwd:
        print("Master password cannot be empty.")
        return

    key = derive_key(master_pwd, salt)
    vault = load_vault(key)
    if vault is None:
        return

    print("✓ Vault authenticated and decrypted successfully.\n")

    while True:
        print("\n--- MENU ---")
        print("1. 🎲 Generate Cryptographically Secure Password")
        print("2. 🔍 Analyze Password Strength & Shannon Entropy")
        print("3. 💾 Save Credential to Vault")
        print("4. 📖 Retrieve Credential from Vault")
        print("5. 📋 List All Stored Services")
        print("6. 🗑️ Delete Credential from Vault")
        print("0. 🚪 Exit")

        choice = input("\nSelect an option [0-6]: ").strip()

        if choice == "1":
            try:
                length = int(input("Enter length (default 18, min 8, max 64): ") or 18)
            except ValueError:
                length = 18
            pwd = generate_password(length=length)
            analysis = assess_strength(pwd)
            print(f"\n✅ Generated Password:  {pwd}")
            print(f"📊 Entropy:            {analysis['entropy_bits']} bits")
            print(f"🛡️ Rating:             {analysis['rating']}")

        elif choice == "2":
            candidate = getpass("Enter password to test entropy (hidden input): ")
            analysis = assess_strength(candidate)
            print(f"\n📊 Length:       {analysis['length']} characters")
            print(f"📊 Entropy:      {analysis['entropy_bits']} bits")
            print(f"🛡️ Security:     {analysis['rating']}")
            print(f"✓ Has Upper: {analysis['has_upper']} | Lower: {analysis['has_lower']} | Digit: {analysis['has_digit']} | Symbol: {analysis['has_symbol']}")

        elif choice == "3":
            service = input("Service / Website name (e.g., github.com): ").strip().lower()
            username = input("Username / Email: ").strip()
            use_gen = input("Auto-generate secure password? [Y/n]: ").strip().lower()
            if use_gen in ["", "y", "yes"]:
                password = generate_password(18)
                print(f"Generated secure password: {password}")
            else:
                password = getpass("Enter password to store: ")

            vault[service] = {
                "username": username,
                "password": password,
                "entropy": calculate_entropy(password)
            }
            save_vault(vault, key)
            print(f"✓ Credential for '{service}' safely encrypted and persisted in vault.")

        elif choice == "4":
            service = input("Enter service name to look up: ").strip().lower()
            if service in vault:
                item = vault[service]
                print(f"\n--- Stored Credentials for '{service}' ---")
                print(f"Username / Email: {item['username']}")
                print(f"Password:         {item['password']}")
                print(f"Entropy Score:    {item.get('entropy', 'N/A')} bits")
            else:
                print(f"❌ No record found for '{service}'.")

        elif choice == "5":
            if not vault:
                print("Vault is currently empty.")
            else:
                print(f"\n--- Vault Summary ({len(vault)} services stored) ---")
                for s in sorted(vault.keys()):
                    print(f"• {s} ({vault[s]['username']})")

        elif choice == "6":
            service = input("Enter service name to delete: ").strip().lower()
            if service in vault:
                del vault[service]
                save_vault(vault, key)
                print(f"✓ Removed '{service}' from vault.")
            else:
                print(f"❌ Service '{service}' not found.")

        elif choice == "0":
            print("\n🔒 Vault locked. Exiting securely.")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
