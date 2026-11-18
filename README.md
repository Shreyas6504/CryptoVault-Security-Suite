# CryptoVault — Zero-Knowledge Credential Security Suite

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Security-AES--256%20Encryption-red?style=for-the-badge&logo=security&logoColor=white" alt="AES-256" />
  <img src="https://img.shields.io/badge/KDF-PBKDF2--HMAC--SHA256-orange?style=for-the-badge" alt="PBKDF2" />
  <img src="https://img.shields.io/badge/Architecture-Zero--Knowledge-green?style=for-the-badge" alt="Zero-Knowledge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" alt="MIT License" />
</p>

> **CryptoVault** is a privacy-first, zero-knowledge credential manager and password security suite built in Python. It provides mathematically robust password generation using CSPRNG entropy sources, Shannon information entropy evaluation, and local encrypted vault storage powered by PBKDF2 key derivation and AES-128/256-CBC authenticated encryption.

---

## 🔒 Security Architecture

1. **Zero-Knowledge Model:** Passwords are never stored in plain text. Only an encrypted binary blob (`vault.enc`) persists on disk.
2. **PBKDF2 Key Derivation:** Master passwords are never written to disk. Keys are dynamically generated at runtime via PBKDF2-HMAC-SHA256 with **200,000 computation rounds** and a cryptographically unique 16-byte random salt to prevent rainbow table attacks.
3. **CSPRNG Generation:** Passwords are created using the operating system's cryptographic entropy source (`secrets` / `SystemRandom`).
4. **Shannon Entropy Audit:** Calculates exact bits of entropy (\(E = L \times \log_2(R)\)) to warn users against weak patterns and dictionary attacks.

---

## 🌟 Key Features

- 🎲 **CSPRNG Password Generation:** Generates arbitrary-length, customizable alphanumeric and special-character passwords with guaranteed character diversity.
- 📊 **Shannon Information Entropy Analyzer:** Evaluates brute-force resistance across 5 security tiers (Very Weak to Hardened/Military-grade).
- 🗄️ **Authenticated Encrypted Storage:** AES-CBC symmetric encryption with HMAC validation (`Fernet`) ensures integrity against tampering.
- ⚡ **Interactive CLI Workspace:** Add, view, list, and delete credentials securely with hidden masked terminal input (`getpass`).

---

## 🚀 Getting Started

### Installation
```bash
git clone https://github.com/Shreyas6504/CryptoVault-Security-Suite.git
cd CryptoVault-Security-Suite
pip install -r requirements.txt
```

### Usage
```bash
python cryptovault.py
```

Follow the on-screen prompts to set your Master Password, generate passwords, and manage your vault.

---

## 👤 Author
**Shreyas**  
- GitHub: [@Shreyas6504](https://github.com/Shreyas6504)
