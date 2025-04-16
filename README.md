# Regulus: Authenticated Encryption

## 🚀 Overview

The goal of this project was to build a secure messaging system that provides **confidentiality** and **integrity** using authenticated encryption. The system is designed to prevent a powerful attacker from being able to read, modify, or replay messages, even with full control over the network.

All cryptographic operations are implemented using a minimal and secure set of primitives provided by the project harness. The project enforces careful design decisions around nonce management, key separation, and tamper detection.

## 🔒 Features

- **Authenticated Encryption (Encrypt-then-MAC):** Messages are encrypted and authenticated using AES-CTR and HMAC-SHA256.
- **Unique Nonce Generation:** Ensures nonces are never reused under the same key.
- **Replay Protection:** Rejects duplicated ciphertexts using a set of seen nonces.
- **Tampering Detection:** Automatically detects and rejects modified or truncated messages.

## 🛠️ Skills & Technologies Used

- **Programming Language:** Python 3.11+
- **Cryptography:** AES in CTR mode, HMAC-SHA256
- **Security Concepts:** 
  - Encrypt-then-MAC
  - Replay attack prevention
  - Message authentication codes (MACs)
  - Nonce management and key derivation
- **Testing:** Python `unittest` framework + fuzz testing

## 📁 Structure

- `crypto/`: Core cryptographic operations (encryption, MAC, key derivation)
- `regulus/`: Main message sender/receiver logic and client state tracking
- `tests/`: Unit tests and integration tests provided in the harness
- `Makefile`: Used for building and running the harness
- `README.md`: This file

## 🧪 How to Run

Make sure you are using Python 3.11+ and have all dependencies installed.

```bash
# Build the harness
make

# Run all tests
make test

