# Kryptos-C (`kryptos-c`)

A modular, zero-dependency **Encrypted CLI Credential & Secret Vault** written in pure C (`C11`). Kryptos protects sensitive credentials at rest using salted keystream encryption, DJB2 Master PIN authentication, FNV-1a file tamper detection, and automated password hygiene auditing.

## Key Security Features

* **Salted Master PIN Authentication & Lockout:** Verifies users against a salted DJB2 hash stored in the vault header (`KRYPTOS_HDR`) and enforces a 3-attempt brute-force lockout.
* **Symmetric Keystream Encryption at Rest:** Passwords are encrypted in memory via a salted stream cipher before touching `kryptos_vault.dat`—plaintext secrets are never written to disk.
* **File Integrity Verification (FNV-1a Checksum):** Computes a checksum across stored records to detect unauthorized external modifications to `kryptos_vault.dat`.
* **Secure Memory Zeroing (`secureWipe`):** Uses a `volatile` pointer wipe to scrub plaintext passwords and the active Master PIN from RAM upon deletion or exit.
* **Built-In Password Generator & Hygiene Auditor:** Generates 16-character high-entropy passwords, flags weak or reused credentials, computes a `0–100` Vault Security Score, and exports a redacted `kryptos_audit.txt` report.

## Repository Structure

```text
kryptos-c/
├── include/
│   └── kryptos.h            # Struct definitions & module interfaces
├── src/
│   ├── crypto.c             # Stream cipher, hashing, checksums & generator
│   ├── storage.c            # Encrypted file persistence & PIN verification
│   └── main.c               # CLI interface, CRUD & security audit engine
├── docs/
│   └── ARCHITECTURE.md      # System architecture & threat model
├── Makefile                 # Multi-file GCC build script
├── .gitignore               # Ignores binaries and local .dat files
└── README.md                # Project documentation
```

## Build & Run

### Using GCC (Windows / Linux / macOS)
```bash
gcc -Wall -Wextra -std=c11 -Iinclude src/main.c src/crypto.c src/storage.c -o kryptos
./kryptos
```

### Using Make
```bash
make
./kryptos
```

## Future Roadmap
* Upgrade stream cipher to **AES-256-GCM** and **Argon2id** key derivation.
* Add clipboard auto-clear timeout after copying credentials.

## Author
**Pragati Singhal** — B.Tech CSE (Cybersecurity), Bennett University