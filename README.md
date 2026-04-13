# ORIGIN-SEAL (MVP)
**Offline Proof Capsule Generator** — build research-grade integrity proofs on Android/Termux.

Origin-Seal creates a signed `.seal` capsule for any file:
- Detects tampering (SHA-256 integrity)
- Proves authorship (Ed25519 signatures via libsodium)
- Works offline (no server required)

## Build (Termux)
```bash
pkg install clang libsodium -y
clang++ -O3 src/seal.cpp -o seal -lsodium

Usage
1) Generate keys
Bash

./seal keygen keys
2) Create a capsule
Bash

./seal make keys note.txt "experiment#1 baseline" proof.seal
3) Verify later (offline)
Bash

./seal verify note.txt proof.seal

If the file changes by even 1 byte, verification fails.

Capsule format (v1)
Human-readable text fields + base64 pubkey/signature.

Roadmap
ledger mode (append-only chain of capsules)
multi-witness signing (quorum proofs)
QR export/import for airgapped sharing



### 2) `setup.sh`
`nano setup.sh` → paste:

```bash
#!/data/data/com.termux/files/usr/bin/bash
set -e

pkg update -y
pkg install clang libsodium -y

clang++ -O3 src/seal.cpp -o seal -lsodium
chmod +x seal

echo "[+] Build complete. Try:"
echo "    ./seal keygen keys"


Then:

Bash

chmod +x setup.sh



