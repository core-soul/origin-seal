#!/data/data/com.termux/files/usr/bin/bash
set -e

pkg update -y
pkg install clang libsodium -y

clang++ -O3 src/seal.cpp -o seal -lsodium
chmod +x seal

echo "[+] Build complete. Try:"
echo "    ./seal keygen keys"
