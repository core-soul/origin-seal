#include <sodium.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>
#include <ctime>

static std::string read_file_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
}

static bool sha256_file_hex(const std::string& path, std::string& out_hex) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);

    char buf[8192];
    while (in.good()) {
        in.read(buf, sizeof(buf));
        std::streamsize n = in.gcount();
        if (n > 0) crypto_hash_sha256_update(&st, (const unsigned char*)buf, (unsigned long long)n);
    }

    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&st, digest);

    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), digest, sizeof(digest));
    out_hex = hex;
    return true;
}

static std::string b64(const unsigned char* bin, size_t len) {
    size_t b64_len = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(b64_len, '\0');
    sodium_bin2base64(out.data(), out.size(), bin, len, sodium_base64_VARIANT_ORIGINAL);
    // remove trailing '\0' or newline-like padding space
    while (!out.empty() && (out.back() == '\0')) out.pop_back();
    return out;
}

static bool b64dec(const std::string& s, unsigned char* bin, size_t bin_max, size_t& bin_len) {
    if (s.empty()) return false;
    if (sodium_base642bin(bin, bin_max, s.c_str(), s.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return false;
    }
    return true;
}

static std::string canonical_message_v1(const std::string& file_sha256_hex,
                                        long long unix_time,
                                        const std::string& note) {
    // simple canonical format (stable across platforms)
    // IMPORTANT: keep this exact order for v1
    std::string msg;
    msg += "origin-seal-v1\n";
    msg += "sha256:" + file_sha256_hex + "\n";
    msg += "time:" + std::to_string(unix_time) + "\n";
    msg += "note:" + note + "\n";
    return msg;
}

static void usage() {
    std::cout <<
R"(Origin-Seal (MVP)
Commands:
  seal keygen <keydir>
  seal make   <keydir> <file> <note> <out.seal>
  seal verify <file> <capsule.seal>

Examples:
  ./seal keygen keys
  ./seal make keys secret.txt "experiment#1 result" proof.seal
  ./seal verify secret.txt proof.seal
)";
}

static bool write_text(const std::string& path, const std::string& s) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(s.data(), (std::streamsize)s.size());
    return true;
}

static std::string trim_newlines(std::string s) {
    while (!s.empty() && (s.back()=='\n' || s.back()=='\r')) s.pop_back();
    return s;
}

static bool read_line_kv(std::ifstream& in, std::string& key, std::string& val) {
    std::string line;
    if (!std::getline(in, line)) return false;
    line = trim_newlines(line);
    auto pos = line.find(':');
    if (pos == std::string::npos) return false;
    key = line.substr(0, pos);
    val = line.substr(pos + 1);
    // remove one leading space if present
    if (!val.empty() && val[0] == ' ') val.erase(0, 1);
    return true;
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];

    if (cmd == "keygen") {
        if (argc != 3) { usage(); return 1; }
        std::string keydir = argv[2];
        std::string sk_path = keydir + "/seal_sk.key";
        std::string pk_path = keydir + "/seal_pk.key";

        // create dir
        std::string mk = "mkdir -p " + keydir;
        std::system(mk.c_str());

        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);

        if (!write_text(sk_path, b64(sk, sizeof(sk)))) { std::cerr << "write sk failed\n"; return 1; }
        if (!write_text(pk_path, b64(pk, sizeof(pk)))) { std::cerr << "write pk failed\n"; return 1; }

        std::cout << "[+] Keypair generated in: " << keydir << "\n";
        std::cout << "    Public:  " << pk_path << "\n";
        std::cout << "    Secret:  " << sk_path << "\n";
        return 0;
    }

    if (cmd == "make") {
        if (argc != 6) { usage(); return 1; }
        std::string keydir = argv[2];
        std::string file = argv[3];
        std::string note = argv[4];
        std::string out_seal = argv[5];

        std::string sk_b64 = read_file_all(keydir + "/seal_sk.key");
        sk_b64 = trim_newlines(sk_b64);
        if (sk_b64.empty()) { std::cerr << "Secret key not found.\n"; return 1; }

        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        size_t sk_len = 0;
        if (!b64dec(sk_b64, sk, sizeof(sk), sk_len) || sk_len != sizeof(sk)) {
            std::cerr << "Secret key decode failed.\n";
            return 1;
        }

        std::string sha_hex;
        if (!sha256_file_hex(file, sha_hex)) {
            std::cerr << "Cannot read file: " << file << "\n";
            return 1;
        }

        long long t = (long long)std::time(nullptr);
        std::string msg = canonical_message_v1(sha_hex, t, note);

        unsigned char sig[crypto_sign_BYTES];
        unsigned long long siglen = 0;
        crypto_sign_detached(sig, &siglen, (const unsigned char*)msg.data(), (unsigned long long)msg.size(), sk);

        // also store public key derived from sk (libsodium stores pk inside sk)
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        crypto_sign_ed25519_sk_to_pk(pk, sk);

        // Capsule format (human-readable, no JSON libs needed)
        std::string capsule;
        capsule += "origin-seal: v1\n";
        capsule += "file_sha256: " + sha_hex + "\n";
        capsule += "time_unix: " + std::to_string(t) + "\n";
        capsule += "note: " + note + "\n";
        capsule += "pubkey_b64: " + b64(pk, sizeof(pk)) + "\n";
        capsule += "sig_b64: " + b64(sig, (size_t)siglen) + "\n";

        if (!write_text(out_seal, capsule)) {
            std::cerr << "Write failed: " << out_seal << "\n";
            return 1;
        }

        std::cout << "[+] Capsule created: " << out_seal << "\n";
        return 0;
    }

    if (cmd == "verify") {
        if (argc != 4) { usage(); return 1; }
        std::string file = argv[2];
        std::string seal = argv[3];

        std::ifstream in(seal);
        if (!in) { std::cerr << "Cannot open capsule: " << seal << "\n"; return 1; }

        // read first line
        std::string first;
        std::getline(in, first);
        first = trim_newlines(first);
        if (first != "origin-seal: v1") {
            std::cerr << "Unsupported capsule format.\n";
            return 1;
        }

        std::string file_sha, time_unix, note, pk_b64, sig_b64;

        for (int i = 0; i < 5; i++) {
            std::string k, v;
            if (!read_line_kv(in, k, v)) { std::cerr << "Capsule parse error.\n"; return 1; }
            if (k == "file_sha256") file_sha = v;
            else if (k == "time_unix") time_unix = v;
            else if (k == "note") note = v;
            else if (k == "pubkey_b64") pk_b64 = v;
            else if (k == "sig_b64") sig_b64 = v;
        }

        std::string sha_hex_now;
        if (!sha256_file_hex(file, sha_hex_now)) {
            std::cerr << "Cannot read file: " << file << "\n";
            return 1;
        }

        if (sha_hex_now != file_sha) {
            std::cerr << "[-] FAIL: File hash mismatch (file changed)\n";
            std::cerr << "    expected: " << file_sha << "\n";
            std::cerr << "    got:      " << sha_hex_now << "\n";
            return 2;
        }

        // rebuild canonical message
        long long t = std::stoll(time_unix);
        std::string msg = canonical_message_v1(file_sha, t, note);

        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sig[crypto_sign_BYTES];
        size_t pk_len = 0, sig_len = 0;

        if (!b64dec(pk_b64, pk, sizeof(pk), pk_len) || pk_len != sizeof(pk)) {
            std::cerr << "Public key decode failed.\n"; return 1;
        }
        if (!b64dec(sig_b64, sig, sizeof(sig), sig_len) || sig_len != crypto_sign_BYTES) {
            std::cerr << "Signature decode failed.\n"; return 1;
        }

        if (crypto_sign_verify_detached(sig, (const unsigned char*)msg.data(),
                                        (unsigned long long)msg.size(), pk) != 0) {
            std::cerr << "[-] FAIL: Signature invalid\n";
            return 3;
        }

        std::cout << "[+] OK: Capsule is valid\n";
        std::cout << "    sha256: " << file_sha << "\n";
        std::cout << "    time:   " << time_unix << "\n";
        std::cout << "    note:   " << note << "\n";
        return 0;
    }

    usage();
    return 1;
}
