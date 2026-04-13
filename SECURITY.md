# Security Policy / Notes (Origin-Seal)

## What this tool guarantees
Origin-Seal provides:
- **Integrity proof** (SHA-256): detects file tampering/changes.
- **Authorship proof** (Ed25519 signatures): proves the capsule was signed by the key owner.

## What this tool does NOT guarantee
- **Trusted timestamp**: device time can be spoofed.
- **Truth of content**: it proves a file did not change, not that the content is “true”.
- **Confidentiality**: capsules are not encryption; do not store secrets in notes.

## Key handling (IMPORTANT)
- Never commit or upload your secret key:
  - `keys/seal_sk.key`
- If the secret key leaks, generate a new keypair:
  - `./seal keygen keys`

## Reporting issues
If you find a security issue, open a GitHub Issue with a minimal reproduction.
Do not publish private keys or sensitive data in issues.
