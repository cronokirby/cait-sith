# 0.8.0

- Added an extra requirement to Curve API for constant-time scalar sampling

# 0.7.0

- Remove triple setup interface, always doing a fresh setup, for security reasons.
- Fix various security bugs.
- Update dependencies.

# 0.6.0

- Modify specification to use a single threshold (turns out the code accidentally enforced this already)
- Modify code to match simplified presigning protocol because of this threshold.
- Modify specification to pre-commit to C polynomial in triple generation.
- Modify code accordingly.

# 0.5.0

- Modify specification & implementation to use perfectly hiding commitments.
- Update dependencies to recent Rust-Crypto ECDSA versions.
- Support arbitrary curves and message hashes.
- Add curve description (name) to transcript in keysharing and triple generation.

# 0.4.0

- Added key refresh and resharing protocols.
