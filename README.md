# @qmoosa/pqc-slhdsa-engine

[![CI Gate](https://github.com/elon00/qmoosa-pqc-slhdsa-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-slhdsa-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — NIST FIPS 205 SLH-DSA Audited Stateless Hash-Based Digital Signature Engine & Invariant Verification.

## Overview

`@qmoosa/pqc-slhdsa-engine` delivers high-assurance, quantum-resistant digital signing and verification based on NIST FIPS 205 (SLH-DSA, formerly SPHINCS+).
Production cryptographic execution delegates directly to the audited `@noble/post-quantum/slh-dsa.js` primitive, while the pedagogical `reference-sphincs-math.ts` module preserves the underlying WOTS+ chain and Merkle hypertree mathematics.

## Features

- **Audited Cryptographic Core:** Uses `@noble/post-quantum/slh-dsa.js` (FIPS 205 compliant).
- **Multiple Parameter Sets:** Supports `SLH-DSA-SHA2-128s`, `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192s`, `SLH-DSA-SHA2-256s`, and `SLH-DSA-SHAKE-128s`.
- **Deterministic Seeding:** Supports reproducible keypair generation from 32-byte master seeds or exact $3 \times n$ raw seeds for KAT compliance.
- **Context Domain Separation:** Strict enforcement of FIPS 205 Section 5 context strings to prevent cross-protocol signature substitution attacks.
- **Defensive Invariant Validation:** Rejects tampered signatures, corrupted keys, altered payloads, and context mismatches.

## Installation & Testing

```bash
npm install
npm run build
npm test
npm run lint
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
