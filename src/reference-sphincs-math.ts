/**
 * QMOOSA Post-Quantum Cryptography — Educational Mathematical Reference
 * NIST FIPS 205 SLH-DSA / SPHINCS+ Underlying Hash Architecture
 *
 * NOTE: For production signing and verification, use SlhDsaEngine which delegates
 * directly to the audited `@noble/post-quantum/slh-dsa.js` implementation.
 * This module demonstrates the mathematical structures (WOTS+ hash chains,
 * base-w digit decomposition, and Merkle tree root authentication).
 */

import { createHash } from 'node:crypto';

export const WOTS_W = 16;
export const WOTS_LOG_W = 4;
export const WOTS_LEN1 = 32; // for 16-byte hash digest (SHA-256 truncated to 16 bytes)
export const WOTS_LEN2 = 3;  // checksum digits in base 16
export const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

/**
 * SHA-256 helper
 */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Evaluates a WOTS+ hash chain from step 'start' to 'steps' iterations.
 * c^i(x) = H(c^{i-1}(x) || pubSeed || adrs)
 */
export function wotsChain(
  input: Uint8Array,
  startStep: number,
  steps: number,
  pubSeed: Uint8Array = new Uint8Array(16)
): Uint8Array {
  let out = new Uint8Array(input);
  for (let i = startStep; i < startStep + steps && i < WOTS_W; i++) {
    const preimage = new Uint8Array(out.length + pubSeed.length + 4);
    preimage.set(out, 0);
    preimage.set(pubSeed, out.length);
    preimage[preimage.length - 1] = i;
    const h = sha256(preimage);
    out = new Uint8Array(h.subarray(0, out.length));
  }
  return out;
}

/**
 * Converts a byte array into base-w (w=16) digits for WOTS+ signing.
 */
export function baseW(msg: Uint8Array, outLen: number): number[] {
  const base: number[] = [];
  let inIdx = 0;
  let total = 0;
  let bits = 0;

  for (let consumed = 0; consumed < outLen; consumed++) {
    if (bits === 0) {
      total = inIdx < msg.length ? msg[inIdx++] : 0;
      bits += 8;
    }
    bits -= WOTS_LOG_W;
    base.push((total >>> bits) & (WOTS_W - 1));
  }
  return base;
}

/**
 * Computes WOTS+ checksum digits over base-w message digits.
 */
export function wotsChecksum(digits: number[]): number[] {
  let csum = 0;
  for (const d of digits) {
    csum += WOTS_W - 1 - d;
  }
  // csum converted to base-w
  const csumBytes = new Uint8Array([
    (csum >>> 8) & 0xff,
    csum & 0xff
  ]);
  return baseW(csumBytes, WOTS_LEN2);
}

/**
 * Computes root of a complete binary Merkle tree over leaf hashes.
 */
export function computeMerkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error('Merkle tree must contain at least 1 leaf');
  }
  let currentLayer: Uint8Array[] = leaves.map(l => new Uint8Array(l));
  while (currentLayer.length > 1) {
    if (currentLayer.length % 2 !== 0) {
      currentLayer.push(currentLayer[currentLayer.length - 1]);
    }
    const nextLayer: Uint8Array[] = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const combined = new Uint8Array(currentLayer[i].length + currentLayer[i + 1].length);
      combined.set(currentLayer[i], 0);
      combined.set(currentLayer[i + 1], currentLayer[i].length);
      const parent = sha256(combined);
      nextLayer.push(parent);
    }
    currentLayer = nextLayer;
  }
  return currentLayer[0];
}
