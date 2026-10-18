/**
 * QMOOSA Post-Quantum Cryptography — NIST FIPS 205 SLH-DSA Signature Engine
 *
 * Provides cryptographic signing, verification, and key generation for SLH-DSA
 * (formerly SPHINCS+), supporting SHA-2 and SHAKE instantiations.
 *
 * Production cryptographic execution delegates directly to the audited `@noble/post-quantum/slh-dsa.js`
 * library. Underlying WOTS+ and Merkle hypertree mathematics are preserved for pedagogical
 * verification in `reference-sphincs-math.ts`.
 */

import { randomBytes, createHmac } from 'node:crypto';
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128s
} from '@noble/post-quantum/slh-dsa.js';
import {
  SLH_DSA_SHA2_128S,
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHA2_192S,
  SLH_DSA_SHA2_256S,
  SLH_DSA_SHAKE_128S,
  getSlhDsaParameters,
  validatePublicKey,
  validateSecretKey,
  validateSignature,
  constantTimeEqual,
  type SlhDsaParameterName,
  type SlhDsaParameters,
  type SlhDsaKeyPair,
  type SlhDsaSignatureResult
} from '@qmoosa/pqc-slhdsa-protocol';

export * as ReferenceSphincsMath from './reference-sphincs-math.js';

export interface KeyGenOptions {
  /**
   * Deterministic seed for NIST FIPS 205 key generation.
   * Can be either a 32-byte master seed (expanded via HKDF-SHA256 to 3*n bytes)
   * or the exact 3*n byte raw seed (48 bytes for 128s/128f, 72 bytes for 192s, 96 bytes for 256s).
   */
  readonly seed?: Uint8Array;
}

export interface SignOptions {
  /**
   * Optional context string (max 255 bytes) for domain separation per NIST FIPS 205 Section 5.
   */
  readonly context?: Uint8Array | string;
  /**
   * Optional extra entropy (n bytes) for randomized signing per FIPS 205 Algorithm 17.
   */
  readonly extraEntropy?: Uint8Array;
}

export interface VerifyOptions {
  /**
   * Optional context string (max 255 bytes) for domain separation per NIST FIPS 205 Section 5.
   * MUST match the context string provided during signing.
   */
  readonly context?: Uint8Array | string;
}

function getNobleInstance(name: SlhDsaParameterName) {
  switch (name) {
    case 'SLH-DSA-SHA2-128s':
      return slh_dsa_sha2_128s;
    case 'SLH-DSA-SHA2-128f':
      return slh_dsa_sha2_128f;
    case 'SLH-DSA-SHA2-192s':
      return slh_dsa_sha2_192s;
    case 'SLH-DSA-SHA2-256s':
      return slh_dsa_sha2_256s;
    case 'SLH-DSA-SHAKE-128s':
      return slh_dsa_shake_128s;
    default:
      throw new Error(`UNSUPPORTED_SLH_DSA_PARAMETER_SET: ${name}`);
  }
}

function getRequiredSeedLength(name: SlhDsaParameterName): number {
  switch (name) {
    case 'SLH-DSA-SHA2-128s':
    case 'SLH-DSA-SHA2-128f':
    case 'SLH-DSA-SHAKE-128s':
      return 48; // 3 * 16 bytes
    case 'SLH-DSA-SHA2-192s':
      return 72; // 3 * 24 bytes
    case 'SLH-DSA-SHA2-256s':
      return 96; // 3 * 32 bytes
    default:
      return 48;
  }
}

function expandMasterSeed(masterSeed: Uint8Array, targetLength: number): Uint8Array {
  // Simple HKDF-Expand using HMAC-SHA256
  const prk = createHmac('sha256', Buffer.from('QMOOSA-FIPS205-SLH-DSA-SEED-KDF'))
    .update(Buffer.from(masterSeed))
    .digest();

  const out = Buffer.alloc(targetLength);
  let currentBlock = Buffer.alloc(0);
  let offset = 0;
  let counter = 1;

  while (offset < targetLength) {
    const hmac = createHmac('sha256', prk);
    hmac.update(currentBlock);
    hmac.update(Buffer.from('FIPS205_KEYGEN_SEED'));
    hmac.update(Buffer.from([counter++]));
    currentBlock = hmac.digest();
    const toCopy = Math.min(currentBlock.length, targetLength - offset);
    currentBlock.copy(out, offset, 0, toCopy);
    offset += toCopy;
  }

  return new Uint8Array(out);
}

function normalizeContext(context?: Uint8Array | string): Uint8Array | undefined {
  if (context === undefined) return undefined;
  let ctxBytes: Uint8Array;
  if (typeof context === 'string') {
    ctxBytes = new Uint8Array(Buffer.from(context, 'utf8'));
  } else if (context instanceof Uint8Array) {
    ctxBytes = context;
  } else {
    throw new Error('INVALID_CONTEXT_TYPE: Context must be a string or Uint8Array');
  }

  if (ctxBytes.length > 255) {
    throw new Error(`CONTEXT_TOO_LONG: FIPS 205 context string must be at most 255 bytes (got ${ctxBytes.length})`);
  }
  return ctxBytes;
}

export class SlhDsaEngine {
  /**
   * NIST FIPS 205 SLH-DSA Key Generation (Algorithm 13 / 16)
   * Generates a stateless hash-based digital signature key pair (pk, sk).
   */
  public generateKeyPair(
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options: KeyGenOptions = {}
  ): Readonly<SlhDsaKeyPair> {
    const params = getSlhDsaParameters(paramName);
    const noble = getNobleInstance(paramName);
    const reqSeedLen = getRequiredSeedLength(paramName);

    let seed: Uint8Array;
    if (options.seed !== undefined) {
      if (!(options.seed instanceof Uint8Array)) {
        throw new Error('INVALID_SEED_TYPE: Seed must be a Uint8Array');
      }
      if (options.seed.length === reqSeedLen) {
        seed = options.seed;
      } else if (options.seed.length === 32) {
        seed = expandMasterSeed(options.seed, reqSeedLen);
      } else {
        throw new Error(
          `INVALID_SEED_LENGTH: SLH-DSA seed must be either 32 bytes or ${reqSeedLen} bytes for ${paramName} (got ${options.seed.length})`
        );
      }
    } else {
      seed = new Uint8Array(randomBytes(reqSeedLen));
    }

    const { publicKey, secretKey } = noble.keygen(seed);

    if (!validatePublicKey(publicKey, params) || !validateSecretKey(secretKey, params)) {
      throw new Error('INTERNAL_KEY_VALIDATION_FAILURE: Generated keys do not match FIPS 205 byte lengths');
    }

    return Object.freeze({
      publicKey: new Uint8Array(publicKey),
      secretKey: new Uint8Array(secretKey),
      parameterSet: paramName
    });
  }

  /**
   * NIST FIPS 205 SLH-DSA Signing (Algorithm 14 / 17)
   * Signs message M using secret key sk and optional context string.
   */
  public sign(
    message: Uint8Array,
    secretKey: Uint8Array,
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options: SignOptions = {}
  ): Readonly<SlhDsaSignatureResult> {
    const params = getSlhDsaParameters(paramName);
    if (!validateSecretKey(secretKey, params)) {
      throw new Error(`INVALID_SECRET_KEY: Secret key length must be ${params.secretKeyBytes} bytes for ${paramName}`);
    }
    if (!(message instanceof Uint8Array)) {
      throw new Error('INVALID_MESSAGE_TYPE: Message must be a Uint8Array');
    }

    const context = normalizeContext(options.context);
    const noble = getNobleInstance(paramName);

    const nobleOpts: { context?: Uint8Array; extraEntropy?: Uint8Array } = {};
    if (context) nobleOpts.context = context;
    if (options.extraEntropy) nobleOpts.extraEntropy = options.extraEntropy;

    const signature = noble.sign(message, secretKey, nobleOpts);

    if (!validateSignature(signature, params)) {
      throw new Error('INTERNAL_SIGNATURE_VALIDATION_FAILURE: Output signature length does not match FIPS 205');
    }

    return Object.freeze({
      signature: new Uint8Array(signature),
      parameterSet: paramName
    });
  }

  /**
   * NIST FIPS 205 SLH-DSA Verification (Algorithm 15 / 18)
   * Verifies signature sigma on message M using public key pk and context string.
   * Returns true if valid, false if invalid or corrupted.
   */
  public verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
    paramName: SlhDsaParameterName = SLH_DSA_SHA2_128S.name,
    options: VerifyOptions = {}
  ): boolean {
    const params = getSlhDsaParameters(paramName);
    if (!validatePublicKey(publicKey, params)) {
      return false;
    }
    if (!validateSignature(signature, params)) {
      return false;
    }
    if (!(message instanceof Uint8Array)) {
      return false;
    }

    try {
      const context = normalizeContext(options.context);
      const noble = getNobleInstance(paramName);
      const nobleOpts: { context?: Uint8Array } = {};
      if (context) nobleOpts.context = context;

      return noble.verify(signature, message, publicKey, nobleOpts);
    } catch {
      return false;
    }
  }
}
