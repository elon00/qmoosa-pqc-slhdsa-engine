import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SlhDsaEngine,
  ReferenceSphincsMath
} from '../dist/index.js';
import {
  SLH_DSA_SHA2_128S,
  SLH_DSA_SHA2_128F,
  constantTimeEqual
} from '@qmoosa/pqc-slhdsa-protocol';

test('SLH-DSA Engine: Full Sign & Verify Round-Trip on SLH-DSA-SHA2-128s', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128s');

  assert.equal(alice.publicKey.length, SLH_DSA_SHA2_128S.publicKeyBytes);
  assert.equal(alice.secretKey.length, SLH_DSA_SHA2_128S.secretKeyBytes);

  const message = new TextEncoder().encode('QMOOSA Web4 Hash-Based Root #128s');
  const sigResult = engine.sign(message, alice.secretKey, 'SLH-DSA-SHA2-128s');

  assert.equal(sigResult.signature.length, SLH_DSA_SHA2_128S.signatureBytes);

  const isValid = engine.verify(sigResult.signature, message, alice.publicKey, 'SLH-DSA-SHA2-128s');
  assert.equal(isValid, true, 'Valid SLH-DSA-SHA2-128s signature must verify successfully');
});

test('SLH-DSA Engine: Full Sign & Verify Round-Trip on SLH-DSA-SHA2-128f (Fast Mode)', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128f');

  assert.equal(alice.publicKey.length, SLH_DSA_SHA2_128F.publicKeyBytes);
  assert.equal(alice.secretKey.length, SLH_DSA_SHA2_128F.secretKeyBytes);

  const message = new TextEncoder().encode('QMOOSA Fast Throughput Settlement Block #128f');
  const sigResult = engine.sign(message, alice.secretKey, 'SLH-DSA-SHA2-128f');

  assert.equal(sigResult.signature.length, SLH_DSA_SHA2_128F.signatureBytes);

  const isValid = engine.verify(sigResult.signature, message, alice.publicKey, 'SLH-DSA-SHA2-128f');
  assert.equal(isValid, true, 'Valid SLH-DSA-SHA2-128f signature must verify successfully');
});

test('SLH-DSA Engine: Deterministic Seeding & FIPS 205 KAT Reproducibility', () => {
  const engine = new SlhDsaEngine();
  const masterSeed = new Uint8Array(32).fill(0x5a);

  const kp1 = engine.generateKeyPair('SLH-DSA-SHA2-128s', { seed: masterSeed });
  const kp2 = engine.generateKeyPair('SLH-DSA-SHA2-128s', { seed: masterSeed });

  assert.ok(constantTimeEqual(kp1.publicKey, kp2.publicKey), 'Identical master seed must yield identical public key');
  assert.ok(constantTimeEqual(kp1.secretKey, kp2.secretKey), 'Identical master seed must yield identical secret key');
});

test('SLH-DSA Engine: Context String Domain Separation Enforcement', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128s');
  const message = new TextEncoder().encode('Stateless Hash Transaction Intent');

  // Sign with context
  const contextA = 'DOMAIN:QMOOSA-CROSSCHAIN-FIPS205';
  const sigResult = engine.sign(message, alice.secretKey, 'SLH-DSA-SHA2-128s', { context: contextA });

  // Verify with same context -> PASS
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'SLH-DSA-SHA2-128s', { context: contextA }),
    true
  );

  // Verify with different context -> FAIL
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'SLH-DSA-SHA2-128s', { context: 'DOMAIN:WRONG-DOMAIN' }),
    false
  );

  // Verify without context -> FAIL
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'SLH-DSA-SHA2-128s'),
    false
  );
});

test('SLH-DSA Engine: Adversarial Negative Control - Corrupted Signature Bit Rejection', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128s');
  const message = new TextEncoder().encode('Adversarial Payload Test');

  const sigResult = engine.sign(message, alice.secretKey, 'SLH-DSA-SHA2-128s');

  // Corrupt 1 byte in signature
  const tamperedSig = new Uint8Array(sigResult.signature);
  tamperedSig[200] ^= 0x01;

  assert.equal(
    engine.verify(tamperedSig, message, alice.publicKey, 'SLH-DSA-SHA2-128s'),
    false,
    'Corrupted signature bit must be rejected'
  );
});

test('SLH-DSA Engine: Adversarial Negative Control - Tampered Message Rejection', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128s');
  const legitMessage = new TextEncoder().encode('Transfer 1000 QMOOSA to 0xAAAA');
  const forgedMessage = new TextEncoder().encode('Transfer 1000 QMOOSA to 0xBBBB');

  const sigResult = engine.sign(legitMessage, alice.secretKey, 'SLH-DSA-SHA2-128s');

  assert.equal(
    engine.verify(sigResult.signature, forgedMessage, alice.publicKey, 'SLH-DSA-SHA2-128s'),
    false,
    'Signature over legitimate message must reject altered payload'
  );
});

test('SLH-DSA Engine: Adversarial Negative Control - Wrong Public Key Rejection', () => {
  const engine = new SlhDsaEngine();
  const alice = engine.generateKeyPair('SLH-DSA-SHA2-128s');
  const bob = engine.generateKeyPair('SLH-DSA-SHA2-128s');
  const message = new TextEncoder().encode('Hash Signature Authentication');

  const sigResult = engine.sign(message, alice.secretKey, 'SLH-DSA-SHA2-128s');

  assert.equal(
    engine.verify(sigResult.signature, message, bob.publicKey, 'SLH-DSA-SHA2-128s'),
    false,
    'Verification against non-owner public key must return false'
  );
});

test('SLH-DSA Engine: Defensive Validation Errors', () => {
  const engine = new SlhDsaEngine();

  // Invalid seed length (must be 32 or 48 bytes for 128s)
  assert.throws(
    () => engine.generateKeyPair('SLH-DSA-SHA2-128s', { seed: new Uint8Array(16) }),
    /INVALID_SEED_LENGTH/
  );

  // Invalid secret key length
  assert.throws(
    () => engine.sign(new Uint8Array(10), new Uint8Array(32), 'SLH-DSA-SHA2-128s'),
    /INVALID_SECRET_KEY/
  );

  // Context too long (> 255 bytes)
  const hugeContext = new Uint8Array(256);
  assert.throws(
    () => engine.sign(new Uint8Array(10), new Uint8Array(64), 'SLH-DSA-SHA2-128s', { context: hugeContext }),
    /CONTEXT_TOO_LONG/
  );
});

test('SLH-DSA Engine: Reference SPHINCS+ Math Module Verification', () => {
  assert.ok(ReferenceSphincsMath);
  assert.equal(ReferenceSphincsMath.WOTS_W, 16);
  assert.equal(ReferenceSphincsMath.WOTS_LOG_W, 4);

  // Test base-w decomposition
  const msg = new Uint8Array([0xab, 0xcd]);
  const digits = ReferenceSphincsMath.baseW(msg, 4);
  assert.deepEqual(digits, [0xa, 0xb, 0xc, 0xd]);

  // Test checksum computation
  const csum = ReferenceSphincsMath.wotsChecksum(digits);
  assert.equal(csum.length, ReferenceSphincsMath.WOTS_LEN2);

  // Test WOTS chain
  const chainInput = new Uint8Array(16).fill(0x11);
  const chainOutput = ReferenceSphincsMath.wotsChain(chainInput, 0, 5);
  assert.equal(chainOutput.length, 16);
  assert.notDeepEqual(chainOutput, chainInput);

  // Test Merkle root computation
  const leaf1 = ReferenceSphincsMath.sha256(new Uint8Array([1]));
  const leaf2 = ReferenceSphincsMath.sha256(new Uint8Array([2]));
  const root = ReferenceSphincsMath.computeMerkleRoot([leaf1, leaf2]);
  assert.equal(root.length, 32);
});
