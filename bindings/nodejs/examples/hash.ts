/**
 * Hardware-accelerated Hashing example
 */

import {
    initialize,
    cleanup,
    openFirstDevice,
    HashAlgorithm,
} from '../src';

async function main() {
    console.log('=== Hardware-Accelerated Hashing Example ===\n');

    // Initialize
    initialize();
    const device = openFirstDevice();
    const hash = device.hash;

    const data = Buffer.from('Hello, World!');
    console.log(`Data: "${data.toString()}"\n`);

    // SHA-2 family
    console.log('--- SHA-2 Family ---');
    console.log(`SHA-256:  ${hash.sha256(data).toString('hex')}`);
    console.log(`SHA-384:  ${hash.sha384(data).toString('hex')}`);
    console.log(`SHA-512:  ${hash.sha512(data).toString('hex')}`);
    console.log();

    // SHA-3 family
    console.log('--- SHA-3 Family ---');
    console.log(`SHA3-256: ${hash.sha3_256(data).toString('hex')}`);
    console.log(`SHA3-384: ${hash.sha3_384(data).toString('hex')}`);
    console.log(`SHA3-512: ${hash.sha3_512(data).toString('hex')}`);
    console.log();

    // SHAKE (XOF)
    console.log('--- SHAKE (XOF) ---');
    console.log(`SHAKE128 (32 bytes): ${hash.shake128(data, 32).toString('hex')}`);
    console.log(`SHAKE128 (64 bytes): ${hash.shake128(data, 64).toString('hex')}`);
    console.log(`SHAKE256 (32 bytes): ${hash.shake256(data, 32).toString('hex')}`);
    console.log();

    // Incremental hashing
    console.log('--- Incremental Hashing ---');
    const ctx = hash.createContext(HashAlgorithm.Sha256);
    ctx.update('Hello, ');
    ctx.update('World!');
    const incrementalDigest = ctx.finalize();

    const oneshotDigest = hash.sha256('Hello, World!');

    console.log(`Incremental: ${incrementalDigest.toString('hex')}`);
    console.log(`One-shot:    ${oneshotDigest.toString('hex')}`);
    console.log(`Match: ${incrementalDigest.equals(oneshotDigest) ? '✓' : '✗'}`);
    console.log();

    // HMAC
    console.log('--- HMAC ---');
    const key = Buffer.from('secret-key');
    const message = Buffer.from('message to authenticate');

    console.log(`HMAC-SHA256: ${hash.hmacSha256(key, message).toString('hex')}`);
    console.log(`HMAC-SHA384: ${hash.hmacSha384(key, message).toString('hex')}`);
    console.log(`HMAC-SHA512: ${hash.hmacSha512(key, message).toString('hex')}`);
    console.log();

    // HKDF
    console.log('--- HKDF Key Derivation ---');
    const ikm = Buffer.from('input keying material');
    const salt = Buffer.from('salt');
    const info = Buffer.from('context info');

    const derived32 = hash.hkdfSha256(ikm, salt, info, 32);
    const derived64 = hash.hkdfSha256(ikm, salt, info, 64);

    console.log(`HKDF-SHA256 (32 bytes): ${derived32.toString('hex')}`);
    console.log(`HKDF-SHA256 (64 bytes): ${derived64.toString('hex')}`);
    console.log(`First 32 bytes match: ${derived32.equals(derived64.subarray(0, 32)) ? '✓' : '✗'}`);
    console.log();

    // Performance test
    console.log('--- Performance ---');
    const largeData = Buffer.alloc(1024 * 1024); // 1MB
    const iterations = 100;

    const startTime = performance.now();
    for (let i = 0; i < iterations; i++) {
        hash.sha256(largeData);
    }
    const endTime = performance.now();

    const totalTime = endTime - startTime;
    const throughput = (iterations * largeData.length) / (totalTime / 1000) / (1024 * 1024);

    console.log(`SHA-256: ${iterations} x 1MB in ${totalTime.toFixed(2)}ms`);
    console.log(`Throughput: ${throughput.toFixed(2)} MB/s`);
    console.log();

    // Clean up
    device.close();
    cleanup();
    console.log('Done!');
}

main().catch(console.error);