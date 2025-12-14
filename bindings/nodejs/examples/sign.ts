/**
 * ML-DSA (Dilithium) Digital Signature example
 */

import {
    initialize,
    cleanup,
    openFirstDevice,
    SignAlgorithm,
} from '../src';

async function main() {
    console.log('=== ML-DSA (Dilithium) Digital Signature Example ===\n');

    // Initialize
    initialize();
    const device = openFirstDevice();
    const sign = device.sign;

    const message = Buffer.from('Hello, quantum-safe world!');
    console.log(`Message: "${message.toString()}"\n`);

    // Test all signature variants
    const algorithms = [
        { algo: SignAlgorithm.MlDsa44, name: 'ML-DSA-44' },
        { algo: SignAlgorithm.MlDsa65, name: 'ML-DSA-65' },
        { algo: SignAlgorithm.MlDsa87, name: 'ML-DSA-87' },
    ];

    for (const { algo, name } of algorithms) {
        console.log(`--- ${name} ---`);

        // Generate key pair
        console.log('Generating key pair...');
        const startGen = performance.now();
        const keypair = sign.generateKeypair(algo);
        const genTime = performance.now() - startGen;

        console.log(`  Public key: ${keypair.publicKey.length} bytes`);
        console.log(`  Secret key: ${keypair.secretKey.length} bytes`);
        console.log(`  Time: ${genTime.toFixed(2)}ms`);

        // Sign
        console.log('Signing...');
        const startSign = performance.now();
        const signature = sign.sign(keypair.secretKey, message, algo);
        const signTime = performance.now() - startSign;

        console.log(`  Signature: ${signature.length} bytes`);
        console.log(`  Time: ${signTime.toFixed(2)}ms`);

        // Verify
        console.log('Verifying...');
        const startVerify = performance.now();
        const isValid = sign.verify(keypair.publicKey, message, signature, algo);
        const verifyTime = performance.now() - startVerify;

        console.log(`  Valid: ${isValid ? '✓' : '✗'}`);
        console.log(`  Time: ${verifyTime.toFixed(2)}ms`);

        // Test with tampered message
        const tamperedMessage = Buffer.from('Hello, quantum-safe world?');
        const tamperedValid = sign.verify(
            keypair.publicKey,
            tamperedMessage,
            signature,
            algo
        );
        console.log(`  Tampered message rejected: ${!tamperedValid ? '✓' : '✗'}`);

        if (!isValid) {
            console.error('ERROR: Valid signature verification failed!');
            process.exit(1);
        }

        console.log();
    }

    // Convenience method example
    console.log('--- Using Convenience Methods ---');
    const keypair65 = sign.generateKeypair65();
    const sig = sign.sign65(keypair65.secretKey, message);
    const valid = sign.verify65(keypair65.publicKey, message, sig);
    console.log(`Signature valid: ${valid ? '✓' : '✗'}\n`);

    // verifyOrThrow example
    console.log('--- Using verifyOrThrow ---');
    try {
        sign.verifyOrThrow(keypair65.publicKey, message, sig, SignAlgorithm.MlDsa65);
        console.log('Verification passed ✓');
    } catch (e) {
        console.log('Verification failed ✗');
    }

    try {
        const badMessage = Buffer.from('tampered');
        sign.verifyOrThrow(keypair65.publicKey, badMessage, sig, SignAlgorithm.MlDsa65);
        console.log('Should have thrown!');
    } catch (e) {
        console.log('Correctly threw on invalid signature ✓');
    }
    console.log();

    // Clean up
    device.close();
    cleanup();
    console.log('Done!');
}

main().catch(console.error);