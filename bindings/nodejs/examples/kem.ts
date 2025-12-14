/**
 * ML-KEM (Kyber) Key Encapsulation example
 */

import {
    initialize,
    cleanup,
    openFirstDevice,
    KemAlgorithm,
} from '../src';

async function main() {
    console.log('=== ML-KEM (Kyber) Key Encapsulation Example ===\n');

    // Initialize
    initialize();
    const device = openFirstDevice();
    const kem = device.kem;

    // Test all KEM variants
    const algorithms = [
        { algo: KemAlgorithm.MlKem512, name: 'ML-KEM-512' },
        { algo: KemAlgorithm.MlKem768, name: 'ML-KEM-768' },
        { algo: KemAlgorithm.MlKem1024, name: 'ML-KEM-1024' },
    ];

    for (const { algo, name } of algorithms) {
        console.log(`--- ${name} ---`);

        // Generate key pair
        console.log('Generating key pair...');
        const startGen = performance.now();
        const keypair = kem.generateKeypair(algo);
        const genTime = performance.now() - startGen;

        console.log(`  Public key: ${keypair.publicKey.length} bytes`);
        console.log(`  Secret key: ${keypair.secretKey.length} bytes`);
        console.log(`  Time: ${genTime.toFixed(2)}ms`);

        // Encapsulate (sender side)
        console.log('Encapsulating...');
        const startEncap = performance.now();
        const { ciphertext, sharedSecret: senderSecret } = kem.encapsulate(
            keypair.publicKey,
            algo
        );
        const encapTime = performance.now() - startEncap;

        console.log(`  Ciphertext: ${ciphertext.length} bytes`);
        console.log(`  Shared secret: ${senderSecret.toString('hex').slice(0, 32)}...`);
        console.log(`  Time: ${encapTime.toFixed(2)}ms`);

        // Decapsulate (receiver side)
        console.log('Decapsulating...');
        const startDecap = performance.now();
        const receiverSecret = kem.decapsulate(keypair.secretKey, ciphertext, algo);
        const decapTime = performance.now() - startDecap;

        console.log(`  Shared secret: ${receiverSecret.toString('hex').slice(0, 32)}...`);
        console.log(`  Time: ${decapTime.toFixed(2)}ms`);

        // Verify secrets match
        const match = senderSecret.equals(receiverSecret);
        console.log(`  Secrets match: ${match ? '✓' : '✗'}`);

        if (!match) {
            console.error('ERROR: Shared secrets do not match!');
            process.exit(1);
        }

        console.log();
    }

    // Convenience method example
    console.log('--- Using Convenience Methods ---');
    const keypair768 = kem.generateKeypair768();
    const { ciphertext, sharedSecret } = kem.encapsulate768(keypair768.publicKey);
    const decrypted = kem.decapsulate768(keypair768.secretKey, ciphertext);
    console.log(`Secrets match: ${sharedSecret.equals(decrypted) ? '✓' : '✗'}\n`);

    // Clean up
    device.close();
    cleanup();
    console.log('Done!');
}

main().catch(console.error);