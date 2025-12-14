/**
 * Quantum Random Number Generation example
 */

import {
    initialize,
    cleanup,
    openFirstDevice,
} from '../src';

async function main() {
    console.log('=== Quantum Random Number Generation Example ===\n');

    // Initialize
    initialize();
    const device = openFirstDevice();
    const random = device.random;

    // Entropy status
    console.log('--- Entropy Status ---');
    const status = random.getEntropyStatus();
    console.log(`Level: ${status.level}%`);
    console.log(`Healthy: ${status.isHealthy ? '✓' : '✗'}`);
    console.log(`Bytes available: ${status.bytesAvailable}`);
    console.log();

    // Random bytes
    console.log('--- Random Bytes ---');
    console.log(`16 bytes: ${random.bytes(16).toString('hex')}`);
    console.log(`32 bytes: ${random.bytes(32).toString('hex')}`);
    console.log();

    // Integers
    console.log('--- Random Integers ---');
    console.log(`uint8:  ${random.uint8()}`);
    console.log(`uint16: ${random.uint16()}`);
    console.log(`uint32: ${random.uint32()}`);
    console.log(`uint64: ${random.uint64()}`);
    console.log(`int32:  ${random.int32()}`);
    console.log();

    // Bounded integers
    console.log('--- Bounded Integers ---');
    console.log(`[0, 100):  ${random.uint32Bounded(100)}`);
    console.log(`[1, 6]:    ${random.int(1, 6)} (dice roll)`);
    console.log(`[1, 100]:  ${random.int(1, 100)}`);
    console.log();

    // Floats
    console.log('--- Random Floats ---');
    console.log(`[0, 1):    ${random.float()}`);
    console.log(`[0, 1):    ${random.double()}`);
    console.log(`[10, 20):  ${random.uniform(10, 20)}`);
    console.log();

    // Booleans
    console.log('--- Random Booleans ---');
    const bools = Array.from({ length: 10 }, () => random.bool());
    console.log(`10 bools: ${bools.map(b => b ? '1' : '0').join('')}`);

    const biasedBools = Array.from({ length: 10 }, () => random.bool(0.8));
    console.log(`10 biased (80%): ${biasedBools.map(b => b ? '1' : '0').join('')}`);
    console.log();

    // UUIDs
    console.log('--- UUIDs ---');
    console.log(`UUID: ${random.uuid()}`);
    console.log(`UUID: ${random.uuid()}`);
    console.log(`UUID: ${random.uuid()}`);
    console.log();

    // String generation
    console.log('--- Random Strings ---');
    console.log(`Hex (16):       ${random.hex(16)}`);
    console.log(`Base64 (12):    ${random.base64(12)}`);
    console.log(`Alphanumeric:   ${random.alphanumeric(16)}`);
    console.log();

    // Array operations
    console.log('--- Array Operations ---');
    const items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    console.log(`Original:  [${items.join(', ')}]`);
    console.log(`Choice:    ${random.choice(items)}`);
    console.log(`Sample(3): [${random.sample(items, 3).join(', ')}]`);
    console.log(`Shuffled:  [${random.shuffled(items).join(', ')}]`);
    console.log();

    // Shuffle in place
    const deck = ['A', 'K', 'Q', 'J', '10'];
    console.log(`Before shuffle: [${deck.join(', ')}]`);
    random.shuffle(deck);
    console.log(`After shuffle:  [${deck.join(', ')}]`);
    console.log();

    // Distribution test
    console.log('--- Distribution Test (1000 dice rolls) ---');
    const counts = [0, 0, 0, 0, 0, 0];
    for (let i = 0; i < 1000; i++) {
        counts[random.int(1, 6) - 1]!++;
    }
    for (let i = 0; i < 6; i++) {
        const bar = '█'.repeat(Math.round(counts[i]! / 10));
        console.log(`  ${i + 1}: ${counts[i]!.toString().padStart(3)} ${bar}`);
    }
    console.log();

    // Performance test
    console.log('--- Performance ---');
    const iterations = 10000;
    const bytesPerIter = 32;

    const startTime = performance.now();
    for (let i = 0; i < iterations; i++) {
        random.bytes(bytesPerIter);
    }
    const endTime = performance.now();

    const totalTime = endTime - startTime;
    const throughput = (iterations * bytesPerIter) / (totalTime / 1000) / 1024;

    console.log(`Generated ${iterations * bytesPerIter} bytes in ${totalTime.toFixed(2)}ms`);
    console.log(`Throughput: ${throughput.toFixed(2)} KB/s`);
    console.log();

    // Clean up
    device.close();
    cleanup();
    console.log('Done!');
}

main().catch(console.error);