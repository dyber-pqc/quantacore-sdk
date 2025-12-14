/**
 * Basic usage example for QUAC 100 SDK
 */

import {
    initialize,
    cleanup,
    getVersion,
    getBuildInfo,
    getDeviceCount,
    enumerateDevices,
    openFirstDevice,
} from '../src';

async function main() {
    console.log('=== QUAC 100 SDK Basic Example ===\n');

    // Show version
    console.log(`Library Version: ${getVersion()}`);
    console.log(`Build Info: ${getBuildInfo()}\n`);

    // Initialize library
    console.log('Initializing library...');
    initialize();
    console.log('Library initialized.\n');

    // Enumerate devices
    const deviceCount = getDeviceCount();
    console.log(`Found ${deviceCount} device(s)\n`);

    if (deviceCount === 0) {
        console.log('No devices found. Please connect a QUAC 100 device.');
        cleanup();
        return;
    }

    // List all devices
    const devices = enumerateDevices();
    for (const info of devices) {
        console.log(`Device ${info.index}:`);
        console.log(`  Model: ${info.model}`);
        console.log(`  Serial: ${info.serialNumber}`);
        console.log(`  Firmware: ${info.firmwareVersion}`);
        console.log(`  Key Slots: ${info.keySlots}`);
        console.log();
    }

    // Open first device
    console.log('Opening first device...');
    const device = openFirstDevice();
    console.log('Device opened.\n');

    // Get device status
    const status = device.getStatus();
    console.log('Device Status:');
    console.log(`  Temperature: ${status.temperature}°C`);
    console.log(`  Entropy Level: ${status.entropyLevel}%`);
    console.log(`  Operations: ${status.operationsCount}`);
    console.log(`  Uptime: ${status.uptime}s`);
    console.log(`  Ready: ${status.isReady}`);
    console.log();

    // Run self-test
    console.log('Running self-test...');
    device.selfTest();
    console.log('Self-test passed!\n');

    // Clean up
    console.log('Closing device...');
    device.close();
    console.log('Device closed.\n');

    console.log('Cleaning up library...');
    cleanup();
    console.log('Done!');
}

main().catch(console.error);