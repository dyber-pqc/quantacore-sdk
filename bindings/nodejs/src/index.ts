/**
 * QuantaCore SDK for Node.js
 *
 * Provides bindings to the QUAC 100 Post-Quantum Cryptographic Accelerator.
 *
 * @packageDocumentation
 * @module @dyber/quantacore-sdk
 *
 * @example
 * ```typescript
 * import {
 *   initialize,
 *   cleanup,
 *   openFirstDevice,
 *   KemAlgorithm,
 *   SignAlgorithm
 * } from '@dyber/quantacore-sdk';
 *
 * // Initialize library
 * initialize();
 *
 * // Open device
 * const device = openFirstDevice();
 *
 * // Generate ML-KEM-768 key pair
 * const keypair = device.kem.generateKeypair(KemAlgorithm.MlKem768);
 *
 * // Encapsulate/decapsulate
 * const { ciphertext, sharedSecret } = device.kem.encapsulate(
 *   keypair.publicKey,
 *   KemAlgorithm.MlKem768
 * );
 * const decrypted = device.kem.decapsulate(
 *   keypair.secretKey,
 *   ciphertext,
 *   KemAlgorithm.MlKem768
 * );
 *
 * // Clean up
 * device.close();
 * cleanup();
 * ```
 */

import { getLib } from './ffi';
import { checkError } from './errors';
import { InitFlags } from './types';

// Re-export types
export * from './types';
export * from './errors';

// Re-export classes
export { Device, openDevice, openFirstDevice, getDeviceCount, enumerateDevices } from './device';
export { Kem } from './kem';
export { Sign } from './sign';
export { Hash, HashContext } from './hash';
export { Random } from './random';
export { Keys } from './keys';

// Library state
let _initialized = false;

/**
 * Initialize the QUAC 100 library
 * @param flags - Initialization flags (default: InitFlags.Default)
 */
export function initialize(flags: InitFlags = InitFlags.Default): void {
    if (_initialized) {
        return;
    }

    const lib = getLib();
    const result = lib.quac_init(flags);
    checkError(result);
    _initialized = true;
}

/**
 * Clean up the QUAC 100 library
 */
export function cleanup(): void {
    if (!_initialized) {
        return;
    }

    const lib = getLib();
    const result = lib.quac_cleanup();
    checkError(result);
    _initialized = false;
}

/**
 * Check if the library is initialized
 */
export function isInitialized(): boolean {
    return _initialized;
}

/**
 * Get the library version string
 */
export function getVersion(): string {
    const lib = getLib();
    return lib.quac_get_version();
}

/**
 * Get the library build information
 */
export function getBuildInfo(): string {
    const lib = getLib();
    return lib.quac_get_build_info();
}

/**
 * Using pattern for automatic cleanup
 *
 * @example
 * ```typescript
 * await using(() => {
 *   const device = openFirstDevice();
 *   // use device...
 * });
 * // Library automatically cleaned up
 * ```
 */
export async function using<T>(fn: () => T | Promise<T>): Promise<T> {
    initialize();
    try {
        return await fn();
    } finally {
        cleanup();
    }
}

/**
 * Convenience function to run with auto-cleanup
 */
export function withDevice<T>(fn: (device: import('./device').Device) => T): T {
    initialize();
    const { openFirstDevice } = require('./device');
    const device = openFirstDevice();
    try {
        return fn(device);
    } finally {
        device.close();
        cleanup();
    }
}

// Default export
export default {
    initialize,
    cleanup,
    isInitialized,
    getVersion,
    getBuildInfo,
    using,
    withDevice,
};