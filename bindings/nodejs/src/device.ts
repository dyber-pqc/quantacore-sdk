/**
 * QUAC 100 Device management
 * @module device
 */

import { getLib, createPointer, derefPointer } from './ffi';
import { checkError, QuacError, ErrorCode } from './errors';
import { DeviceInfo, DeviceStatus } from './types';
import { Kem } from './kem';
import { Sign } from './sign';
import { Hash } from './hash';
import { Random } from './random';
import { Keys } from './keys';

/**
 * QUAC 100 Device
 *
 * Represents a connection to a QUAC 100 hardware device.
 *
 * @example
 * ```typescript
 * const device = openFirstDevice();
 * const info = device.getInfo();
 * console.log(`Connected to ${info.model}`);
 *
 * // Use subsystems
 * const kem = device.kem;
 * const keypair = await kem.generateKeypair(KemAlgorithm.MlKem768);
 *
 * // Clean up
 * device.close();
 * ```
 */
export class Device {
    private handle: Buffer | null;
    private readonly _index: number;
    private _kem: Kem | null = null;
    private _sign: Sign | null = null;
    private _hash: Hash | null = null;
    private _random: Random | null = null;
    private _keys: Keys | null = null;

    constructor(handle: Buffer, index: number) {
        this.handle = handle;
        this._index = index;
    }

    /**
     * Get the device index
     */
    get index(): number {
        return this._index;
    }

    /**
     * Check if device is open
     */
    get isOpen(): boolean {
        return this.handle !== null;
    }

    /**
     * Get the raw handle (for internal use)
     */
    getHandle(): Buffer {
        if (!this.handle) {
            throw new QuacError(ErrorCode.InvalidState, 'Device is closed');
        }
        return this.handle;
    }

    /**
     * Close the device
     */
    close(): void {
        if (this.handle) {
            const lib = getLib();
            lib.quac_close_device(this.handle);
            this.handle = null;
            this._kem = null;
            this._sign = null;
            this._hash = null;
            this._random = null;
            this._keys = null;
        }
    }

    /**
     * Get device information
     */
    getInfo(): DeviceInfo {
        const handle = this.getHandle();
        const lib = getLib();

        // Allocate info struct buffer (256 bytes should be enough)
        const infoBuffer = Buffer.alloc(256);
        const result = lib.quac_get_device_info(this._index, infoBuffer);
        checkError(result);

        // Parse the struct
        return {
            index: this._index,
            model: infoBuffer.toString('utf8', 0, 64).replace(/\0/g, '').trim(),
            serialNumber: infoBuffer.toString('utf8', 64, 96).replace(/\0/g, '').trim(),
            firmwareVersion: infoBuffer.toString('utf8', 96, 112).replace(/\0/g, '').trim(),
            hardwareVersion: infoBuffer.toString('utf8', 112, 128).replace(/\0/g, '').trim(),
            keySlots: infoBuffer.readUInt32LE(128),
            maxOpsPerSecond: infoBuffer.readUInt32LE(132),
        };
    }

    /**
     * Get device status
     */
    getStatus(): DeviceStatus {
        const handle = this.getHandle();
        const lib = getLib();

        // Allocate status struct buffer
        const statusBuffer = Buffer.alloc(64);
        const result = lib.quac_device_get_status(handle, statusBuffer);
        checkError(result);

        // Parse the struct
        return {
            temperature: statusBuffer.readInt32LE(0),
            entropyLevel: statusBuffer.readUInt32LE(4),
            operationsCount: statusBuffer.readUInt32LE(8),
            uptime: statusBuffer.readUInt32LE(12),
            lastError: statusBuffer.readInt32LE(16),
            isReady: statusBuffer.readUInt8(20) !== 0,
        };
    }

    /**
     * Run self-test
     * @throws {QuacError} If self-test fails
     */
    selfTest(): void {
        const handle = this.getHandle();
        const lib = getLib();
        const result = lib.quac_device_self_test(handle);
        checkError(result);
    }

    /**
     * Reset the device
     */
    reset(): void {
        const handle = this.getHandle();
        const lib = getLib();
        const result = lib.quac_device_reset(handle);
        checkError(result);
    }

    /**
     * Get KEM operations interface
     */
    get kem(): Kem {
        if (!this._kem) {
            this._kem = new Kem(this);
        }
        return this._kem;
    }

    /**
     * Get signature operations interface
     */
    get sign(): Sign {
        if (!this._sign) {
            this._sign = new Sign(this);
        }
        return this._sign;
    }

    /**
     * Get hash operations interface
     */
    get hash(): Hash {
        if (!this._hash) {
            this._hash = new Hash(this);
        }
        return this._hash;
    }

    /**
     * Get random number generator interface
     */
    get random(): Random {
        if (!this._random) {
            this._random = new Random(this);
        }
        return this._random;
    }

    /**
     * Get key storage interface
     */
    get keys(): Keys {
        if (!this._keys) {
            this._keys = new Keys(this);
        }
        return this._keys;
    }
}

/**
 * Open a device by index
 * @param index - Device index (0-based)
 * @returns Device instance
 */
export function openDevice(index: number): Device {
    const lib = getLib();
    const handlePtr = createPointer();

    const result = lib.quac_open_device(index, handlePtr);
    checkError(result);

    const handle = derefPointer(handlePtr);
    return new Device(handle, index);
}

/**
 * Open the first available device
 * @returns Device instance
 */
export function openFirstDevice(): Device {
    const count = getDeviceCount();
    if (count === 0) {
        throw new QuacError(ErrorCode.DeviceNotFound, 'No QUAC 100 devices found');
    }
    return openDevice(0);
}

/**
 * Get the number of available devices
 */
export function getDeviceCount(): number {
    const lib = getLib();
    const count = lib.quac_get_device_count();
    return count < 0 ? 0 : count;
}

/**
 * Enumerate all available devices
 */
export function enumerateDevices(): DeviceInfo[] {
    const count = getDeviceCount();
    const devices: DeviceInfo[] = [];

    for (let i = 0; i < count; i++) {
        const lib = getLib();
        const infoBuffer = Buffer.alloc(256);
        const result = lib.quac_get_device_info(i, infoBuffer);

        if (result === 0) {
            devices.push({
                index: i,
                model: infoBuffer.toString('utf8', 0, 64).replace(/\0/g, '').trim(),
                serialNumber: infoBuffer.toString('utf8', 64, 96).replace(/\0/g, '').trim(),
                firmwareVersion: infoBuffer.toString('utf8', 96, 112).replace(/\0/g, '').trim(),
                hardwareVersion: infoBuffer.toString('utf8', 112, 128).replace(/\0/g, '').trim(),
                keySlots: infoBuffer.readUInt32LE(128),
                maxOpsPerSecond: infoBuffer.readUInt32LE(132),
            });
        }
    }

    return devices;
}
