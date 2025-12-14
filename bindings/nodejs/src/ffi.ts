/**
 * FFI bindings to native QUAC 100 library using koffi
 * @module ffi
 */

import * as koffi from 'koffi';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

/**
 * Find the native library path
 */
function findLibraryPath(): string {
    const platform = os.platform();
    const arch = os.arch();

    // Environment variable override
    const envPath = process.env['QUAC100_LIB_PATH'];
    if (envPath) {
        return envPath;
    }

    // Platform-specific paths
    const searchPaths: string[] = [];

    if (platform === 'win32') {
        searchPaths.push(
            'C:\\Program Files\\Dyber\\QUAC100\\bin\\quac100.dll',
            'C:\\Dyber\\bin\\quac100.dll',
            path.join(process.cwd(), 'quac100.dll'),
            path.join(__dirname, '..', 'native', 'win32', arch, 'quac100.dll')
        );
    } else if (platform === 'darwin') {
        searchPaths.push(
            '/opt/homebrew/lib/libquac100.dylib',
            '/usr/local/lib/libquac100.dylib',
            path.join(process.cwd(), 'libquac100.dylib'),
            path.join(__dirname, '..', 'native', 'darwin', arch, 'libquac100.dylib')
        );
    } else {
        // Linux
        searchPaths.push(
            '/usr/lib/libquac100.so',
            '/usr/local/lib/libquac100.so',
            '/opt/dyber/lib/libquac100.so',
            path.join(process.cwd(), 'libquac100.so'),
            path.join(__dirname, '..', 'native', 'linux', arch, 'libquac100.so')
        );
    }

    // Check if any path exists
    for (const p of searchPaths) {
        if (fs.existsSync(p)) {
            return p;
        }
    }

    // Return library name and let OS find it
    if (platform === 'win32') {
        return 'quac100.dll';
    } else if (platform === 'darwin') {
        return 'libquac100.dylib';
    } else {
        return 'libquac100.so';
    }
}

// Library instance (lazy loaded)
let _lib: koffi.IKoffiLib | null = null;

/**
 * Get the native library instance
 */
function getLibInstance(): koffi.IKoffiLib {
    if (_lib === null) {
        const libPath = findLibraryPath();
        _lib = koffi.load(libPath);
    }
    return _lib;
}

// Define function signatures
let _functions: NativeLib | null = null;

export interface NativeLib {
    quac_init: (flags: number) => number;
    quac_cleanup: () => number;
    quac_is_initialized: () => number;
    quac_get_version: () => string;
    quac_get_build_info: () => string;
    quac_get_device_count: () => number;
    quac_get_device_info: (index: number, info: Buffer) => number;
    quac_open_device: (index: number, handle: Buffer) => number;
    quac_close_device: (handle: Buffer) => number;
    quac_device_get_status: (handle: Buffer, status: Buffer) => number;
    quac_device_self_test: (handle: Buffer) => number;
    quac_device_reset: (handle: Buffer) => number;
    quac_kem_keygen: (handle: Buffer, algorithm: number, pk: Buffer, pkl: Buffer, sk: Buffer, skl: Buffer) => number;
    quac_kem_encapsulate: (handle: Buffer, algorithm: number, pk: Buffer, pkl: number, ct: Buffer, ctl: Buffer, ss: Buffer, ssl: Buffer) => number;
    quac_kem_decapsulate: (handle: Buffer, algorithm: number, sk: Buffer, skl: number, ct: Buffer, ctl: number, ss: Buffer, ssl: Buffer) => number;
    quac_sign_keygen: (handle: Buffer, algorithm: number, pk: Buffer, pkl: Buffer, sk: Buffer, skl: Buffer) => number;
    quac_sign: (handle: Buffer, algorithm: number, sk: Buffer, skl: number, msg: Buffer, msgl: number, sig: Buffer, sigl: Buffer) => number;
    quac_verify: (handle: Buffer, algorithm: number, pk: Buffer, pkl: number, msg: Buffer, msgl: number, sig: Buffer, sigl: number) => number;
    quac_hash: (handle: Buffer, algorithm: number, data: Buffer, datal: number, digest: Buffer, digestl: Buffer) => number;
    quac_hash_init: (handle: Buffer, algorithm: number, ctx: Buffer) => number;
    quac_hash_update: (ctx: Buffer, data: Buffer, datal: number) => number;
    quac_hash_final: (ctx: Buffer, digest: Buffer, digestl: Buffer) => number;
    quac_hash_free: (ctx: Buffer) => number;
    quac_hmac: (handle: Buffer, algorithm: number, key: Buffer, keyl: number, data: Buffer, datal: number, mac: Buffer, macl: Buffer) => number;
    quac_hkdf: (handle: Buffer, algorithm: number, ikm: Buffer, ikml: number, salt: Buffer, saltl: number, info: Buffer, infol: number, out: Buffer, outl: number) => number;
    quac_random_bytes: (handle: Buffer, buffer: Buffer, length: number) => number;
    quac_get_entropy_status: (handle: Buffer, status: Buffer) => number;
    quac_key_store: (handle: Buffer, slot: number, keyType: number, algorithm: number, usage: number, label: string, keyData: Buffer, keyDataLen: number) => number;
    quac_key_load: (handle: Buffer, slot: number, keyData: Buffer, keyDataLen: Buffer) => number;
    quac_key_get_info: (handle: Buffer, slot: number, info: Buffer) => number;
    quac_key_delete: (handle: Buffer, slot: number) => number;
    quac_key_list: (handle: Buffer, slots: Buffer, count: Buffer) => number;
    quac_key_get_slot_count: (handle: Buffer) => number;
    quac_key_get_free_slot: (handle: Buffer) => number;
    quac_key_clear_all: (handle: Buffer) => number;
}

/**
 * Get the native library functions
 */
export function getLib(): NativeLib {
    if (_functions === null) {
        const lib = getLibInstance();

        _functions = {
            // Library management
            quac_init: lib.func('int quac_init(uint32_t flags)'),
            quac_cleanup: lib.func('int quac_cleanup()'),
            quac_is_initialized: lib.func('int quac_is_initialized()'),
            quac_get_version: lib.func('const char* quac_get_version()'),
            quac_get_build_info: lib.func('const char* quac_get_build_info()'),

            // Device management
            quac_get_device_count: lib.func('int quac_get_device_count()'),
            quac_get_device_info: lib.func('int quac_get_device_info(uint32_t index, void* info)'),
            quac_open_device: lib.func('int quac_open_device(uint32_t index, void** handle)'),
            quac_close_device: lib.func('int quac_close_device(void* handle)'),
            quac_device_get_status: lib.func('int quac_device_get_status(void* handle, void* status)'),
            quac_device_self_test: lib.func('int quac_device_self_test(void* handle)'),
            quac_device_reset: lib.func('int quac_device_reset(void* handle)'),

            // KEM operations
            quac_kem_keygen: lib.func('int quac_kem_keygen(void* handle, int algo, void* pk, size_t* pkl, void* sk, size_t* skl)'),
            quac_kem_encapsulate: lib.func('int quac_kem_encapsulate(void* handle, int algo, void* pk, size_t pkl, void* ct, size_t* ctl, void* ss, size_t* ssl)'),
            quac_kem_decapsulate: lib.func('int quac_kem_decapsulate(void* handle, int algo, void* sk, size_t skl, void* ct, size_t ctl, void* ss, size_t* ssl)'),

            // Signature operations
            quac_sign_keygen: lib.func('int quac_sign_keygen(void* handle, int algo, void* pk, size_t* pkl, void* sk, size_t* skl)'),
            quac_sign: lib.func('int quac_sign(void* handle, int algo, void* sk, size_t skl, void* msg, size_t msgl, void* sig, size_t* sigl)'),
            quac_verify: lib.func('int quac_verify(void* handle, int algo, void* pk, size_t pkl, void* msg, size_t msgl, void* sig, size_t sigl)'),

            // Hash operations
            quac_hash: lib.func('int quac_hash(void* handle, int algo, void* data, size_t datal, void* digest, size_t* digestl)'),
            quac_hash_init: lib.func('int quac_hash_init(void* handle, int algo, void** ctx)'),
            quac_hash_update: lib.func('int quac_hash_update(void* ctx, void* data, size_t datal)'),
            quac_hash_final: lib.func('int quac_hash_final(void* ctx, void* digest, size_t* digestl)'),
            quac_hash_free: lib.func('int quac_hash_free(void* ctx)'),
            quac_hmac: lib.func('int quac_hmac(void* handle, int algo, void* key, size_t keyl, void* data, size_t datal, void* mac, size_t* macl)'),
            quac_hkdf: lib.func('int quac_hkdf(void* handle, int algo, void* ikm, size_t ikml, void* salt, size_t saltl, void* info, size_t infol, void* out, size_t outl)'),

            // Random operations
            quac_random_bytes: lib.func('int quac_random_bytes(void* handle, void* buffer, size_t length)'),
            quac_get_entropy_status: lib.func('int quac_get_entropy_status(void* handle, void* status)'),

            // Key storage
            quac_key_store: lib.func('int quac_key_store(void* handle, uint32_t slot, int keyType, int algo, uint32_t usage, const char* label, void* keyData, size_t keyDataLen)'),
            quac_key_load: lib.func('int quac_key_load(void* handle, uint32_t slot, void* keyData, size_t* keyDataLen)'),
            quac_key_get_info: lib.func('int quac_key_get_info(void* handle, uint32_t slot, void* info)'),
            quac_key_delete: lib.func('int quac_key_delete(void* handle, uint32_t slot)'),
            quac_key_list: lib.func('int quac_key_list(void* handle, uint32_t* slots, size_t* count)'),
            quac_key_get_slot_count: lib.func('int quac_key_get_slot_count(void* handle)'),
            quac_key_get_free_slot: lib.func('int quac_key_get_free_slot(void* handle)'),
            quac_key_clear_all: lib.func('int quac_key_clear_all(void* handle)'),
        };
    }

    return _functions;
}

/**
 * Create a pointer buffer (8 bytes for 64-bit)
 */
export function createPointer(): Buffer {
    return Buffer.alloc(8);
}

/**
 * Create a size_t buffer
 */
export function createSizeT(value: number = 0): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(BigInt(value), 0);
    return buf;
}

/**
 * Read size_t from buffer
 */
export function readSizeT(buf: Buffer): number {
    return Number(buf.readBigUInt64LE(0));
}

/**
 * Read pointer from buffer
 */
export function derefPointer(buf: Buffer): Buffer {
    // Return the buffer itself for koffi - it handles pointer dereferencing
    return buf;
}