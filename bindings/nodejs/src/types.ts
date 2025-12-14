/**
 * Type definitions for QUAC 100 SDK
 * @module types
 */

/** Key Encapsulation Mechanism algorithms */
export enum KemAlgorithm {
    /** ML-KEM-512 (128-bit security) */
    MlKem512 = 0,
    /** ML-KEM-768 (192-bit security) */
    MlKem768 = 1,
    /** ML-KEM-1024 (256-bit security) */
    MlKem1024 = 2,
}

/** Digital Signature algorithms */
export enum SignAlgorithm {
    /** ML-DSA-44 (128-bit security) */
    MlDsa44 = 0,
    /** ML-DSA-65 (192-bit security) */
    MlDsa65 = 1,
    /** ML-DSA-87 (256-bit security) */
    MlDsa87 = 2,
}

/** Hash algorithms */
export enum HashAlgorithm {
    /** SHA-256 */
    Sha256 = 0,
    /** SHA-384 */
    Sha384 = 1,
    /** SHA-512 */
    Sha512 = 2,
    /** SHA3-256 */
    Sha3_256 = 3,
    /** SHA3-384 */
    Sha3_384 = 4,
    /** SHA3-512 */
    Sha3_512 = 5,
    /** SHAKE128 (variable output) */
    Shake128 = 6,
    /** SHAKE256 (variable output) */
    Shake256 = 7,
}

/** Key types for HSM storage */
export enum KeyType {
    /** Symmetric key */
    Secret = 0,
    /** Public key only */
    Public = 1,
    /** Private key only */
    Private = 2,
    /** Full key pair */
    KeyPair = 3,
}

/** Key usage flags */
export enum KeyUsage {
    /** Key can be used for encryption */
    Encrypt = 0x01,
    /** Key can be used for decryption */
    Decrypt = 0x02,
    /** Key can be used for signing */
    Sign = 0x04,
    /** Key can be used for verification */
    Verify = 0x08,
    /** Key can be used for key derivation */
    Derive = 0x10,
    /** Key can be used to wrap other keys */
    Wrap = 0x20,
    /** Key can be used to unwrap other keys */
    Unwrap = 0x40,
    /** All usages */
    All = 0x7f,
}

/** Library initialization flags */
export enum InitFlags {
    /** Use hardware acceleration */
    HardwareAccel = 0x01,
    /** Enable side-channel protection */
    SideChannelProtect = 0x02,
    /** Use constant-time operations */
    ConstantTime = 0x04,
    /** Auto-zeroize sensitive data */
    AutoZeroize = 0x08,
    /** Enable FIPS 140-3 mode */
    FipsMode = 0x10,
    /** Enable debug output */
    Debug = 0x20,
    /** Allow software fallback */
    SoftwareFallback = 0x40,
    /** Default flags */
    Default = 0x0f,
}

/** Device information */
export interface DeviceInfo {
    /** Device index */
    index: number;
    /** Device model */
    model: string;
    /** Serial number */
    serialNumber: string;
    /** Firmware version */
    firmwareVersion: string;
    /** Hardware version */
    hardwareVersion: string;
    /** Number of key slots */
    keySlots: number;
    /** Maximum operations per second */
    maxOpsPerSecond: number;
}

/** Device status */
export interface DeviceStatus {
    /** Device temperature in Celsius */
    temperature: number;
    /** Entropy level (0-100) */
    entropyLevel: number;
    /** Operations performed */
    operationsCount: number;
    /** Device uptime in seconds */
    uptime: number;
    /** Last error code */
    lastError: number;
    /** Device is ready */
    isReady: boolean;
}

/** Key information */
export interface KeyInfo {
    /** Slot number */
    slot: number;
    /** Key type */
    keyType: KeyType;
    /** Algorithm identifier */
    algorithm: number;
    /** Usage flags */
    usage: KeyUsage;
    /** Key label */
    label: string;
    /** Key size in bytes */
    size: number;
    /** Creation timestamp */
    createdAt: Date;
}

/** Entropy status */
export interface EntropyStatus {
    /** Entropy level (0-100) */
    level: number;
    /** Entropy source is healthy */
    isHealthy: boolean;
    /** Bytes available */
    bytesAvailable: number;
}

/** KEM key pair */
export interface KemKeyPair {
    /** Public key */
    publicKey: Buffer;
    /** Secret key */
    secretKey: Buffer;
}

/** Encapsulation result */
export interface EncapsulationResult {
    /** Ciphertext */
    ciphertext: Buffer;
    /** Shared secret */
    sharedSecret: Buffer;
}

/** Signature key pair */
export interface SignKeyPair {
    /** Public key */
    publicKey: Buffer;
    /** Secret key */
    secretKey: Buffer;
}

/** Algorithm sizes */
export const KEM_SIZES = {
    [KemAlgorithm.MlKem512]: { publicKey: 800, secretKey: 1632, ciphertext: 768, sharedSecret: 32 },
    [KemAlgorithm.MlKem768]: { publicKey: 1184, secretKey: 2400, ciphertext: 1088, sharedSecret: 32 },
    [KemAlgorithm.MlKem1024]: { publicKey: 1568, secretKey: 3168, ciphertext: 1568, sharedSecret: 32 },
} as const;

export const SIGN_SIZES = {
    [SignAlgorithm.MlDsa44]: { publicKey: 1312, secretKey: 2560, signature: 2420 },
    [SignAlgorithm.MlDsa65]: { publicKey: 1952, secretKey: 4032, signature: 3309 },
    [SignAlgorithm.MlDsa87]: { publicKey: 2592, secretKey: 4896, signature: 4627 },
} as const;

export const HASH_SIZES = {
    [HashAlgorithm.Sha256]: 32,
    [HashAlgorithm.Sha384]: 48,
    [HashAlgorithm.Sha512]: 64,
    [HashAlgorithm.Sha3_256]: 32,
    [HashAlgorithm.Sha3_384]: 48,
    [HashAlgorithm.Sha3_512]: 64,
    [HashAlgorithm.Shake128]: null, // Variable
    [HashAlgorithm.Shake256]: null, // Variable
} as const;