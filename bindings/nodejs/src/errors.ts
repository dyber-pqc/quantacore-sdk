/**
 * Error handling for QUAC 100 SDK
 * @module errors
 */

/** Error codes returned by the native library */
export enum ErrorCode {
    Success = 0,
    InvalidParameter = -1,
    BufferTooSmall = -2,
    NotInitialized = -3,
    DeviceNotFound = -4,
    DeviceBusy = -5,
    DeviceError = -6,
    OperationFailed = -7,
    InvalidKey = -8,
    InvalidSignature = -9,
    InvalidCiphertext = -10,
    KeyNotFound = -11,
    SlotOccupied = -12,
    SlotEmpty = -13,
    InsufficientEntropy = -14,
    HardwareError = -15,
    PermissionDenied = -16,
    NotSupported = -17,
    Timeout = -18,
    CommunicationError = -19,
    VerificationFailed = -20,
    SelfTestFailed = -21,
    FipsError = -22,
    MemoryError = -23,
    InternalError = -24,
    AlreadyInitialized = -25,
    InvalidState = -26,
    Unknown = -999,
}

/** Map error codes to human-readable messages */
const ERROR_MESSAGES: Record<ErrorCode, string> = {
    [ErrorCode.Success]: 'Success',
    [ErrorCode.InvalidParameter]: 'Invalid parameter',
    [ErrorCode.BufferTooSmall]: 'Buffer too small',
    [ErrorCode.NotInitialized]: 'Library not initialized',
    [ErrorCode.DeviceNotFound]: 'Device not found',
    [ErrorCode.DeviceBusy]: 'Device is busy',
    [ErrorCode.DeviceError]: 'Device error',
    [ErrorCode.OperationFailed]: 'Operation failed',
    [ErrorCode.InvalidKey]: 'Invalid key',
    [ErrorCode.InvalidSignature]: 'Invalid signature',
    [ErrorCode.InvalidCiphertext]: 'Invalid ciphertext',
    [ErrorCode.KeyNotFound]: 'Key not found',
    [ErrorCode.SlotOccupied]: 'Key slot is occupied',
    [ErrorCode.SlotEmpty]: 'Key slot is empty',
    [ErrorCode.InsufficientEntropy]: 'Insufficient entropy',
    [ErrorCode.HardwareError]: 'Hardware error',
    [ErrorCode.PermissionDenied]: 'Permission denied',
    [ErrorCode.NotSupported]: 'Operation not supported',
    [ErrorCode.Timeout]: 'Operation timed out',
    [ErrorCode.CommunicationError]: 'Communication error',
    [ErrorCode.VerificationFailed]: 'Verification failed',
    [ErrorCode.SelfTestFailed]: 'Self-test failed',
    [ErrorCode.FipsError]: 'FIPS compliance error',
    [ErrorCode.MemoryError]: 'Memory allocation error',
    [ErrorCode.InternalError]: 'Internal error',
    [ErrorCode.AlreadyInitialized]: 'Already initialized',
    [ErrorCode.InvalidState]: 'Invalid state',
    [ErrorCode.Unknown]: 'Unknown error',
};

/**
 * Custom error class for QUAC 100 SDK errors
 */
export class QuacError extends Error {
    /** Error code */
    public readonly code: ErrorCode;

    constructor(code: ErrorCode, message?: string) {
        const defaultMessage = ERROR_MESSAGES[code] ?? 'Unknown error';
        super(message ?? defaultMessage);
        this.name = 'QuacError';
        this.code = code;
        Error.captureStackTrace(this, QuacError);
    }

    /**
     * Check if this is a specific error code
     */
    is(code: ErrorCode): boolean {
        return this.code === code;
    }

    /**
     * Get the error code name
     */
    get codeName(): string {
        return ErrorCode[this.code] ?? 'Unknown';
    }

    /**
     * Create string representation
     */
    toString(): string {
        return `QuacError [${this.codeName}]: ${this.message}`;
    }

    /**
     * Create error from native error code
     */
    static fromCode(code: number): QuacError {
        const errorCode = code in ErrorCode ? (code as ErrorCode) : ErrorCode.Unknown;
        return new QuacError(errorCode);
    }
}

/**
 * Check return code and throw if error
 * @param code - Return code from native function
 * @throws {QuacError} If code indicates an error
 */
export function checkError(code: number): void {
    if (code !== ErrorCode.Success) {
        throw QuacError.fromCode(code);
    }
}

/**
 * Wrap a function that returns an error code
 * @param fn - Function to wrap
 * @returns Wrapped function that throws on error
 */
export function wrapErrorCode<T extends (...args: unknown[]) => number>(
    fn: T
): (...args: Parameters<T>) => void {
    return (...args: Parameters<T>) => {
        const result = fn(...args);
        checkError(result);
    };
}