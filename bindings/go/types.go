// D:\quantacore-sdk\bindings\go\types.go
// QUAC 100 SDK - Type Definitions
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

import (
	"sync"
	"time"
)

// Status represents QUAC 100 operation result codes
type Status int

const (
	StatusSuccess            Status = 0
	StatusError              Status = -1
	StatusInvalidParameter   Status = -2
	StatusBufferTooSmall     Status = -3
	StatusDeviceNotFound     Status = -4
	StatusDeviceBusy         Status = -5
	StatusDeviceError        Status = -6
	StatusOutOfMemory        Status = -7
	StatusNotSupported       Status = -8
	StatusAuthRequired       Status = -9
	StatusAuthFailed         Status = -10
	StatusKeyNotFound        Status = -11
	StatusInvalidKey         Status = -12
	StatusVerifyFailed       Status = -13
	StatusDecapsFailed       Status = -14
	StatusHardwareNotAvail   Status = -15
	StatusTimeout            Status = -16
	StatusNotInitialized     Status = -17
	StatusAlreadyInitialized Status = -18
	StatusInvalidHandle      Status = -19
	StatusCancelled          Status = -20
	StatusEntropyDepleted    Status = -21
	StatusSelfTestFailed     Status = -22
	StatusTamperDetected     Status = -23
	StatusTemperatureError   Status = -24
	StatusPowerError         Status = -25
)

// String returns human-readable status description
func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "success"
	case StatusError:
		return "generic error"
	case StatusInvalidParameter:
		return "invalid parameter"
	case StatusBufferTooSmall:
		return "buffer too small"
	case StatusDeviceNotFound:
		return "device not found"
	case StatusDeviceBusy:
		return "device busy"
	case StatusDeviceError:
		return "device error"
	case StatusOutOfMemory:
		return "out of memory"
	case StatusNotSupported:
		return "not supported"
	case StatusAuthRequired:
		return "authentication required"
	case StatusAuthFailed:
		return "authentication failed"
	case StatusKeyNotFound:
		return "key not found"
	case StatusInvalidKey:
		return "invalid key"
	case StatusVerifyFailed:
		return "verification failed"
	case StatusDecapsFailed:
		return "decapsulation failed"
	case StatusHardwareNotAvail:
		return "hardware not available"
	case StatusTimeout:
		return "timeout"
	case StatusNotInitialized:
		return "not initialized"
	case StatusAlreadyInitialized:
		return "already initialized"
	case StatusInvalidHandle:
		return "invalid handle"
	case StatusCancelled:
		return "cancelled"
	case StatusEntropyDepleted:
		return "entropy depleted"
	case StatusSelfTestFailed:
		return "self-test failed"
	case StatusTamperDetected:
		return "tamper detected"
	case StatusTemperatureError:
		return "temperature error"
	case StatusPowerError:
		return "power error"
	default:
		return "unknown error"
	}
}

// KemAlgorithm represents ML-KEM (Kyber) algorithm variants
type KemAlgorithm int

const (
	// MlKem512 is ML-KEM-512 (NIST Security Level 1)
	MlKem512 KemAlgorithm = 1
	// MlKem768 is ML-KEM-768 (NIST Security Level 3) - Recommended
	MlKem768 KemAlgorithm = 2
	// MlKem1024 is ML-KEM-1024 (NIST Security Level 5)
	MlKem1024 KemAlgorithm = 3
)

// String returns algorithm name
func (k KemAlgorithm) String() string {
	switch k {
	case MlKem512:
		return "ML-KEM-512"
	case MlKem768:
		return "ML-KEM-768"
	case MlKem1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

// SignatureAlgorithm represents ML-DSA and SLH-DSA algorithm variants
type SignatureAlgorithm int

const (
	// MlDsa44 is ML-DSA-44 (NIST Security Level 2)
	MlDsa44 SignatureAlgorithm = 1
	// MlDsa65 is ML-DSA-65 (NIST Security Level 3) - Recommended
	MlDsa65 SignatureAlgorithm = 2
	// MlDsa87 is ML-DSA-87 (NIST Security Level 5)
	MlDsa87 SignatureAlgorithm = 3

	// SLH-DSA SHA2 variants
	SlhDsaSha2_128s SignatureAlgorithm = 10
	SlhDsaSha2_128f SignatureAlgorithm = 11
	SlhDsaSha2_192s SignatureAlgorithm = 12
	SlhDsaSha2_192f SignatureAlgorithm = 13
	SlhDsaSha2_256s SignatureAlgorithm = 14
	SlhDsaSha2_256f SignatureAlgorithm = 15

	// SLH-DSA SHAKE variants
	SlhDsaShake_128s SignatureAlgorithm = 20
	SlhDsaShake_128f SignatureAlgorithm = 21
	SlhDsaShake_192s SignatureAlgorithm = 22
	SlhDsaShake_192f SignatureAlgorithm = 23
	SlhDsaShake_256s SignatureAlgorithm = 24
	SlhDsaShake_256f SignatureAlgorithm = 25
)

// String returns algorithm name
func (s SignatureAlgorithm) String() string {
	switch s {
	case MlDsa44:
		return "ML-DSA-44"
	case MlDsa65:
		return "ML-DSA-65"
	case MlDsa87:
		return "ML-DSA-87"
	case SlhDsaSha2_128s:
		return "SLH-DSA-SHA2-128s"
	case SlhDsaSha2_128f:
		return "SLH-DSA-SHA2-128f"
	case SlhDsaSha2_192s:
		return "SLH-DSA-SHA2-192s"
	case SlhDsaSha2_192f:
		return "SLH-DSA-SHA2-192f"
	case SlhDsaSha2_256s:
		return "SLH-DSA-SHA2-256s"
	case SlhDsaSha2_256f:
		return "SLH-DSA-SHA2-256f"
	case SlhDsaShake_128s:
		return "SLH-DSA-SHAKE-128s"
	case SlhDsaShake_128f:
		return "SLH-DSA-SHAKE-128f"
	case SlhDsaShake_192s:
		return "SLH-DSA-SHAKE-192s"
	case SlhDsaShake_192f:
		return "SLH-DSA-SHAKE-192f"
	case SlhDsaShake_256s:
		return "SLH-DSA-SHAKE-256s"
	case SlhDsaShake_256f:
		return "SLH-DSA-SHAKE-256f"
	default:
		return "unknown"
	}
}

// HashAlgorithm represents supported hash algorithms
type HashAlgorithm int

const (
	HashSha256    HashAlgorithm = 1
	HashSha384    HashAlgorithm = 2
	HashSha512    HashAlgorithm = 3
	HashSha3_256  HashAlgorithm = 4
	HashSha3_384  HashAlgorithm = 5
	HashSha3_512  HashAlgorithm = 6
	HashShake128  HashAlgorithm = 7
	HashShake256  HashAlgorithm = 8
)

// DeviceFlags represents device operation flags
type DeviceFlags uint32

const (
	FlagNone                 DeviceFlags = 0
	FlagHardwareAcceleration DeviceFlags = 1 << 0
	FlagSideChannelProtection DeviceFlags = 1 << 1
	FlagConstantTime         DeviceFlags = 1 << 2
	FlagAutoZeroize          DeviceFlags = 1 << 3
	FlagFipsMode             DeviceFlags = 1 << 4
	FlagDebug                DeviceFlags = 1 << 5
	FlagSoftwareFallback     DeviceFlags = 1 << 6
	FlagAsyncOperations      DeviceFlags = 1 << 7
	FlagBatchProcessing      DeviceFlags = 1 << 8

	// FlagDefault is recommended default flags
	FlagDefault = FlagHardwareAcceleration | FlagSideChannelProtection | FlagAutoZeroize
)

// EntropySource represents entropy source type
type EntropySource int

const (
	EntropyQRNG    EntropySource = 0 // Hardware quantum random number generator
	EntropyTRNG    EntropySource = 1 // Hardware true random number generator
	EntropyHybrid  EntropySource = 2 // Hybrid QRNG + TRNG
	EntropySoftware EntropySource = 3 // Software CSPRNG (fallback)
)

// KeyUsage represents key usage restrictions
type KeyUsage uint32

const (
	KeyUsageSign        KeyUsage = 1 << 0
	KeyUsageVerify      KeyUsage = 1 << 1
	KeyUsageEncapsulate KeyUsage = 1 << 2
	KeyUsageDecapsulate KeyUsage = 1 << 3
	KeyUsageExport      KeyUsage = 1 << 4
	KeyUsageWrap        KeyUsage = 1 << 5
	KeyUsageUnwrap      KeyUsage = 1 << 6
	KeyUsageDerive      KeyUsage = 1 << 7

	KeyUsageAllSign = KeyUsageSign | KeyUsageVerify
	KeyUsageAllKem  = KeyUsageEncapsulate | KeyUsageDecapsulate
	KeyUsageAll     = 0xFFFFFFFF
)

// DeviceInfo contains device information
type DeviceInfo struct {
	DeviceIndex      int
	VendorID         uint16
	ProductID        uint16
	SerialNumber     string
	FirmwareVersion  string
	HardwareVersion  string
	ModelName        string
	Capabilities     uint32
	MaxConcurrentOps int
	KeySlots         int
	FipsMode         bool
	HardwareAvailable bool
}

// DeviceStatus contains device status information
type DeviceStatus struct {
	Temperature      float32
	PowerMilliwatts  uint32
	UptimeSeconds    uint64
	TotalOperations  uint64
	OpsPerSecond     uint32
	EntropyLevel     int
	ActiveSessions   int
	UsedKeySlots     int
	LastError        Status
	TamperStatus     int
}

// KemParams contains ML-KEM algorithm parameters
type KemParams struct {
	Algorithm        KemAlgorithm
	PublicKeySize    int
	SecretKeySize    int
	CiphertextSize   int
	SharedSecretSize int
	SecurityLevel    int
	Name             string
}

// GetKemParams returns parameters for the specified algorithm
func GetKemParams(alg KemAlgorithm) KemParams {
	switch alg {
	case MlKem512:
		return KemParams{MlKem512, 800, 1632, 768, 32, 1, "ML-KEM-512"}
	case MlKem768:
		return KemParams{MlKem768, 1184, 2400, 1088, 32, 3, "ML-KEM-768"}
	case MlKem1024:
		return KemParams{MlKem1024, 1568, 3168, 1568, 32, 5, "ML-KEM-1024"}
	default:
		return KemParams{}
	}
}

// SignatureParams contains signature algorithm parameters
type SignatureParams struct {
	Algorithm     SignatureAlgorithm
	PublicKeySize int
	SecretKeySize int
	SignatureSize int
	SecurityLevel int
	Name          string
}

// GetSignatureParams returns parameters for the specified algorithm
func GetSignatureParams(alg SignatureAlgorithm) SignatureParams {
	switch alg {
	case MlDsa44:
		return SignatureParams{MlDsa44, 1312, 2560, 2420, 2, "ML-DSA-44"}
	case MlDsa65:
		return SignatureParams{MlDsa65, 1952, 4032, 3309, 3, "ML-DSA-65"}
	case MlDsa87:
		return SignatureParams{MlDsa87, 2592, 4896, 4627, 5, "ML-DSA-87"}
	case SlhDsaSha2_128s:
		return SignatureParams{SlhDsaSha2_128s, 32, 64, 7856, 1, "SLH-DSA-SHA2-128s"}
	case SlhDsaSha2_128f:
		return SignatureParams{SlhDsaSha2_128f, 32, 64, 17088, 1, "SLH-DSA-SHA2-128f"}
	case SlhDsaSha2_192s:
		return SignatureParams{SlhDsaSha2_192s, 48, 96, 16224, 3, "SLH-DSA-SHA2-192s"}
	case SlhDsaSha2_192f:
		return SignatureParams{SlhDsaSha2_192f, 48, 96, 35664, 3, "SLH-DSA-SHA2-192f"}
	case SlhDsaSha2_256s:
		return SignatureParams{SlhDsaSha2_256s, 64, 128, 29792, 5, "SLH-DSA-SHA2-256s"}
	case SlhDsaSha2_256f:
		return SignatureParams{SlhDsaSha2_256f, 64, 128, 49856, 5, "SLH-DSA-SHA2-256f"}
	default:
		return SignatureParams{}
	}
}

// KemKeyPair represents an ML-KEM key pair
type KemKeyPair struct {
	PublicKey  []byte
	SecretKey  []byte
	Algorithm  KemAlgorithm
	Label      string
	Usage      KeyUsage
	CreatedAt  time.Time
	mu         sync.RWMutex
	zeroized   bool
}

// NewKemKeyPair creates a new KEM key pair container
func NewKemKeyPair(publicKey, secretKey []byte, alg KemAlgorithm) *KemKeyPair {
	return &KemKeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
		Algorithm: alg,
		Usage:     KeyUsageAllKem,
		CreatedAt: time.Now(),
	}
}

// Zeroize securely clears the key material
func (kp *KemKeyPair) Zeroize() {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	
	if kp.zeroized {
		return
	}
	
	SecureZero(kp.SecretKey)
	SecureZero(kp.PublicKey)
	kp.zeroized = true
}

// IsZeroized returns whether the key has been zeroized
func (kp *KemKeyPair) IsZeroized() bool {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.zeroized
}

// SignatureKeyPair represents an ML-DSA/SLH-DSA key pair
type SignatureKeyPair struct {
	PublicKey  []byte
	SecretKey  []byte
	Algorithm  SignatureAlgorithm
	Label      string
	Usage      KeyUsage
	CreatedAt  time.Time
	mu         sync.RWMutex
	zeroized   bool
}

// NewSignatureKeyPair creates a new signature key pair container
func NewSignatureKeyPair(publicKey, secretKey []byte, alg SignatureAlgorithm) *SignatureKeyPair {
	return &SignatureKeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
		Algorithm: alg,
		Usage:     KeyUsageAllSign,
		CreatedAt: time.Now(),
	}
}

// Zeroize securely clears the key material
func (kp *SignatureKeyPair) Zeroize() {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	
	if kp.zeroized {
		return
	}
	
	SecureZero(kp.SecretKey)
	SecureZero(kp.PublicKey)
	kp.zeroized = true
}

// IsZeroized returns whether the key has been zeroized
func (kp *SignatureKeyPair) IsZeroized() bool {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.zeroized
}

// EncapsulationResult contains KEM encapsulation output
type EncapsulationResult struct {
	Ciphertext   []byte
	SharedSecret []byte
	mu           sync.RWMutex
	zeroized     bool
}

// Zeroize securely clears the shared secret
func (er *EncapsulationResult) Zeroize() {
	er.mu.Lock()
	defer er.mu.Unlock()
	
	if er.zeroized {
		return
	}
	
	SecureZero(er.SharedSecret)
	er.zeroized = true
}

// EntropyStatus contains entropy pool status
type EntropyStatus struct {
	Level  int
	Source EntropySource
}

// PerformanceStats contains performance statistics
type PerformanceStats struct {
	OpsPerSecond     float64
	AvgLatencyMicros float64
	MinLatencyMicros int64
	MaxLatencyMicros int64
	P99LatencyMicros int64
	TotalOperations  int64
	TotalErrors      int64
}

// SecureZero overwrites a byte slice with zeros
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureCompare performs constant-time comparison
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}