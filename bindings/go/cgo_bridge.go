// D:\quantacore-sdk\bindings\go\cgo_bridge.go
// QUAC 100 SDK - CGO Native Library Bridge
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo linux LDFLAGS: -L${SRCDIR}/lib -lquac100 -Wl,-rpath,${SRCDIR}/lib
#cgo darwin LDFLAGS: -L${SRCDIR}/lib -lquac100 -Wl,-rpath,${SRCDIR}/lib
#cgo windows LDFLAGS: -L${SRCDIR}/lib -lquac100

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Forward declarations - these match the actual QUAC 100 C API

// Library initialization
int quac_init(uint32_t flags);
int quac_cleanup(void);
const char* quac_version(void);
int quac_version_info(int* major, int* minor, int* patch);

// Device info structure
typedef struct {
    int device_index;
    uint16_t vendor_id;
    uint16_t product_id;
    char serial_number[64];
    char firmware_version[32];
    char hardware_version[32];
    char model_name[64];
    uint32_t capabilities;
    int max_concurrent_ops;
    int key_slots;
    uint8_t fips_mode;
    uint8_t hardware_available;
} quac_device_info_t;

// Device status structure
typedef struct {
    float temperature;
    uint32_t power_mw;
    uint64_t uptime_seconds;
    uint64_t total_operations;
    uint32_t ops_per_second;
    int entropy_level;
    int active_sessions;
    int used_key_slots;
    int last_error;
    int tamper_status;
} quac_device_status_t;

// Device management
int quac_enumerate_devices(quac_device_info_t* devices, int max_devices, int* device_count);
int quac_open_device(int device_index, uint32_t flags, void** handle);
int quac_close_device(void* handle);
int quac_get_device_info(void* handle, quac_device_info_t* info);
int quac_get_device_status(void* handle, quac_device_status_t* status);
int quac_reset_device(void* handle);
int quac_self_test(void* handle);

// ML-KEM operations
int quac_kem_keygen(void* handle, int algorithm,
    uint8_t* public_key, int* public_key_len,
    uint8_t* secret_key, int* secret_key_len);
int quac_kem_encaps(void* handle, int algorithm,
    const uint8_t* public_key, int public_key_len,
    uint8_t* ciphertext, int* ciphertext_len,
    uint8_t* shared_secret, int* shared_secret_len);
int quac_kem_decaps(void* handle, int algorithm,
    const uint8_t* secret_key, int secret_key_len,
    const uint8_t* ciphertext, int ciphertext_len,
    uint8_t* shared_secret, int* shared_secret_len);
int quac_kem_get_params(int algorithm,
    int* public_key_len, int* secret_key_len,
    int* ciphertext_len, int* shared_secret_len);

// ML-DSA/SLH-DSA operations
int quac_sign_keygen(void* handle, int algorithm,
    uint8_t* public_key, int* public_key_len,
    uint8_t* secret_key, int* secret_key_len);
int quac_sign(void* handle, int algorithm,
    const uint8_t* secret_key, int secret_key_len,
    const uint8_t* message, int message_len,
    uint8_t* signature, int* signature_len);
int quac_verify(void* handle, int algorithm,
    const uint8_t* public_key, int public_key_len,
    const uint8_t* message, int message_len,
    const uint8_t* signature, int signature_len);
int quac_sign_get_params(int algorithm,
    int* public_key_len, int* secret_key_len, int* signature_len);

// Random number generation
int quac_random_bytes(void* handle, uint8_t* buffer, int length);
int quac_random_bytes_ex(void* handle, uint8_t* buffer, int length, int entropy_source);
int quac_random_entropy_status(void* handle, int* level, int* source);
int quac_random_seed(void* handle, const uint8_t* seed, int seed_len);
int quac_random_reseed(void* handle);

// Key storage
int quac_key_store(void* handle, const uint8_t* key, int key_len,
    int key_type, const char* label, uint32_t usage, int* slot);
int quac_key_load(void* handle, int slot, uint8_t* key, int* key_len);
int quac_key_delete(void* handle, int slot);
int quac_key_list(void* handle, int* slots, int max_slots, int* count);

// Hash operations
int quac_hash(void* handle, int algorithm,
    const uint8_t* data, int data_len,
    uint8_t* hash, int* hash_len);
int quac_hash_init(void* handle, int algorithm, void** context);
int quac_hash_update(void* context, const uint8_t* data, int data_len);
int quac_hash_final(void* context, uint8_t* hash, int* hash_len);
int quac_hash_free(void* context);

// Utility functions
const char* quac_error_string(int error_code);
void quac_secure_zero(uint8_t* buffer, int length);
int quac_secure_compare(const uint8_t* a, const uint8_t* b, int length);

*/
import "C"

import (
	"sync"
	"unsafe"
)

var (
	initOnce   sync.Once
	initErr    error
	initMu     sync.Mutex
	initialized bool
)

// cgoInit initializes the native library
func cgoInit(flags DeviceFlags) error {
	initMu.Lock()
	defer initMu.Unlock()
	
	if initialized {
		return nil
	}
	
	status := Status(C.quac_init(C.uint32_t(flags)))
	if status != StatusSuccess && status != StatusAlreadyInitialized {
		return statusToError(status)
	}
	
	initialized = true
	return nil
}

// cgoCleanup cleans up the native library
func cgoCleanup() error {
	initMu.Lock()
	defer initMu.Unlock()
	
	if !initialized {
		return nil
	}
	
	status := Status(C.quac_cleanup())
	initialized = false
	return statusToError(status)
}

// cgoVersion returns the library version string
func cgoVersion() string {
	return C.GoString(C.quac_version())
}

// cgoVersionInfo returns version numbers
func cgoVersionInfo() (major, minor, patch int) {
	var cMajor, cMinor, cPatch C.int
	C.quac_version_info(&cMajor, &cMinor, &cPatch)
	return int(cMajor), int(cMinor), int(cPatch)
}

// cgoEnumerateDevices enumerates available devices
func cgoEnumerateDevices(maxDevices int) ([]DeviceInfo, error) {
	devices := make([]C.quac_device_info_t, maxDevices)
	var count C.int
	
	status := Status(C.quac_enumerate_devices(&devices[0], C.int(maxDevices), &count))
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	result := make([]DeviceInfo, int(count))
	for i := 0; i < int(count); i++ {
		result[i] = deviceInfoFromC(&devices[i])
	}
	
	return result, nil
}

// cgoOpenDevice opens a device handle
func cgoOpenDevice(deviceIndex int, flags DeviceFlags) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	
	status := Status(C.quac_open_device(C.int(deviceIndex), C.uint32_t(flags), &handle))
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	return handle, nil
}

// cgoCloseDevice closes a device handle
func cgoCloseDevice(handle unsafe.Pointer) error {
	status := Status(C.quac_close_device(handle))
	return statusToError(status)
}

// cgoGetDeviceInfo gets device information
func cgoGetDeviceInfo(handle unsafe.Pointer) (*DeviceInfo, error) {
	var info C.quac_device_info_t
	
	status := Status(C.quac_get_device_info(handle, &info))
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	result := deviceInfoFromC(&info)
	return &result, nil
}

// cgoGetDeviceStatus gets device status
func cgoGetDeviceStatus(handle unsafe.Pointer) (*DeviceStatus, error) {
	var status C.quac_device_status_t
	
	result := Status(C.quac_get_device_status(handle, &status))
	if err := statusToError(result); err != nil {
		return nil, err
	}
	
	return &DeviceStatus{
		Temperature:     float32(status.temperature),
		PowerMilliwatts: uint32(status.power_mw),
		UptimeSeconds:   uint64(status.uptime_seconds),
		TotalOperations: uint64(status.total_operations),
		OpsPerSecond:    uint32(status.ops_per_second),
		EntropyLevel:    int(status.entropy_level),
		ActiveSessions:  int(status.active_sessions),
		UsedKeySlots:    int(status.used_key_slots),
		LastError:       Status(status.last_error),
		TamperStatus:    int(status.tamper_status),
	}, nil
}

// cgoResetDevice resets the device
func cgoResetDevice(handle unsafe.Pointer) error {
	status := Status(C.quac_reset_device(handle))
	return statusToError(status)
}

// cgoSelfTest runs device self-test
func cgoSelfTest(handle unsafe.Pointer) (bool, error) {
	status := Status(C.quac_self_test(handle))
	if status == StatusSuccess {
		return true, nil
	}
	if status == StatusSelfTestFailed {
		return false, nil
	}
	return false, statusToError(status)
}

// cgoKemKeygen generates ML-KEM key pair
func cgoKemKeygen(handle unsafe.Pointer, alg KemAlgorithm) ([]byte, []byte, error) {
	params := GetKemParams(alg)
	
	publicKey := make([]byte, params.PublicKeySize)
	secretKey := make([]byte, params.SecretKeySize)
	pkLen := C.int(len(publicKey))
	skLen := C.int(len(secretKey))
	
	status := Status(C.quac_kem_keygen(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), &pkLen,
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), &skLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, nil, err
	}
	
	return publicKey[:pkLen], secretKey[:skLen], nil
}

// cgoKemEncaps performs ML-KEM encapsulation
func cgoKemEncaps(handle unsafe.Pointer, alg KemAlgorithm, publicKey []byte) ([]byte, []byte, error) {
	params := GetKemParams(alg)
	
	ciphertext := make([]byte, params.CiphertextSize)
	sharedSecret := make([]byte, params.SharedSecretSize)
	ctLen := C.int(len(ciphertext))
	ssLen := C.int(len(sharedSecret))
	
	status := Status(C.quac_kem_encaps(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.int(len(publicKey)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), &ctLen,
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])), &ssLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, nil, err
	}
	
	return ciphertext[:ctLen], sharedSecret[:ssLen], nil
}

// cgoKemDecaps performs ML-KEM decapsulation
func cgoKemDecaps(handle unsafe.Pointer, alg KemAlgorithm, secretKey, ciphertext []byte) ([]byte, error) {
	params := GetKemParams(alg)
	
	sharedSecret := make([]byte, params.SharedSecretSize)
	ssLen := C.int(len(sharedSecret))
	
	status := Status(C.quac_kem_decaps(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.int(len(secretKey)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.int(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])), &ssLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	return sharedSecret[:ssLen], nil
}

// cgoSignKeygen generates signature key pair
func cgoSignKeygen(handle unsafe.Pointer, alg SignatureAlgorithm) ([]byte, []byte, error) {
	params := GetSignatureParams(alg)
	
	publicKey := make([]byte, params.PublicKeySize)
	secretKey := make([]byte, params.SecretKeySize)
	pkLen := C.int(len(publicKey))
	skLen := C.int(len(secretKey))
	
	status := Status(C.quac_sign_keygen(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), &pkLen,
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), &skLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, nil, err
	}
	
	return publicKey[:pkLen], secretKey[:skLen], nil
}

// cgoSign signs a message
func cgoSign(handle unsafe.Pointer, alg SignatureAlgorithm, secretKey, message []byte) ([]byte, error) {
	params := GetSignatureParams(alg)
	
	signature := make([]byte, params.SignatureSize)
	sigLen := C.int(len(signature))
	
	status := Status(C.quac_sign(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.int(len(secretKey)),
		(*C.uint8_t)(unsafe.Pointer(&message[0])), C.int(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])), &sigLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	return signature[:sigLen], nil
}

// cgoVerify verifies a signature
func cgoVerify(handle unsafe.Pointer, alg SignatureAlgorithm, publicKey, message, signature []byte) (bool, error) {
	status := Status(C.quac_verify(
		handle,
		C.int(alg),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.int(len(publicKey)),
		(*C.uint8_t)(unsafe.Pointer(&message[0])), C.int(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])), C.int(len(signature)),
	))
	
	if status == StatusSuccess {
		return true, nil
	}
	if status == StatusVerifyFailed {
		return false, nil
	}
	return false, statusToError(status)
}

// cgoRandomBytes generates random bytes
func cgoRandomBytes(handle unsafe.Pointer, buffer []byte) error {
	status := Status(C.quac_random_bytes(
		handle,
		(*C.uint8_t)(unsafe.Pointer(&buffer[0])),
		C.int(len(buffer)),
	))
	return statusToError(status)
}

// cgoRandomBytesEx generates random bytes with specific entropy source
func cgoRandomBytesEx(handle unsafe.Pointer, buffer []byte, source EntropySource) error {
	status := Status(C.quac_random_bytes_ex(
		handle,
		(*C.uint8_t)(unsafe.Pointer(&buffer[0])),
		C.int(len(buffer)),
		C.int(source),
	))
	return statusToError(status)
}

// cgoEntropyStatus gets entropy pool status
func cgoEntropyStatus(handle unsafe.Pointer) (int, EntropySource, error) {
	var level, source C.int
	
	status := Status(C.quac_random_entropy_status(handle, &level, &source))
	if err := statusToError(status); err != nil {
		return 0, 0, err
	}
	
	return int(level), EntropySource(source), nil
}

// cgoRandomSeed seeds the RNG
func cgoRandomSeed(handle unsafe.Pointer, seed []byte) error {
	status := Status(C.quac_random_seed(
		handle,
		(*C.uint8_t)(unsafe.Pointer(&seed[0])),
		C.int(len(seed)),
	))
	return statusToError(status)
}

// cgoRandomReseed reseeds from hardware entropy
func cgoRandomReseed(handle unsafe.Pointer) error {
	status := Status(C.quac_random_reseed(handle))
	return statusToError(status)
}

// cgoHash computes hash
func cgoHash(handle unsafe.Pointer, alg HashAlgorithm, data []byte) ([]byte, error) {
	hashLen := hashSize(alg)
	hash := make([]byte, hashLen)
	hLen := C.int(hashLen)
	
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	
	status := Status(C.quac_hash(
		handle,
		C.int(alg),
		dataPtr, C.int(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&hash[0])), &hLen,
	))
	
	if err := statusToError(status); err != nil {
		return nil, err
	}
	
	return hash[:hLen], nil
}

// cgoSecureZero securely zeros memory
func cgoSecureZero(buffer []byte) {
	if len(buffer) > 0 {
		C.quac_secure_zero((*C.uint8_t)(unsafe.Pointer(&buffer[0])), C.int(len(buffer)))
	}
}

// cgoSecureCompare performs constant-time comparison
func cgoSecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	
	result := C.quac_secure_compare(
		(*C.uint8_t)(unsafe.Pointer(&a[0])),
		(*C.uint8_t)(unsafe.Pointer(&b[0])),
		C.int(len(a)),
	)
	return result == 0
}

// cgoErrorString gets error message for status code
func cgoErrorString(status Status) string {
	return C.GoString(C.quac_error_string(C.int(status)))
}

// Helper functions

func deviceInfoFromC(info *C.quac_device_info_t) DeviceInfo {
	return DeviceInfo{
		DeviceIndex:      int(info.device_index),
		VendorID:         uint16(info.vendor_id),
		ProductID:        uint16(info.product_id),
		SerialNumber:     C.GoString(&info.serial_number[0]),
		FirmwareVersion:  C.GoString(&info.firmware_version[0]),
		HardwareVersion:  C.GoString(&info.hardware_version[0]),
		ModelName:        C.GoString(&info.model_name[0]),
		Capabilities:     uint32(info.capabilities),
		MaxConcurrentOps: int(info.max_concurrent_ops),
		KeySlots:         int(info.key_slots),
		FipsMode:         info.fips_mode != 0,
		HardwareAvailable: info.hardware_available != 0,
	}
}

func hashSize(alg HashAlgorithm) int {
	switch alg {
	case HashSha256, HashSha3_256:
		return 32
	case HashSha384, HashSha3_384:
		return 48
	case HashSha512, HashSha3_512:
		return 64
	default:
		return 32
	}
}