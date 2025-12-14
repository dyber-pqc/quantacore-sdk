// D:\quantacore-sdk\bindings\go\errors.go
// QUAC 100 SDK - Error Types
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

import (
	"errors"
	"fmt"
)

var (
	// ErrDeviceNotFound indicates no QUAC 100 device was found
	ErrDeviceNotFound = errors.New("quac100: device not found")

	// ErrDeviceBusy indicates the device is busy
	ErrDeviceBusy = errors.New("quac100: device busy")

	// ErrDeviceError indicates a device error occurred
	ErrDeviceError = errors.New("quac100: device error")

	// ErrInvalidParameter indicates an invalid parameter was provided
	ErrInvalidParameter = errors.New("quac100: invalid parameter")

	// ErrBufferTooSmall indicates the output buffer is too small
	ErrBufferTooSmall = errors.New("quac100: buffer too small")

	// ErrNotSupported indicates the operation is not supported
	ErrNotSupported = errors.New("quac100: not supported")

	// ErrAuthRequired indicates authentication is required
	ErrAuthRequired = errors.New("quac100: authentication required")

	// ErrAuthFailed indicates authentication failed
	ErrAuthFailed = errors.New("quac100: authentication failed")

	// ErrKeyNotFound indicates the key was not found
	ErrKeyNotFound = errors.New("quac100: key not found")

	// ErrInvalidKey indicates the key is invalid
	ErrInvalidKey = errors.New("quac100: invalid key")

	// ErrVerifyFailed indicates signature verification failed
	ErrVerifyFailed = errors.New("quac100: signature verification failed")

	// ErrDecapsFailed indicates decapsulation failed
	ErrDecapsFailed = errors.New("quac100: decapsulation failed")

	// ErrHardwareNotAvailable indicates hardware acceleration is not available
	ErrHardwareNotAvailable = errors.New("quac100: hardware not available")

	// ErrTimeout indicates the operation timed out
	ErrTimeout = errors.New("quac100: operation timeout")

	// ErrNotInitialized indicates the library is not initialized
	ErrNotInitialized = errors.New("quac100: not initialized")

	// ErrAlreadyInitialized indicates the library is already initialized
	ErrAlreadyInitialized = errors.New("quac100: already initialized")

	// ErrInvalidHandle indicates an invalid handle was provided
	ErrInvalidHandle = errors.New("quac100: invalid handle")

	// ErrCancelled indicates the operation was cancelled
	ErrCancelled = errors.New("quac100: operation cancelled")

	// ErrEntropyDepleted indicates the entropy pool is depleted
	ErrEntropyDepleted = errors.New("quac100: entropy depleted")

	// ErrSelfTestFailed indicates the self-test failed
	ErrSelfTestFailed = errors.New("quac100: self-test failed")

	// ErrTamperDetected indicates tamper was detected
	ErrTamperDetected = errors.New("quac100: tamper detected")

	// ErrTemperature indicates a temperature error
	ErrTemperature = errors.New("quac100: temperature error")

	// ErrPower indicates a power supply error
	ErrPower = errors.New("quac100: power error")

	// ErrOutOfMemory indicates memory allocation failed
	ErrOutOfMemory = errors.New("quac100: out of memory")

	// ErrClosed indicates the device has been closed
	ErrClosed = errors.New("quac100: device closed")

	// ErrKeyZeroized indicates the key has been zeroized
	ErrKeyZeroized = errors.New("quac100: key has been zeroized")
)

// Error represents a QUAC 100 error with status code
type Error struct {
	Status  Status
	Message string
	Cause   error
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quac100: %s (status=%d): %v", e.Message, e.Status, e.Cause)
	}
	return fmt.Sprintf("quac100: %s (status=%d)", e.Message, e.Status)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is implements error matching
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Status == t.Status
	}
	return false
}

// NewError creates a new QUAC 100 error
func NewError(status Status, message string) *Error {
	return &Error{
		Status:  status,
		Message: message,
	}
}

// WrapError wraps an existing error with QUAC 100 context
func WrapError(status Status, message string, cause error) *Error {
	return &Error{
		Status:  status,
		Message: message,
		Cause:   cause,
	}
}

// statusToError converts a Status code to an error
func statusToError(status Status) error {
	switch status {
	case StatusSuccess:
		return nil
	case StatusDeviceNotFound:
		return ErrDeviceNotFound
	case StatusDeviceBusy:
		return ErrDeviceBusy
	case StatusDeviceError:
		return ErrDeviceError
	case StatusInvalidParameter:
		return ErrInvalidParameter
	case StatusBufferTooSmall:
		return ErrBufferTooSmall
	case StatusNotSupported:
		return ErrNotSupported
	case StatusAuthRequired:
		return ErrAuthRequired
	case StatusAuthFailed:
		return ErrAuthFailed
	case StatusKeyNotFound:
		return ErrKeyNotFound
	case StatusInvalidKey:
		return ErrInvalidKey
	case StatusVerifyFailed:
		return ErrVerifyFailed
	case StatusDecapsFailed:
		return ErrDecapsFailed
	case StatusHardwareNotAvail:
		return ErrHardwareNotAvailable
	case StatusTimeout:
		return ErrTimeout
	case StatusNotInitialized:
		return ErrNotInitialized
	case StatusAlreadyInitialized:
		return ErrAlreadyInitialized
	case StatusInvalidHandle:
		return ErrInvalidHandle
	case StatusCancelled:
		return ErrCancelled
	case StatusEntropyDepleted:
		return ErrEntropyDepleted
	case StatusSelfTestFailed:
		return ErrSelfTestFailed
	case StatusTamperDetected:
		return ErrTamperDetected
	case StatusTemperatureError:
		return ErrTemperature
	case StatusPowerError:
		return ErrPower
	case StatusOutOfMemory:
		return ErrOutOfMemory
	default:
		return &Error{Status: status, Message: status.String()}
	}
}

// checkStatus converts a status code to an error with context
func checkStatus(status Status, context string) error {
	if status == StatusSuccess {
		return nil
	}
	
	baseErr := statusToError(status)
	if context == "" {
		return baseErr
	}
	
	return WrapError(status, context, baseErr)
}

// IsDeviceNotFound returns true if err indicates device not found
func IsDeviceNotFound(err error) bool {
	return errors.Is(err, ErrDeviceNotFound)
}

// IsVerifyFailed returns true if err indicates verification failure
func IsVerifyFailed(err error) bool {
	return errors.Is(err, ErrVerifyFailed)
}

// IsDecapsFailed returns true if err indicates decapsulation failure
func IsDecapsFailed(err error) bool {
	return errors.Is(err, ErrDecapsFailed)
}

// IsTamperDetected returns true if err indicates tamper detection
func IsTamperDetected(err error) bool {
	return errors.Is(err, ErrTamperDetected)
}

// IsHardwareNotAvailable returns true if err indicates hardware unavailable
func IsHardwareNotAvailable(err error) bool {
	return errors.Is(err, ErrHardwareNotAvailable)
}