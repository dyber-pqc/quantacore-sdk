// D:\quantacore-sdk\bindings\go\device.go
// QUAC 100 SDK - Device Management
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

import (
	"context"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Device represents a connection to a QUAC 100 device
type Device struct {
	handle      unsafe.Pointer
	deviceIndex int
	flags       DeviceFlags
	closed      atomic.Bool
	mu          sync.RWMutex
}

// OpenDevice opens a connection to a QUAC 100 device
func OpenDevice(deviceIndex int, flags DeviceFlags) (*Device, error) {
	// Ensure library is initialized
	if err := cgoInit(flags); err != nil {
		return nil, err
	}
	
	handle, err := cgoOpenDevice(deviceIndex, flags)
	if err != nil {
		return nil, err
	}
	
	return &Device{
		handle:      handle,
		deviceIndex: deviceIndex,
		flags:       flags,
	}, nil
}

// Open opens the first available device with default flags
func Open() (*Device, error) {
	return OpenDevice(0, FlagDefault)
}

// TryOpen attempts to open a device, returning nil if not found
func TryOpen(deviceIndex int, flags DeviceFlags) *Device {
	dev, err := OpenDevice(deviceIndex, flags)
	if err != nil {
		return nil
	}
	return dev
}

// Close closes the device connection
func (d *Device) Close() error {
	if d.closed.Swap(true) {
		return nil // Already closed
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if d.handle != nil {
		err := cgoCloseDevice(d.handle)
		d.handle = nil
		return err
	}
	return nil
}

// IsClosed returns whether the device is closed
func (d *Device) IsClosed() bool {
	return d.closed.Load()
}

// DeviceIndex returns the device index
func (d *Device) DeviceIndex() int {
	return d.deviceIndex
}

// Flags returns the device flags
func (d *Device) Flags() DeviceFlags {
	return d.flags
}

// checkOpen returns an error if the device is closed
func (d *Device) checkOpen() error {
	if d.closed.Load() {
		return ErrClosed
	}
	return nil
}

// getHandle returns the native handle with read lock
func (d *Device) getHandle() (unsafe.Pointer, error) {
	if err := d.checkOpen(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	return d.handle, nil
}

// releaseHandle releases the read lock
func (d *Device) releaseHandle() {
	d.mu.RUnlock()
}

// Info returns device information
func (d *Device) Info() (*DeviceInfo, error) {
	handle, err := d.getHandle()
	if err != nil {
		return nil, err
	}
	defer d.releaseHandle()
	
	return cgoGetDeviceInfo(handle)
}

// Status returns device status
func (d *Device) Status() (*DeviceStatus, error) {
	handle, err := d.getHandle()
	if err != nil {
		return nil, err
	}
	defer d.releaseHandle()
	
	return cgoGetDeviceStatus(handle)
}

// Reset resets the device
func (d *Device) Reset() error {
	handle, err := d.getHandle()
	if err != nil {
		return err
	}
	defer d.releaseHandle()
	
	return cgoResetDevice(handle)
}

// SelfTest runs the device self-test
func (d *Device) SelfTest() (bool, error) {
	handle, err := d.getHandle()
	if err != nil {
		return false, err
	}
	defer d.releaseHandle()
	
	return cgoSelfTest(handle)
}

// EnumerateDevices returns information about all available devices
func EnumerateDevices() ([]DeviceInfo, error) {
	// Ensure library is initialized
	if err := cgoInit(FlagDefault); err != nil {
		return nil, err
	}
	
	return cgoEnumerateDevices(16)
}

// DeviceCount returns the number of available devices
func DeviceCount() (int, error) {
	devices, err := EnumerateDevices()
	if err != nil {
		return 0, err
	}
	return len(devices), nil
}

// DevicePool manages a pool of device connections for high-throughput operations
type DevicePool struct {
	devices   []*Device
	available chan *Device
	size      int
	closed    atomic.Bool
	mu        sync.Mutex
}

// NewDevicePool creates a new device pool
func NewDevicePool(poolSize int, flags DeviceFlags) (*DevicePool, error) {
	if poolSize < 1 {
		return nil, ErrInvalidParameter
	}
	
	pool := &DevicePool{
		devices:   make([]*Device, poolSize),
		available: make(chan *Device, poolSize),
		size:      poolSize,
	}
	
	// Open all devices
	for i := 0; i < poolSize; i++ {
		dev, err := OpenDevice(0, flags)
		if err != nil {
			// Clean up already opened devices
			pool.Close()
			return nil, err
		}
		pool.devices[i] = dev
		pool.available <- dev
	}
	
	return pool, nil
}

// Acquire gets a device from the pool
func (p *DevicePool) Acquire(ctx context.Context) (*Device, error) {
	if p.closed.Load() {
		return nil, ErrClosed
	}
	
	select {
	case dev := <-p.available:
		return dev, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Release returns a device to the pool
func (p *DevicePool) Release(dev *Device) {
	if p.closed.Load() {
		return
	}
	
	select {
	case p.available <- dev:
	default:
		// Pool is full, shouldn't happen
	}
}

// Size returns the pool size
func (p *DevicePool) Size() int {
	return p.size
}

// Available returns the number of available devices
func (p *DevicePool) Available() int {
	return len(p.available)
}

// Close closes all devices in the pool
func (p *DevicePool) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	close(p.available)
	
	var lastErr error
	for _, dev := range p.devices {
		if dev != nil {
			if err := dev.Close(); err != nil {
				lastErr = err
			}
		}
	}
	
	return lastErr
}

// PooledOperation executes an operation using a pooled device
func (p *DevicePool) PooledOperation(ctx context.Context, fn func(*Device) error) error {
	dev, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	defer p.Release(dev)
	
	return fn(dev)
}

// Version returns the SDK version string
func Version() string {
	cgoInit(FlagDefault) // Ensure initialized
	return cgoVersion()
}

// VersionInfo returns the SDK version numbers
func VersionInfo() (major, minor, patch int) {
	cgoInit(FlagDefault) // Ensure initialized
	return cgoVersionInfo()
}

// Cleanup cleans up the SDK
func Cleanup() error {
	return cgoCleanup()
}

// ErrorString returns the error message for a status code
func ErrorString(status Status) string {
	return cgoErrorString(status)
}