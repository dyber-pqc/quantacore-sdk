# QUAC 100 Windows Driver Architecture

## Overview

The QUAC 100 Windows driver is implemented as a Windows Kernel-Mode Driver Framework (KMDF) driver that provides access to the QUAC 100 Post-Quantum Cryptographic Accelerator hardware. The driver follows Microsoft's recommended architecture patterns for PCIe device drivers.

```
┌─────────────────────────────────────────────────────────────────┐
│                      User Applications                          │
├─────────────────────────────────────────────────────────────────┤
│                    quac100lib.dll (User-Mode)                   │
│              Win32 API / DeviceIoControl Interface              │
├─────────────────────────────────────────────────────────────────┤
│                        I/O Manager                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────┐      ┌─────────────────────┐         │
│   │   quac100.sys (PF)  │      │  quac100vf.sys (VF) │         │
│   │   Physical Function │      │  Virtual Function   │         │
│   │      Driver         │      │     Driver          │         │
│   └──────────┬──────────┘      └──────────┬──────────┘         │
│              │                            │                     │
│   ┌──────────┴────────────────────────────┴──────────┐         │
│   │              Hardware Abstraction Layer           │         │
│   │         (PCIe, DMA, Interrupts, Registers)       │         │
│   └──────────────────────┬───────────────────────────┘         │
│                          │                                      │
├──────────────────────────┼──────────────────────────────────────┤
│                          │                                      │
│              ┌───────────┴───────────┐                         │
│              │   QUAC 100 Hardware   │                         │
│              │   PCIe Accelerator    │                         │
│              └───────────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Driver Components

### Physical Function Driver (quac100.sys)

The main driver that manages the physical QUAC 100 device.

#### Core Modules

| Module | File | Description |
|--------|------|-------------|
| Driver Entry | `driver.c` | WDF driver initialization, DriverEntry |
| Device | `device.c` | Device creation, PnP, power management |
| Queue | `queue.c` | I/O request queue management |
| IOCTL | `ioctl.c` | Device I/O control request handling |

#### Hardware Abstraction Layer (HAL)

| Module | File | Description |
|--------|------|-------------|
| Registers | `registers.c/h` | Register definitions and access |
| PCIe | `pcie.c/h` | PCIe configuration and BAR mapping |
| DMA | `dma.c/h` | DMA engine and transfer management |
| Interrupts | `interrupt.c/h` | MSI-X interrupt handling |

#### Cryptographic Engines

| Module | File | Description |
|--------|------|-------------|
| KEM | `kem.c/h` | ML-KEM (Kyber) operations |
| Sign | `sign.c/h` | ML-DSA and SLH-DSA signatures |
| QRNG | `qrng.c/h` | Quantum random number generation |

#### Support Modules

| Module | File | Description |
|--------|------|-------------|
| Power | `power.c/h` | Power state management |
| Diagnostics | `health.c`, `selftest.c` | Hardware health monitoring |
| Job Queue | `jobqueue.c/h` | Async operation scheduling |

### Virtual Function Driver (quac100vf.sys)

SR-IOV Virtual Function driver for virtualized environments.

- Lightweight driver for VM guests
- Communicates through VF BAR resources
- Limited feature set compared to PF

### User-Mode Library (quac100lib.dll)

The user-mode interface library that applications link against.

- Device enumeration and handle management
- IOCTL wrapper functions
- Thread-safe operations
- Error handling and reporting

## Memory Architecture

### BAR Layout

```
BAR0 (16 MB) - Main Control/Status Registers
├── 0x0000-0x00FF: Device Control
├── 0x0100-0x01FF: Device Status
├── 0x0200-0x02FF: Interrupt Control
├── 0x0300-0x03FF: DMA Control
├── 0x1000-0x1FFF: KEM Engine
├── 0x2000-0x2FFF: Sign Engine
├── 0x3000-0x3FFF: QRNG Engine
├── 0x4000-0x4FFF: Key Storage
└── 0x8000-0xFFFF: Reserved

BAR2 (256 MB) - DMA Buffer Region
├── Channel 0: TX Descriptors + Buffers
├── Channel 1: TX Descriptors + Buffers
├── Channel 2: RX Descriptors + Buffers
└── Channel 3: RX Descriptors + Buffers
```

### DMA Architecture

The driver uses scatter-gather DMA with descriptor rings:

```
┌─────────────────┐
│  Descriptor 0   │──► Source PA, Dest PA, Length, Control
├─────────────────┤
│  Descriptor 1   │──► ...
├─────────────────┤
│      ...        │
├─────────────────┤
│  Descriptor N   │
└─────────────────┘
        │
        ▼
   Head/Tail Pointers (Hardware managed)
```

- 4 DMA channels (2 TX, 2 RX)
- 64-byte aligned descriptors
- Maximum 4 MB per transfer
- Completion via MSI-X interrupts

## Interrupt Handling

### MSI-X Vector Assignment

| Vector | Purpose |
|--------|---------|
| 0 | DMA TX Channel 0 Completion |
| 1 | DMA TX Channel 1 Completion |
| 2 | DMA RX Channel 0 Completion |
| 3 | DMA RX Channel 1 Completion |
| 4 | Crypto Engine Done |
| 5 | Crypto Engine Error |
| 6 | QRNG Entropy Ready |
| 7 | QRNG Entropy Low |
| 8-15 | Reserved |

### Interrupt Flow

```
Hardware Interrupt
       │
       ▼
┌──────────────┐
│     ISR      │  IRQL: DIRQL
│  (Minimal)   │  - Read status
└──────┬───────┘  - Acknowledge
       │          - Queue DPC
       ▼
┌──────────────┐
│     DPC      │  IRQL: DISPATCH_LEVEL
│  (Deferred)  │  - Process completion
└──────┬───────┘  - Signal events
       │          - Complete requests
       ▼
   Application
```

## Request Flow

### Synchronous Operation

```
Application                 Driver                    Hardware
    │                         │                          │
    │  DeviceIoControl()      │                          │
    ├────────────────────────►│                          │
    │                         │  Allocate DMA buffer     │
    │                         ├─────────────────────────►│
    │                         │                          │
    │                         │  Submit command          │
    │                         ├─────────────────────────►│
    │                         │                          │
    │                         │  Wait for completion     │
    │                         │◄─────────────────────────┤
    │                         │                          │
    │  Return result          │                          │
    │◄────────────────────────┤                          │
    │                         │                          │
```

### Asynchronous Operation

```
Application                 Driver                    Hardware
    │                         │                          │
    │  DeviceIoControl()      │                          │
    │  (OVERLAPPED)           │                          │
    ├────────────────────────►│                          │
    │                         │  Queue job               │
    │  STATUS_PENDING         │                          │
    │◄────────────────────────┤                          │
    │                         │                          │
    │                         │  Worker thread           │
    │                         ├─────────────────────────►│
    │                         │                          │
    │                         │  MSI-X Interrupt         │
    │                         │◄─────────────────────────┤
    │                         │                          │
    │  GetOverlappedResult()  │  Complete request        │
    ├────────────────────────►├─────────────────────────►│
    │                         │                          │
```

## Security Considerations

### Memory Protection

- All key material in non-paged pool
- Secure zero on deallocation (RtlSecureZeroMemory)
- No key material in pageable memory
- DMA buffers cleared after use

### Access Control

- Device accessible only to authenticated users
- IOCTL validation at driver boundary
- Buffer size validation
- Algorithm parameter validation

### Hardware Security

- Tamper detection monitoring
- Secure key storage region
- Hardware health monitoring
- Entropy quality validation

## Power Management

### Power States

| State | Description | Hardware |
|-------|-------------|----------|
| D0 | Working | Fully powered |
| D1 | Light sleep | Clocks gated |
| D2 | Deep sleep | Most power off |
| D3 | Off | Minimal power |

### Power Transitions

```
        ┌─────┐
        │ D0  │ ◄─── Working
        └──┬──┘
           │ Idle timeout
           ▼
        ┌─────┐
        │ D1  │ ◄─── Light Sleep
        └──┬──┘
           │ Extended idle
           ▼
        ┌─────┐
        │ D2  │ ◄─── Deep Sleep
        └──┬──┘
           │ System sleep/hibernate
           ▼
        ┌─────┐
        │ D3  │ ◄─── Off
        └─────┘
```

## Error Handling

### Error Categories

| Category | Examples | Recovery |
|----------|----------|----------|
| Transient | DMA timeout, busy | Retry |
| Recoverable | Health warning | Reset engine |
| Fatal | Hardware failure | Device reset |
| Unrecoverable | Tamper detected | Disable device |

### Error Reporting

- NTSTATUS codes to kernel
- QUAC_ERROR codes to user-mode
- Event log entries for critical errors
- WPP tracing for debugging

## Threading Model

### Driver Threads

| Thread | Purpose | Priority |
|--------|---------|----------|
| System Worker | I/O completion | Normal |
| Job Queue | Async crypto ops | Above Normal |
| Health Monitor | Background checks | Below Normal |

### Synchronization

- Spinlocks for hardware register access
- Mutexes for device state
- Events for completion signaling
- Interlocked operations for statistics

## Testing Architecture

### Test Levels

1. **Unit Tests**: Individual function testing
2. **Integration Tests**: Component interaction
3. **Hardware Tests**: Physical device validation
4. **Stress Tests**: Load and endurance testing
5. **HLK Tests**: Windows certification

### Test Coverage

- API contract validation
- Error path testing
- Boundary condition testing
- Performance benchmarking
- Security validation

## Version Compatibility

### Supported Windows Versions

| Version | Support Level |
|---------|--------------|
| Windows 11 23H2+ | Full |
| Windows 11 22H2 | Full |
| Windows 10 22H2 | Limited |
| Windows Server 2022 | Full |
| Windows Server 2019 | Limited |

### Driver Versioning

```
Major.Minor.Patch.Build
  │     │     │     │
  │     │     │     └── Build number (auto-increment)
  │     │     └──────── Bug fixes
  │     └────────────── New features
  └──────────────────── Breaking changes
```

## Related Documentation

- [Building Guide](building.md)
- [Installation Guide](installation.md)
- [IOCTL Reference](ioctl_reference.md)
- [Debugging Guide](debugging.md)

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
