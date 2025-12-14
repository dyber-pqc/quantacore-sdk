/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - Main Header
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 *
 * This driver provides kernel-level support for the QUAC 100 PCIe
 * hardware security module, implementing post-quantum cryptographic
 * algorithms including ML-KEM (Kyber), ML-DSA (Dilithium), and
 * SLH-DSA (SPHINCS+).
 */

#ifndef _QUAC100_DRV_H_
#define _QUAC100_DRV_H_

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>

/*=============================================================================
 * Driver Information
 *=============================================================================*/

#define QUAC100_DRIVER_NAME "quac100"
#define QUAC100_DRIVER_VERSION "1.0.0"
#define QUAC100_DRIVER_DESC "QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator"
#define QUAC100_DRIVER_AUTHOR "Dyber, Inc."
#define QUAC100_DRIVER_LICENSE "GPL v2"

/*=============================================================================
 * PCI Device Identification
 *=============================================================================*/

#define QUAC100_PCI_VENDOR_ID 0x1DYB  /* Dyber vendor ID (placeholder) */
#define QUAC100_PCI_DEVICE_ID 0x0100  /* QUAC 100 device ID */
#define QUAC100_PCI_SUBSYS_STD 0x0001 /* Standard edition */
#define QUAC100_PCI_SUBSYS_ENT 0x0002 /* Enterprise edition */
#define QUAC100_PCI_SUBSYS_GOV 0x0003 /* Government/FIPS edition */

/* For development/testing - use placeholder IDs */
#ifndef QUAC100_PCI_VENDOR_ID
#define QUAC100_PCI_VENDOR_ID 0x1234
#endif

/*=============================================================================
 * Hardware Constants
 *=============================================================================*/

/* BAR definitions */
#define QUAC100_BAR_REGS 0 /* Control registers (BAR0) */
#define QUAC100_BAR_MSIX 2 /* MSI-X table (BAR2) */
#define QUAC100_BAR_SRAM 4 /* On-chip SRAM (BAR4) */

#define QUAC100_BAR0_SIZE (64 * 1024 * 1024) /* 64 MB */
#define QUAC100_BAR2_SIZE (4 * 1024)         /* 4 KB */
#define QUAC100_BAR4_SIZE (16 * 1024 * 1024) /* 16 MB */

/* Register offsets (BAR0) */
#define QUAC100_REG_DEVICE_ID 0x0000
#define QUAC100_REG_DEVICE_REV 0x0004
#define QUAC100_REG_DEVICE_STATUS 0x0008
#define QUAC100_REG_DEVICE_CONTROL 0x000C
#define QUAC100_REG_DEVICE_CAPS 0x0010
#define QUAC100_REG_FW_VERSION 0x0020
#define QUAC100_REG_FW_BUILD 0x0024
#define QUAC100_REG_SCRATCH 0x0080
#define QUAC100_REG_RESET 0x00F0

/* Interrupt registers */
#define QUAC100_REG_INT_STATUS 0x1000
#define QUAC100_REG_INT_ENABLE 0x1004
#define QUAC100_REG_INT_MASK 0x1008
#define QUAC100_REG_INT_FORCE 0x100C
#define QUAC100_REG_MSIX_CONTROL 0x1010

/* DMA registers */
#define QUAC100_REG_DMA_CONTROL 0x2000
#define QUAC100_REG_DMA_STATUS 0x2004
#define QUAC100_REG_DMA_CH_BASE 0x2100
#define QUAC100_REG_DMA_CH_STRIDE 0x0080

/* Per-channel DMA registers */
#define QUAC100_REG_DMA_CH_CTRL 0x0000
#define QUAC100_REG_DMA_CH_STATUS 0x0004
#define QUAC100_REG_DMA_CH_DESC_LO 0x0010
#define QUAC100_REG_DMA_CH_DESC_HI 0x0014
#define QUAC100_REG_DMA_CH_SIZE 0x0018
#define QUAC100_REG_DMA_CH_HEAD 0x0020
#define QUAC100_REG_DMA_CH_TAIL 0x0024
#define QUAC100_REG_DMA_CH_DOORBELL 0x0028

/* Crypto engine registers */
#define QUAC100_REG_CRYPTO_CTRL 0x3000
#define QUAC100_REG_CRYPTO_STATUS 0x3004
#define QUAC100_REG_NTT_CTRL 0x3100
#define QUAC100_REG_NTT_STATUS 0x3104
#define QUAC100_REG_QRNG_CTRL 0x3200
#define QUAC100_REG_QRNG_STATUS 0x3204
#define QUAC100_REG_QRNG_ENTROPY 0x3208

/* Temperature and power registers */
#define QUAC100_REG_TEMP_CORE 0x3800
#define QUAC100_REG_TEMP_MEMORY 0x3804
#define QUAC100_REG_VOLTAGE_CORE 0x3810
#define QUAC100_REG_POWER_DRAW 0x3820

/* Memory regions */
#define QUAC100_DESC_RING_BASE 0x00010000
#define QUAC100_DESC_RING_SIZE 0x00010000 /* 64 KB */
#define QUAC100_KEY_STORAGE_BASE 0x00100000
#define QUAC100_KEY_STORAGE_SIZE 0x00100000 /* 1 MB */
#define QUAC100_WORK_MEM_BASE 0x00200000
#define QUAC100_WORK_MEM_SIZE 0x03E00000 /* 62 MB */

/*=============================================================================
 * Register Bit Definitions
 *=============================================================================*/

/* Device control */
#define QUAC100_DEVCTL_ENABLE BIT(0)
#define QUAC100_DEVCTL_DMA_ENABLE BIT(1)
#define QUAC100_DEVCTL_INT_ENABLE BIT(2)
#define QUAC100_DEVCTL_FIPS_MODE BIT(4)
#define QUAC100_DEVCTL_ZEROIZE BIT(8)
#define QUAC100_DEVCTL_RESET BIT(31)

/* Device status */
#define QUAC100_DEVSTS_READY BIT(0)
#define QUAC100_DEVSTS_ERROR BIT(1)
#define QUAC100_DEVSTS_BUSY BIT(2)
#define QUAC100_DEVSTS_SELFTEST_OK BIT(4)
#define QUAC100_DEVSTS_FIPS_OK BIT(5)
#define QUAC100_DEVSTS_TEMP_WARN BIT(8)
#define QUAC100_DEVSTS_TEMP_CRIT BIT(9)
#define QUAC100_DEVSTS_TAMPER BIT(12)

/* Interrupt bits */
#define QUAC100_INT_DMA_TX0_DONE BIT(0)
#define QUAC100_INT_DMA_TX1_DONE BIT(1)
#define QUAC100_INT_DMA_RX0_DONE BIT(2)
#define QUAC100_INT_DMA_RX1_DONE BIT(3)
#define QUAC100_INT_DMA_ERROR BIT(4)
#define QUAC100_INT_CRYPTO_DONE BIT(8)
#define QUAC100_INT_CRYPTO_ERROR BIT(9)
#define QUAC100_INT_ENTROPY_LOW BIT(12)
#define QUAC100_INT_TEMP_ALERT BIT(16)
#define QUAC100_INT_ERROR BIT(24)
#define QUAC100_INT_FATAL BIT(31)

#define QUAC100_INT_DMA_ALL (QUAC100_INT_DMA_TX0_DONE | \
                             QUAC100_INT_DMA_TX1_DONE | \
                             QUAC100_INT_DMA_RX0_DONE | \
                             QUAC100_INT_DMA_RX1_DONE | \
                             QUAC100_INT_DMA_ERROR)

/* DMA channel control */
#define QUAC100_DMA_CH_ENABLE BIT(0)
#define QUAC100_DMA_CH_START BIT(1)
#define QUAC100_DMA_CH_STOP BIT(2)
#define QUAC100_DMA_CH_RESET BIT(3)
#define QUAC100_DMA_CH_IRQ_ENABLE BIT(8)

/*=============================================================================
 * Driver Limits
 *=============================================================================*/

#define QUAC100_MAX_DEVICES 16
#define QUAC100_MAX_MSIX_VECTORS 32
#define QUAC100_DEFAULT_MSIX 8
#define QUAC100_MAX_VFS 16
#define QUAC100_DMA_CHANNELS 4
#define QUAC100_MAX_DMA_RING_SIZE 4096
#define QUAC100_DEFAULT_RING_SIZE 256
#define QUAC100_MAX_BATCH_SIZE 1024
#define QUAC100_MAX_KEY_SLOTS 256
#define QUAC100_MAX_PENDING_JOBS 4096

/* DMA transfer limits */
#define QUAC100_DMA_MAX_XFER_SIZE (16 * 1024 * 1024) /* 16 MB */
#define QUAC100_DMA_ALIGNMENT 64
#define QUAC100_DMA_DESC_ALIGNMENT 64

/*=============================================================================
 * IOCTL Definitions
 *=============================================================================*/

#define QUAC100_IOCTL_MAGIC 'Q'

/* Device management */
#define QUAC100_IOCTL_GET_VERSION _IOR(QUAC100_IOCTL_MAGIC, 0x00, __u32)
#define QUAC100_IOCTL_GET_INFO _IOR(QUAC100_IOCTL_MAGIC, 0x01, struct quac100_device_info)
#define QUAC100_IOCTL_GET_CAPS _IOR(QUAC100_IOCTL_MAGIC, 0x02, __u32)
#define QUAC100_IOCTL_GET_STATUS _IOR(QUAC100_IOCTL_MAGIC, 0x03, __u32)
#define QUAC100_IOCTL_RESET _IOW(QUAC100_IOCTL_MAGIC, 0x04, __u32)

/* DMA */
#define QUAC100_IOCTL_DMA_ALLOC _IOWR(QUAC100_IOCTL_MAGIC, 0x20, struct quac100_dma_buf)
#define QUAC100_IOCTL_DMA_FREE _IOW(QUAC100_IOCTL_MAGIC, 0x21, __u64)
#define QUAC100_IOCTL_DMA_MAP _IOWR(QUAC100_IOCTL_MAGIC, 0x22, struct quac100_dma_map)
#define QUAC100_IOCTL_DMA_UNMAP _IOW(QUAC100_IOCTL_MAGIC, 0x23, __u64)
#define QUAC100_IOCTL_DMA_SYNC _IOW(QUAC100_IOCTL_MAGIC, 0x24, struct quac100_dma_sync)

/* Cryptographic operations */
#define QUAC100_IOCTL_KEM_KEYGEN _IOWR(QUAC100_IOCTL_MAGIC, 0x40, struct quac100_kem_keygen)
#define QUAC100_IOCTL_KEM_ENCAPS _IOWR(QUAC100_IOCTL_MAGIC, 0x41, struct quac100_kem_encaps)
#define QUAC100_IOCTL_KEM_DECAPS _IOWR(QUAC100_IOCTL_MAGIC, 0x42, struct quac100_kem_decaps)
#define QUAC100_IOCTL_SIGN_KEYGEN _IOWR(QUAC100_IOCTL_MAGIC, 0x43, struct quac100_sign_keygen)
#define QUAC100_IOCTL_SIGN _IOWR(QUAC100_IOCTL_MAGIC, 0x44, struct quac100_sign)
#define QUAC100_IOCTL_VERIFY _IOWR(QUAC100_IOCTL_MAGIC, 0x45, struct quac100_verify)
#define QUAC100_IOCTL_RANDOM _IOWR(QUAC100_IOCTL_MAGIC, 0x46, struct quac100_random)

/* Batch operations */
#define QUAC100_IOCTL_BATCH_SUBMIT _IOWR(QUAC100_IOCTL_MAGIC, 0x80, struct quac100_batch)
#define QUAC100_IOCTL_BATCH_STATUS _IOWR(QUAC100_IOCTL_MAGIC, 0x81, struct quac100_batch_status)
#define QUAC100_IOCTL_BATCH_CANCEL _IOW(QUAC100_IOCTL_MAGIC, 0x82, __u64)

/* Async operations */
#define QUAC100_IOCTL_ASYNC_SUBMIT _IOWR(QUAC100_IOCTL_MAGIC, 0xA0, struct quac100_async_submit)
#define QUAC100_IOCTL_ASYNC_POLL _IOWR(QUAC100_IOCTL_MAGIC, 0xA1, struct quac100_async_poll)
#define QUAC100_IOCTL_ASYNC_WAIT _IOWR(QUAC100_IOCTL_MAGIC, 0xA2, struct quac100_async_wait)
#define QUAC100_IOCTL_ASYNC_CANCEL _IOW(QUAC100_IOCTL_MAGIC, 0xA3, __u64)

/* Key management */
#define QUAC100_IOCTL_KEY_GENERATE _IOWR(QUAC100_IOCTL_MAGIC, 0xC0, struct quac100_key_gen)
#define QUAC100_IOCTL_KEY_IMPORT _IOWR(QUAC100_IOCTL_MAGIC, 0xC1, struct quac100_key_import)
#define QUAC100_IOCTL_KEY_EXPORT _IOWR(QUAC100_IOCTL_MAGIC, 0xC2, struct quac100_key_export)
#define QUAC100_IOCTL_KEY_DELETE _IOW(QUAC100_IOCTL_MAGIC, 0xC3, __u64)

/* Diagnostics */
#define QUAC100_IOCTL_SELF_TEST _IOWR(QUAC100_IOCTL_MAGIC, 0xE0, struct quac100_self_test)
#define QUAC100_IOCTL_GET_HEALTH _IOR(QUAC100_IOCTL_MAGIC, 0xE1, struct quac100_health)
#define QUAC100_IOCTL_GET_TEMP _IOR(QUAC100_IOCTL_MAGIC, 0xE2, __s32)
#define QUAC100_IOCTL_GET_COUNTERS _IOR(QUAC100_IOCTL_MAGIC, 0xE3, struct quac100_counters)

/*=============================================================================
 * IOCTL Data Structures
 *=============================================================================*/

/* Device information */
struct quac100_device_info
{
    __u32 struct_size;
    __u32 driver_version;
    __u32 device_index;
    char device_name[64];
    char serial_number[32];
    __u16 vendor_id;
    __u16 device_id;
    __u16 subsystem_id;
    __u16 revision;
    __u32 fw_version;
    __u32 capabilities;
    __u32 status;
    __u32 max_batch_size;
    __u32 max_pending_jobs;
    __u32 key_slots_total;
    __u32 key_slots_used;
};

/* DMA buffer allocation */
struct quac100_dma_buf
{
    __u64 size;
    __u64 handle;
    __u64 phys_addr;
    __u64 user_addr;
    __u32 flags;
    __u32 reserved;
};

/* DMA mapping */
struct quac100_dma_map
{
    __u64 user_addr;
    __u64 size;
    __u64 handle;
    __u64 dma_addr;
    __u32 direction;
    __u32 reserved;
};

/* DMA sync */
struct quac100_dma_sync
{
    __u64 handle;
    __u64 offset;
    __u64 size;
    __u32 direction;
    __u32 reserved;
};

/* Algorithm identifiers */
enum quac100_algorithm
{
    QUAC100_ALG_NONE = 0x0000,
    /* ML-KEM (Kyber) */
    QUAC100_ALG_KYBER512 = 0x1100,
    QUAC100_ALG_KYBER768 = 0x1101,
    QUAC100_ALG_KYBER1024 = 0x1102,
    /* ML-DSA (Dilithium) */
    QUAC100_ALG_DILITHIUM2 = 0x2100,
    QUAC100_ALG_DILITHIUM3 = 0x2101,
    QUAC100_ALG_DILITHIUM5 = 0x2102,
    /* SLH-DSA (SPHINCS+) */
    QUAC100_ALG_SPHINCS_SHA2_128S = 0x2200,
    QUAC100_ALG_SPHINCS_SHA2_128F = 0x2201,
    QUAC100_ALG_SPHINCS_SHA2_192S = 0x2202,
    QUAC100_ALG_SPHINCS_SHA2_192F = 0x2203,
    QUAC100_ALG_SPHINCS_SHA2_256S = 0x2204,
    QUAC100_ALG_SPHINCS_SHA2_256F = 0x2205,
};

/* KEM key generation */
struct quac100_kem_keygen
{
    __u32 algorithm;
    __u32 flags;
    __u64 pk_addr;
    __u32 pk_size;
    __u32 pk_actual;
    __u64 sk_addr;
    __u32 sk_size;
    __u32 sk_actual;
    __s32 result;
    __u32 reserved;
};

/* KEM encapsulation */
struct quac100_kem_encaps
{
    __u32 algorithm;
    __u32 flags;
    __u64 pk_addr;
    __u32 pk_size;
    __u32 reserved1;
    __u64 ct_addr;
    __u32 ct_size;
    __u32 ct_actual;
    __u64 ss_addr;
    __u32 ss_size;
    __s32 result;
};

/* KEM decapsulation */
struct quac100_kem_decaps
{
    __u32 algorithm;
    __u32 flags;
    __u64 ct_addr;
    __u32 ct_size;
    __u32 reserved1;
    __u64 sk_addr;
    __u32 sk_size;
    __u32 reserved2;
    __u64 ss_addr;
    __u32 ss_size;
    __s32 result;
};

/* Signature key generation */
struct quac100_sign_keygen
{
    __u32 algorithm;
    __u32 flags;
    __u64 pk_addr;
    __u32 pk_size;
    __u32 pk_actual;
    __u64 sk_addr;
    __u32 sk_size;
    __u32 sk_actual;
    __s32 result;
    __u32 reserved;
};

/* Signing */
struct quac100_sign
{
    __u32 algorithm;
    __u32 flags;
    __u64 sk_addr;
    __u32 sk_size;
    __u32 reserved1;
    __u64 msg_addr;
    __u32 msg_size;
    __u32 reserved2;
    __u64 sig_addr;
    __u32 sig_size;
    __u32 sig_actual;
    __s32 result;
    __u32 reserved3;
};

/* Verification */
struct quac100_verify
{
    __u32 algorithm;
    __u32 flags;
    __u64 pk_addr;
    __u32 pk_size;
    __u32 reserved1;
    __u64 msg_addr;
    __u32 msg_size;
    __u32 reserved2;
    __u64 sig_addr;
    __u32 sig_size;
    __s32 result;
};

/* Random generation */
struct quac100_random
{
    __u64 buf_addr;
    __u32 length;
    __u32 quality;
    __s32 result;
    __u32 reserved;
};

/* Batch operation */
struct quac100_batch
{
    __u64 items_addr;
    __u32 item_count;
    __u32 item_size;
    __u32 flags;
    __u32 timeout_ms;
    __u64 job_id;
    __u32 completed;
    __u32 failed;
    __s32 result;
    __u32 reserved;
};

/* Batch status */
struct quac100_batch_status
{
    __u64 job_id;
    __u32 status;
    __u32 progress;
    __u32 completed;
    __u32 failed;
    __s32 result;
    __u32 reserved;
};

/* Async submit */
struct quac100_async_submit
{
    __u32 operation;
    __u32 algorithm;
    __u32 flags;
    __u32 priority;
    __u32 timeout_ms;
    __u32 reserved1;
    __u64 input_addr;
    __u32 input_size;
    __u32 reserved2;
    __u64 output_addr;
    __u32 output_size;
    __u32 reserved3;
    __u64 job_id;
    __s32 result;
    __u32 reserved4;
};

/* Async poll */
struct quac100_async_poll
{
    __u64 job_id;
    __u32 status;
    __u32 progress;
    __s32 result;
    __u32 reserved;
};

/* Async wait */
struct quac100_async_wait
{
    __u64 job_id;
    __u32 timeout_ms;
    __u32 status;
    __s32 result;
    __u32 reserved;
};

/* Key generation */
struct quac100_key_gen
{
    __u32 algorithm;
    __u32 usage;
    __u32 flags;
    __u32 reserved1;
    __u64 label_addr;
    __u32 label_len;
    __u32 reserved2;
    __u64 handle;
    __u64 pk_addr;
    __u32 pk_size;
    __s32 result;
};

/* Key import */
struct quac100_key_import
{
    __u32 algorithm;
    __u32 key_type;
    __u32 usage;
    __u32 flags;
    __u64 label_addr;
    __u32 label_len;
    __u32 reserved1;
    __u64 key_addr;
    __u32 key_len;
    __u32 reserved2;
    __u64 handle;
    __s32 result;
    __u32 reserved3;
};

/* Key export */
struct quac100_key_export
{
    __u64 handle;
    __u32 key_type;
    __u32 reserved1;
    __u64 key_addr;
    __u32 key_size;
    __u32 actual_len;
    __s32 result;
    __u32 reserved2;
};

/* Self-test */
struct quac100_self_test
{
    __u32 tests;
    __u32 flags;
    __u32 tests_passed;
    __u32 tests_failed;
    __u32 duration_us;
    __s32 result;
};

/* Health status */
struct quac100_health
{
    __u32 state;
    __u32 flags;
    __s32 temp_core;
    __s32 temp_memory;
    __u32 voltage_mv;
    __u32 power_mw;
    __u32 clock_mhz;
    __u32 entropy_bits;
    __u64 uptime_sec;
    __u64 ops_completed;
    __u64 ops_failed;
};

/* Performance counters */
struct quac100_counters
{
    __u64 kem_keygen_count;
    __u64 kem_encaps_count;
    __u64 kem_decaps_count;
    __u64 sign_keygen_count;
    __u64 sign_count;
    __u64 verify_count;
    __u64 random_bytes;
    __u64 dma_read_bytes;
    __u64 dma_write_bytes;
    __u64 errors_total;
};

/*=============================================================================
 * Internal Driver Structures
 *=============================================================================*/

/* Forward declarations */
struct quac100_device;
struct quac100_dma_channel;

/* DMA descriptor (hardware format) */
struct quac100_dma_desc
{
    __le64 buffer_addr;
    __le32 length;
    __le16 flags;
    __le16 tag;
    __le64 next_desc;
    __le32 operation;
    __le32 algorithm;
    __le64 user_data;
    __le32 status;
    __le32 bytes_xfer;
    __le64 timestamp;
} __packed __aligned(64);

/* DMA descriptor flags */
#define QUAC100_DESC_FLAG_SOP BIT(0)
#define QUAC100_DESC_FLAG_EOP BIT(1)
#define QUAC100_DESC_FLAG_IRQ BIT(2)
#define QUAC100_DESC_FLAG_CHAIN BIT(3)
#define QUAC100_DESC_FLAG_ERROR BIT(8)
#define QUAC100_DESC_FLAG_COMPLETE BIT(9)

/* DMA ring */
struct quac100_dma_ring
{
    struct quac100_dma_desc *descs; /* Descriptor array */
    dma_addr_t descs_dma;           /* Descriptors DMA address */
    u32 ring_size;                  /* Number of descriptors */
    u32 head;                       /* Producer index */
    u32 tail;                       /* Consumer index */
    spinlock_t lock;                /* Ring lock */
    struct completion completion;   /* Completion event */
};

/* DMA channel */
struct quac100_dma_channel
{
    struct quac100_device *qdev;  /* Parent device */
    u32 channel_id;               /* Channel number */
    u32 direction;                /* DMA_TO_DEVICE or DMA_FROM_DEVICE */
    void __iomem *regs;           /* Channel registers */
    struct quac100_dma_ring ring; /* Descriptor ring */
    u64 bytes_transferred;        /* Total bytes */
    u64 transfers_completed;      /* Total transfers */
    u64 errors;                   /* Error count */
    bool enabled;                 /* Channel enabled */
};

/* Async job */
struct quac100_job
{
    u64 job_id;
    u32 operation;
    u32 algorithm;
    u32 status;
    u32 priority;
    int result;
    struct completion completion;
    void *input;
    size_t input_size;
    void *output;
    size_t output_size;
    struct list_head list;
    ktime_t submit_time;
    ktime_t start_time;
    ktime_t complete_time;
    void *user_data;
};

/* Job status values */
#define QUAC100_JOB_PENDING 0
#define QUAC100_JOB_RUNNING 1
#define QUAC100_JOB_COMPLETED 2
#define QUAC100_JOB_FAILED 3
#define QUAC100_JOB_CANCELLED 4

/* Statistics */
struct quac100_stats
{
    atomic64_t kem_keygen_count;
    atomic64_t kem_encaps_count;
    atomic64_t kem_decaps_count;
    atomic64_t sign_keygen_count;
    atomic64_t sign_count;
    atomic64_t verify_count;
    atomic64_t random_bytes;
    atomic64_t dma_read_bytes;
    atomic64_t dma_write_bytes;
    atomic64_t errors;
    atomic64_t ops_completed;
    atomic64_t ops_failed;
};

/* Main device structure */
struct quac100_device
{
    /* PCI device */
    struct pci_dev *pdev;
    int dev_index;
    char name[32];

    /* Memory mappings */
    void __iomem *bar0; /* Control registers */
    void __iomem *bar2; /* MSI-X table */
    void __iomem *bar4; /* SRAM (optional) */
    resource_size_t bar0_len;
    resource_size_t bar2_len;
    resource_size_t bar4_len;

    /* Character device */
    struct cdev cdev;
    dev_t devno;
    struct device *dev;

    /* Interrupts */
    int num_vectors;
    struct msix_entry *msix_entries;
    int irqs[QUAC100_MAX_MSIX_VECTORS];

    /* DMA */
    struct quac100_dma_channel dma_channels[QUAC100_DMA_CHANNELS];
    struct dma_pool *desc_pool;

    /* Async job management */
    struct idr job_idr;
    spinlock_t job_lock;
    struct list_head job_pending;
    struct list_head job_running;
    struct workqueue_struct *work_queue;
    struct work_struct job_work;
    u64 next_job_id;

    /* Key storage */
    struct idr key_idr;
    struct mutex key_lock;
    u32 key_slots_used;

    /* Device state */
    u32 hw_version;
    u32 fw_version;
    u32 capabilities;
    u32 status;
    char serial_number[32];
    bool initialized;
    bool enabled;
    struct mutex dev_lock;

    /* Statistics */
    struct quac100_stats stats;

    /* SR-IOV */
    int num_vfs;
    bool sriov_enabled;

    /* sysfs */
    struct kobject *kobj;
};

/*=============================================================================
 * Module Parameters (declared in quac100_main.c)
 *=============================================================================*/

extern int max_devices;
extern int dma_ring_size;
extern int msix_vectors;
extern int enable_sriov;
extern int num_vfs;
extern int debug_level;

/*=============================================================================
 * Debug Macros
 *=============================================================================*/

#define QUAC100_DEBUG_NONE 0
#define QUAC100_DEBUG_ERROR 1
#define QUAC100_DEBUG_WARN 2
#define QUAC100_DEBUG_INFO 3
#define QUAC100_DEBUG_DEBUG 4
#define QUAC100_DEBUG_TRACE 5

#define quac100_err(qdev, fmt, ...) \
    dev_err(&(qdev)->pdev->dev, fmt, ##__VA_ARGS__)

#define quac100_warn(qdev, fmt, ...) \
    dev_warn(&(qdev)->pdev->dev, fmt, ##__VA_ARGS__)

#define quac100_info(qdev, fmt, ...) \
    dev_info(&(qdev)->pdev->dev, fmt, ##__VA_ARGS__)

#define quac100_dbg(qdev, fmt, ...)                          \
    do                                                       \
    {                                                        \
        if (debug_level >= QUAC100_DEBUG_DEBUG)              \
            dev_dbg(&(qdev)->pdev->dev, fmt, ##__VA_ARGS__); \
    } while (0)

#define quac100_trace(qdev, fmt, ...)                                   \
    do                                                                  \
    {                                                                   \
        if (debug_level >= QUAC100_DEBUG_TRACE)                         \
            dev_dbg(&(qdev)->pdev->dev, "[TRACE] " fmt, ##__VA_ARGS__); \
    } while (0)

/*=============================================================================
 * Register Access Helpers
 *=============================================================================*/

static inline u32 quac100_read32(struct quac100_device *qdev, u32 offset)
{
    return ioread32(qdev->bar0 + offset);
}

static inline void quac100_write32(struct quac100_device *qdev, u32 offset, u32 value)
{
    iowrite32(value, qdev->bar0 + offset);
}

static inline u64 quac100_read64(struct quac100_device *qdev, u32 offset)
{
    return ioread64(qdev->bar0 + offset);
}

static inline void quac100_write64(struct quac100_device *qdev, u32 offset, u64 value)
{
    iowrite64(value, qdev->bar0 + offset);
}

/*=============================================================================
 * Function Declarations - quac100_main.c
 *=============================================================================*/

int quac100_device_init(struct quac100_device *qdev);
void quac100_device_cleanup(struct quac100_device *qdev);
int quac100_device_enable(struct quac100_device *qdev);
void quac100_device_disable(struct quac100_device *qdev);
int quac100_device_reset(struct quac100_device *qdev, u32 type);

/*=============================================================================
 * Function Declarations - quac100_pcie.c
 *=============================================================================*/

int quac100_pcie_init(struct quac100_device *qdev);
void quac100_pcie_cleanup(struct quac100_device *qdev);
int quac100_pcie_enable_device(struct quac100_device *qdev);
void quac100_pcie_disable_device(struct quac100_device *qdev);

/*=============================================================================
 * Function Declarations - quac100_dma.c
 *=============================================================================*/

int quac100_dma_init(struct quac100_device *qdev);
void quac100_dma_cleanup(struct quac100_device *qdev);
int quac100_dma_channel_start(struct quac100_device *qdev, u32 channel);
void quac100_dma_channel_stop(struct quac100_device *qdev, u32 channel);
int quac100_dma_submit(struct quac100_device *qdev, u32 channel,
                       dma_addr_t addr, size_t len, u32 flags);
int quac100_dma_wait(struct quac100_device *qdev, u32 channel, u32 timeout_ms);
void quac100_dma_process_completions(struct quac100_device *qdev, u32 channel);

/*=============================================================================
 * Function Declarations - quac100_ioctl.c
 *=============================================================================*/

long quac100_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int quac100_ioctl_init(struct quac100_device *qdev);
void quac100_ioctl_cleanup(struct quac100_device *qdev);

/*=============================================================================
 * Function Declarations - quac100_irq.c
 *=============================================================================*/

int quac100_irq_init(struct quac100_device *qdev);
void quac100_irq_cleanup(struct quac100_device *qdev);
void quac100_irq_enable(struct quac100_device *qdev);
void quac100_irq_disable(struct quac100_device *qdev);

/*=============================================================================
 * Function Declarations - quac100_sriov.c
 *=============================================================================*/

int quac100_sriov_init(struct quac100_device *qdev);
void quac100_sriov_cleanup(struct quac100_device *qdev);
int quac100_sriov_enable(struct quac100_device *qdev, int num_vfs);
void quac100_sriov_disable(struct quac100_device *qdev);

/*=============================================================================
 * Function Declarations - quac100_sysfs.c
 *=============================================================================*/

int quac100_sysfs_init(struct quac100_device *qdev);
void quac100_sysfs_cleanup(struct quac100_device *qdev);

/*=============================================================================
 * Global Variables (declared in quac100_main.c)
 *=============================================================================*/

extern struct class *quac100_class;
extern int quac100_major;
extern struct idr quac100_idr;
extern struct mutex quac100_idr_lock;

#endif /* _QUAC100_DRV_H_ */