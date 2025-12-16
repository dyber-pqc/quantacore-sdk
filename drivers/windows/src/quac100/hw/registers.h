/**
 * @file registers.h
 * @brief QUAC 100 Hardware Register Definitions
 *
 * Complete register map for the QUAC 100 Post-Quantum Cryptographic Accelerator.
 * Aligned with Linux SDK quac100_pcie.h register definitions.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 *
 * @par Memory Map (BAR0 - 64MB)
 * | Offset      | Size   | Description                    |
 * |-------------|--------|--------------------------------|
 * | 0x0000_0000 | 4KB    | Device control registers       |
 * | 0x0000_1000 | 4KB    | Interrupt control              |
 * | 0x0000_2000 | 4KB    | DMA engine registers           |
 * | 0x0000_3000 | 4KB    | Cryptographic engine control   |
 * | 0x0001_0000 | 64KB   | Descriptor ring memory         |
 * | 0x0010_0000 | 1MB    | Key storage                    |
 * | 0x0020_0000 | 62MB   | Work memory                    |
 */

#ifndef QUAC100_REGISTERS_H
#define QUAC100_REGISTERS_H

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * PCI Device Identification
 *=============================================================================*/

/** Dyber PCI Vendor ID */
#define QUAC_PCI_VENDOR_ID              0x1DFB

/** QUAC 100 PCI Device ID */
#define QUAC_PCI_DEVICE_ID              0x0100

/** QUAC 100 Subsystem IDs */
#define QUAC_PCI_SUBSYS_STANDARD        0x0001  /**< Standard edition */
#define QUAC_PCI_SUBSYS_ENTERPRISE      0x0002  /**< Enterprise edition */
#define QUAC_PCI_SUBSYS_GOVERNMENT      0x0003  /**< Government/FIPS edition */

/** Device class */
#define QUAC_PCI_CLASS                  0x10    /**< Encryption controller */
#define QUAC_PCI_SUBCLASS               0x80    /**< Other encryption */

/*=============================================================================
 * BAR Definitions
 *=============================================================================*/

/** Number of BARs */
#define QUAC_PCIE_NUM_BARS              3

/** BAR indices */
#define QUAC_PCIE_BAR_REGS              0       /**< Control registers (BAR0) */
#define QUAC_PCIE_BAR_MSIX              2       /**< MSI-X table (BAR2) */
#define QUAC_PCIE_BAR_SRAM              4       /**< On-chip SRAM (BAR4) */

/** BAR0 size */
#define QUAC_PCIE_BAR0_SIZE             (64 * 1024 * 1024)  /* 64 MB */

/** BAR2 size (MSI-X) */
#define QUAC_PCIE_BAR2_SIZE             (4 * 1024)          /* 4 KB */

/** BAR4 size (optional SRAM) */
#define QUAC_PCIE_BAR4_SIZE             (16 * 1024 * 1024)  /* 16 MB */

/*=============================================================================
 * Register Map Offsets (BAR0)
 *=============================================================================*/

/**
 * @name Device Control Registers (0x0000 - 0x0FFF)
 * @{
 */
#define QUAC_REG_DEVICE_ID              0x0000  /**< Device ID (RO) */
#define QUAC_REG_DEVICE_REV             0x0004  /**< Hardware revision (RO) */
#define QUAC_REG_DEVICE_STATUS          0x0008  /**< Device status (RO) */
#define QUAC_REG_DEVICE_CONTROL         0x000C  /**< Device control (RW) */
#define QUAC_REG_DEVICE_CAPS            0x0010  /**< Capabilities (RO) */
#define QUAC_REG_DEVICE_CAPS2           0x0014  /**< Extended capabilities (RO) */
#define QUAC_REG_FW_VERSION             0x0020  /**< Firmware version (RO) */
#define QUAC_REG_FW_BUILD               0x0024  /**< Firmware build (RO) */
#define QUAC_REG_SERIAL_LO              0x0030  /**< Serial number low (RO) */
#define QUAC_REG_SERIAL_HI              0x0034  /**< Serial number high (RO) */
#define QUAC_REG_UPTIME_LO              0x0040  /**< Uptime seconds low (RO) */
#define QUAC_REG_UPTIME_HI              0x0044  /**< Uptime seconds high (RO) */
#define QUAC_REG_OPS_COMPLETE_LO        0x0050  /**< Ops completed low (RO) */
#define QUAC_REG_OPS_COMPLETE_HI        0x0054  /**< Ops completed high (RO) */
#define QUAC_REG_OPS_FAILED_LO          0x0058  /**< Ops failed low (RO) */
#define QUAC_REG_OPS_FAILED_HI          0x005C  /**< Ops failed high (RO) */
#define QUAC_REG_SCRATCH                0x0080  /**< Scratch register (RW) */
#define QUAC_REG_RESET                  0x00F0  /**< Reset control (WO) */
/** @} */

/**
 * @name Interrupt Control Registers (0x1000 - 0x1FFF)
 * @{
 */
#define QUAC_REG_INT_STATUS             0x1000  /**< Interrupt status (RO/W1C) */
#define QUAC_REG_INT_ENABLE             0x1004  /**< Interrupt enable (RW) */
#define QUAC_REG_INT_MASK               0x1008  /**< Interrupt mask (RW) */
#define QUAC_REG_INT_FORCE              0x100C  /**< Force interrupt (WO) */
#define QUAC_REG_MSIX_CONTROL           0x1010  /**< MSI-X control (RW) */
#define QUAC_REG_MSIX_TABLE_SIZE        0x1014  /**< MSI-X table size (RO) */
#define QUAC_REG_INT_COALESCE           0x1020  /**< Interrupt coalescing (RW) */
#define QUAC_REG_INT_THROTTLE           0x1024  /**< Interrupt throttle (RW) */
/** @} */

/**
 * @name DMA Engine Registers (0x2000 - 0x2FFF)
 * @{
 */
#define QUAC_REG_DMA_CONTROL            0x2000  /**< DMA global control */
#define QUAC_REG_DMA_STATUS             0x2004  /**< DMA global status */
#define QUAC_REG_DMA_ERROR              0x2008  /**< DMA error status */
#define QUAC_REG_DMA_ERROR_ADDR_LO      0x2010  /**< Error address low */
#define QUAC_REG_DMA_ERROR_ADDR_HI      0x2014  /**< Error address high */
#define QUAC_REG_DMA_NUM_CHANNELS       0x2020  /**< Number of channels (RO) */
#define QUAC_REG_DMA_CH_BASE            0x2100  /**< Channel 0 base */
#define QUAC_REG_DMA_CH_STRIDE          0x0080  /**< Channel register stride */

/** Per-channel DMA registers (relative to channel base) */
#define QUAC_REG_DMA_CH_CONTROL         0x0000  /**< Channel control */
#define QUAC_REG_DMA_CH_STATUS          0x0004  /**< Channel status */
#define QUAC_REG_DMA_CH_INT_STATUS      0x0008  /**< Channel interrupt status */
#define QUAC_REG_DMA_CH_INT_ENABLE      0x000C  /**< Channel interrupt enable */
#define QUAC_REG_DMA_CH_DESC_LO         0x0010  /**< Descriptor base low */
#define QUAC_REG_DMA_CH_DESC_HI         0x0014  /**< Descriptor base high */
#define QUAC_REG_DMA_CH_DESC_SIZE       0x0018  /**< Descriptor ring size */
#define QUAC_REG_DMA_CH_DESC_COUNT      0x001C  /**< Descriptor count */
#define QUAC_REG_DMA_CH_HEAD            0x0020  /**< Head pointer */
#define QUAC_REG_DMA_CH_TAIL            0x0024  /**< Tail pointer */
#define QUAC_REG_DMA_CH_DOORBELL        0x0028  /**< Doorbell (write to start) */
#define QUAC_REG_DMA_CH_BYTES_LO        0x0030  /**< Bytes transferred low */
#define QUAC_REG_DMA_CH_BYTES_HI        0x0034  /**< Bytes transferred high */
#define QUAC_REG_DMA_CH_DESC_COMPLETE   0x0038  /**< Descriptors completed */
/** @} */

/**
 * @name Cryptographic Engine Registers (0x3000 - 0x3FFF)
 * @{
 */
#define QUAC_REG_CRYPTO_CONTROL         0x3000  /**< Crypto engine control */
#define QUAC_REG_CRYPTO_STATUS          0x3004  /**< Crypto engine status */
#define QUAC_REG_CRYPTO_ERROR           0x3008  /**< Crypto error status */
#define QUAC_REG_CRYPTO_ALGO            0x300C  /**< Current algorithm */
#define QUAC_REG_CRYPTO_OP_COUNT        0x3010  /**< Operations in progress */
#define QUAC_REG_CRYPTO_QUEUE_DEPTH     0x3014  /**< Queue depth */

/** NTT (Number Theoretic Transform) engine */
#define QUAC_REG_NTT_CONTROL            0x3100  /**< NTT engine control */
#define QUAC_REG_NTT_STATUS             0x3104  /**< NTT engine status */
#define QUAC_REG_NTT_PARAM_N            0x3108  /**< NTT parameter N */
#define QUAC_REG_NTT_PARAM_Q            0x310C  /**< NTT parameter Q */

/** Hash engine */
#define QUAC_REG_HASH_CONTROL           0x3180  /**< Hash engine control */
#define QUAC_REG_HASH_STATUS            0x3184  /**< Hash engine status */

/** QRNG (Quantum Random Number Generator) */
#define QUAC_REG_QRNG_CONTROL           0x3200  /**< QRNG control */
#define QUAC_REG_QRNG_STATUS            0x3204  /**< QRNG status */
#define QUAC_REG_QRNG_ENTROPY           0x3208  /**< Available entropy (bits) */
#define QUAC_REG_QRNG_DATA              0x3210  /**< QRNG data output */
#define QUAC_REG_QRNG_HEALTH            0x3220  /**< QRNG health status */
#define QUAC_REG_QRNG_BIAS_COUNT        0x3224  /**< Bias detected count */
/** @} */

/**
 * @name Temperature and Power Registers (0x3800 - 0x38FF)
 * @{
 */
#define QUAC_REG_TEMP_CORE              0x3800  /**< Core temperature (mC) */
#define QUAC_REG_TEMP_MEMORY            0x3804  /**< Memory temperature (mC) */
#define QUAC_REG_TEMP_THRESHOLD_WARN    0x3810  /**< Warning threshold (mC) */
#define QUAC_REG_TEMP_THRESHOLD_CRIT    0x3814  /**< Critical threshold (mC) */
#define QUAC_REG_VOLTAGE_CORE           0x3820  /**< Core voltage (mV) */
#define QUAC_REG_VOLTAGE_AUX            0x3824  /**< Aux voltage (mV) */
#define QUAC_REG_POWER_DRAW             0x3830  /**< Power consumption (mW) */
#define QUAC_REG_POWER_LIMIT            0x3834  /**< Power limit (mW) */
#define QUAC_REG_CLOCK_FREQ             0x3840  /**< Clock frequency (MHz) */
/** @} */

/**
 * @name Key Storage Registers (0x3900 - 0x39FF)
 * @{
 */
#define QUAC_REG_KEY_CONTROL            0x3900  /**< Key storage control */
#define QUAC_REG_KEY_STATUS             0x3904  /**< Key storage status */
#define QUAC_REG_KEY_SLOT_COUNT         0x3908  /**< Total key slots */
#define QUAC_REG_KEY_SLOTS_USED         0x390C  /**< Used key slots */
#define QUAC_REG_KEY_ZEROIZE            0x3910  /**< Zeroize all keys (WO) */
/** @} */

/**
 * @name Self-Test Registers (0x3A00 - 0x3AFF)
 * @{
 */
#define QUAC_REG_SELFTEST_CONTROL       0x3A00  /**< Self-test control */
#define QUAC_REG_SELFTEST_STATUS        0x3A04  /**< Self-test status */
#define QUAC_REG_SELFTEST_RESULT        0x3A08  /**< Self-test result bitmap */
#define QUAC_REG_SELFTEST_DURATION      0x3A0C  /**< Last test duration (us) */
#define QUAC_REG_FIPS_STATUS            0x3A10  /**< FIPS mode status */
/** @} */

/**
 * @name Memory Regions
 * @{
 */
#define QUAC_REG_DESC_RING_BASE         0x00010000  /**< Descriptor ring base */
#define QUAC_REG_DESC_RING_SIZE         0x00010000  /**< Descriptor ring size (64KB) */
#define QUAC_REG_KEY_STORAGE_BASE       0x00100000  /**< Key storage base */
#define QUAC_REG_KEY_STORAGE_SIZE       0x00100000  /**< Key storage size (1MB) */
#define QUAC_REG_WORK_MEM_BASE          0x00200000  /**< Work memory base */
#define QUAC_REG_WORK_MEM_SIZE          0x03E00000  /**< Work memory size (62MB) */
/** @} */

/*=============================================================================
 * Register Bit Definitions
 *=============================================================================*/

/**
 * @name Device Control Register Bits (QUAC_REG_DEVICE_CONTROL)
 * @{
 */
#define QUAC_DEVCTL_ENABLE              (1 << 0)    /**< Device enable */
#define QUAC_DEVCTL_DMA_ENABLE          (1 << 1)    /**< DMA enable */
#define QUAC_DEVCTL_INT_ENABLE          (1 << 2)    /**< Interrupts enable */
#define QUAC_DEVCTL_CRYPTO_ENABLE       (1 << 3)    /**< Crypto engine enable */
#define QUAC_DEVCTL_FIPS_MODE           (1 << 4)    /**< FIPS mode */
#define QUAC_DEVCTL_QRNG_ENABLE         (1 << 5)    /**< QRNG enable */
#define QUAC_DEVCTL_LOW_POWER           (1 << 6)    /**< Low power mode */
#define QUAC_DEVCTL_ZEROIZE             (1 << 8)    /**< Zeroize keys */
#define QUAC_DEVCTL_SELFTEST_RUN        (1 << 12)   /**< Run self-test */
#define QUAC_DEVCTL_RESET               (1 << 31)   /**< Soft reset */
/** @} */

/**
 * @name Device Status Register Bits (QUAC_REG_DEVICE_STATUS)
 * @{
 */
#define QUAC_DEVSTS_READY               (1 << 0)    /**< Device ready */
#define QUAC_DEVSTS_ERROR               (1 << 1)    /**< Error state */
#define QUAC_DEVSTS_BUSY                (1 << 2)    /**< Device busy */
#define QUAC_DEVSTS_DMA_ACTIVE          (1 << 3)    /**< DMA active */
#define QUAC_DEVSTS_SELF_TEST_OK        (1 << 4)    /**< Self-test passed */
#define QUAC_DEVSTS_FIPS_OK             (1 << 5)    /**< FIPS mode active */
#define QUAC_DEVSTS_QRNG_READY          (1 << 6)    /**< QRNG ready */
#define QUAC_DEVSTS_CRYPTO_READY        (1 << 7)    /**< Crypto engine ready */
#define QUAC_DEVSTS_TEMP_WARN           (1 << 8)    /**< Temperature warning */
#define QUAC_DEVSTS_TEMP_CRIT           (1 << 9)    /**< Temperature critical */
#define QUAC_DEVSTS_ENTROPY_LOW         (1 << 10)   /**< Entropy pool low */
#define QUAC_DEVSTS_POWER_WARN          (1 << 11)   /**< Power warning */
#define QUAC_DEVSTS_TAMPER              (1 << 12)   /**< Tamper detected */
#define QUAC_DEVSTS_RECOVERING          (1 << 13)   /**< Recovering from error */
#define QUAC_DEVSTS_SELF_TEST_RUNNING   (1 << 14)   /**< Self-test in progress */
#define QUAC_DEVSTS_INITIALIZING        (1 << 15)   /**< Device initializing */
/** @} */

/**
 * @name Device Capabilities Bits (QUAC_REG_DEVICE_CAPS)
 * @{
 */
#define QUAC_CAP_KEM_KYBER512           (1 << 0)    /**< Kyber-512 supported */
#define QUAC_CAP_KEM_KYBER768           (1 << 1)    /**< Kyber-768 supported */
#define QUAC_CAP_KEM_KYBER1024          (1 << 2)    /**< Kyber-1024 supported */
#define QUAC_CAP_SIGN_DILITHIUM2        (1 << 4)    /**< Dilithium2 supported */
#define QUAC_CAP_SIGN_DILITHIUM3        (1 << 5)    /**< Dilithium3 supported */
#define QUAC_CAP_SIGN_DILITHIUM5        (1 << 6)    /**< Dilithium5 supported */
#define QUAC_CAP_SIGN_SPHINCS           (1 << 8)    /**< SPHINCS+ supported */
#define QUAC_CAP_QRNG                   (1 << 12)   /**< QRNG supported */
#define QUAC_CAP_KEY_STORAGE            (1 << 13)   /**< Key storage supported */
#define QUAC_CAP_ASYNC                  (1 << 14)   /**< Async ops supported */
#define QUAC_CAP_BATCH                  (1 << 15)   /**< Batch ops supported */
#define QUAC_CAP_DMA                    (1 << 16)   /**< DMA supported */
#define QUAC_CAP_SRIOV                  (1 << 17)   /**< SR-IOV supported */
#define QUAC_CAP_FIPS                   (1 << 18)   /**< FIPS mode supported */
#define QUAC_CAP_AER                    (1 << 19)   /**< AER supported */
#define QUAC_CAP_FLR                    (1 << 20)   /**< FLR supported */
/** @} */

/**
 * @name Interrupt Status/Enable Bits
 * @{
 */
#define QUAC_INT_DMA_TX0_DONE           (1 << 0)    /**< TX0 DMA complete */
#define QUAC_INT_DMA_TX1_DONE           (1 << 1)    /**< TX1 DMA complete */
#define QUAC_INT_DMA_RX0_DONE           (1 << 2)    /**< RX0 DMA complete */
#define QUAC_INT_DMA_RX1_DONE           (1 << 3)    /**< RX1 DMA complete */
#define QUAC_INT_DMA_ERROR              (1 << 4)    /**< DMA error */
#define QUAC_INT_CRYPTO_DONE            (1 << 8)    /**< Crypto operation done */
#define QUAC_INT_CRYPTO_ERROR           (1 << 9)    /**< Crypto error */
#define QUAC_INT_CRYPTO_QUEUE_EMPTY     (1 << 10)   /**< Crypto queue empty */
#define QUAC_INT_ENTROPY_LOW            (1 << 12)   /**< Entropy pool low */
#define QUAC_INT_ENTROPY_READY          (1 << 13)   /**< Entropy available */
#define QUAC_INT_SELFTEST_DONE          (1 << 14)   /**< Self-test complete */
#define QUAC_INT_TEMP_ALERT             (1 << 16)   /**< Temperature alert */
#define QUAC_INT_POWER_ALERT            (1 << 17)   /**< Power alert */
#define QUAC_INT_TAMPER                 (1 << 20)   /**< Tamper detected */
#define QUAC_INT_ERROR                  (1 << 24)   /**< General error */
#define QUAC_INT_FATAL                  (1 << 31)   /**< Fatal error */

/** Combined interrupt masks */
#define QUAC_INT_DMA_ALL    (QUAC_INT_DMA_TX0_DONE | QUAC_INT_DMA_TX1_DONE | \
                             QUAC_INT_DMA_RX0_DONE | QUAC_INT_DMA_RX1_DONE | \
                             QUAC_INT_DMA_ERROR)
#define QUAC_INT_CRYPTO_ALL (QUAC_INT_CRYPTO_DONE | QUAC_INT_CRYPTO_ERROR | \
                             QUAC_INT_CRYPTO_QUEUE_EMPTY)
#define QUAC_INT_ALL        0xFFFFFFFF
/** @} */

/**
 * @name DMA Control Bits
 * @{
 */
#define QUAC_DMA_ENABLE                 (1 << 0)    /**< Global DMA enable */
#define QUAC_DMA_RESET                  (1 << 1)    /**< Reset all channels */
#define QUAC_DMA_SCATTER_GATHER         (1 << 2)    /**< S/G mode enable */

/** Per-channel control bits */
#define QUAC_DMA_CH_ENABLE              (1 << 0)    /**< Channel enable */
#define QUAC_DMA_CH_START               (1 << 1)    /**< Start transfers */
#define QUAC_DMA_CH_STOP                (1 << 2)    /**< Stop transfers */
#define QUAC_DMA_CH_RESET               (1 << 3)    /**< Reset channel */
#define QUAC_DMA_CH_IRQ_ENABLE          (1 << 8)    /**< IRQ enable */
#define QUAC_DMA_CH_IRQ_ON_COMPLETE     (1 << 9)    /**< IRQ on completion */
#define QUAC_DMA_CH_IRQ_ON_ERROR        (1 << 10)   /**< IRQ on error */

/** Channel status bits */
#define QUAC_DMA_CH_STS_IDLE            (0 << 0)    /**< Channel idle */
#define QUAC_DMA_CH_STS_RUNNING         (1 << 0)    /**< Channel running */
#define QUAC_DMA_CH_STS_STOPPED         (2 << 0)    /**< Channel stopped */
#define QUAC_DMA_CH_STS_ERROR           (3 << 0)    /**< Channel error */
#define QUAC_DMA_CH_STS_MASK            0x3
/** @} */

/**
 * @name QRNG Control Bits
 * @{
 */
#define QUAC_QRNG_ENABLE                (1 << 0)    /**< Enable QRNG */
#define QUAC_QRNG_CONTINUOUS            (1 << 1)    /**< Continuous mode */
#define QUAC_QRNG_HEALTH_CHECK          (1 << 2)    /**< Enable health checks */
#define QUAC_QRNG_CONDITIONING          (1 << 3)    /**< Enable conditioning */
#define QUAC_QRNG_IRQ_ON_READY          (1 << 8)    /**< IRQ when ready */
#define QUAC_QRNG_IRQ_ON_LOW            (1 << 9)    /**< IRQ when low */

/** QRNG status bits */
#define QUAC_QRNG_STS_READY             (1 << 0)    /**< Data ready */
#define QUAC_QRNG_STS_HEALTHY           (1 << 1)    /**< Health test OK */
#define QUAC_QRNG_STS_LOW               (1 << 2)    /**< Pool low */
#define QUAC_QRNG_STS_ERROR             (1 << 3)    /**< Error state */
/** @} */

/**
 * @name Self-Test Control Bits
 * @{
 */
#define QUAC_SELFTEST_RUN_KAT_KEM       (1 << 0)    /**< Run KEM KAT */
#define QUAC_SELFTEST_RUN_KAT_SIGN      (1 << 1)    /**< Run Sign KAT */
#define QUAC_SELFTEST_RUN_HW_MEMORY     (1 << 4)    /**< Memory test */
#define QUAC_SELFTEST_RUN_HW_DMA        (1 << 5)    /**< DMA test */
#define QUAC_SELFTEST_RUN_ENTROPY       (1 << 8)    /**< Entropy test */
#define QUAC_SELFTEST_RUN_ALL           0xFFFF      /**< Run all tests */

/** Self-test status bits */
#define QUAC_SELFTEST_STS_RUNNING       (1 << 0)    /**< Test running */
#define QUAC_SELFTEST_STS_PASSED        (1 << 1)    /**< All tests passed */
#define QUAC_SELFTEST_STS_FAILED        (1 << 2)    /**< Some tests failed */
/** @} */

/**
 * @name Reset Control Values
 * @{
 */
#define QUAC_RESET_MAGIC                0x52535421  /**< "RST!" */
#define QUAC_RESET_SOFT                 (QUAC_RESET_MAGIC | (0 << 28))
#define QUAC_RESET_CRYPTO               (QUAC_RESET_MAGIC | (1 << 28))
#define QUAC_RESET_DMA                  (QUAC_RESET_MAGIC | (2 << 28))
#define QUAC_RESET_FULL                 (QUAC_RESET_MAGIC | (0xF << 28))
/** @} */

/*=============================================================================
 * DMA Descriptor Structures
 *=============================================================================*/

/** Maximum DMA descriptors per ring */
#define QUAC_DMA_MAX_DESCRIPTORS        256

/** DMA descriptor alignment */
#define QUAC_DMA_DESC_ALIGN             64

#pragma pack(push, 1)

/**
 * @brief DMA descriptor structure (64 bytes)
 */
typedef struct _QUAC_DMA_DESCRIPTOR {
    UINT64  SourceAddress;      /**< Source physical address */
    UINT64  DestAddress;        /**< Destination physical address */
    UINT32  Length;             /**< Transfer length in bytes */
    UINT32  Control;            /**< Descriptor control flags */
    UINT64  NextDescriptor;     /**< Next descriptor address */
    UINT32  Status;             /**< Completion status */
    UINT32  Tag;                /**< User-defined tag */
    UINT64  Reserved[2];        /**< Reserved for alignment */
} QUAC_DMA_DESCRIPTOR, *PQUAC_DMA_DESCRIPTOR;

C_ASSERT(sizeof(QUAC_DMA_DESCRIPTOR) == 64);

/**
 * @name DMA Descriptor Control Bits
 * @{
 */
#define QUAC_DESC_VALID                 (1 << 0)    /**< Descriptor valid */
#define QUAC_DESC_LAST                  (1 << 1)    /**< Last descriptor */
#define QUAC_DESC_IRQ                   (1 << 2)    /**< Generate IRQ */
#define QUAC_DESC_CHAIN                 (1 << 3)    /**< Chained descriptor */
#define QUAC_DESC_TO_DEVICE             (1 << 4)    /**< Direction: to device */
#define QUAC_DESC_FROM_DEVICE           (0 << 4)    /**< Direction: from device */
/** @} */

/**
 * @name DMA Descriptor Status Bits
 * @{
 */
#define QUAC_DESC_STS_COMPLETE          (1 << 0)    /**< Transfer complete */
#define QUAC_DESC_STS_ERROR             (1 << 1)    /**< Transfer error */
#define QUAC_DESC_STS_ABORTED           (1 << 2)    /**< Transfer aborted */
/** @} */

#pragma pack(pop)

/*=============================================================================
 * Algorithm Identifiers (matches IOCTL definitions)
 *=============================================================================*/

#define QUAC_HW_ALG_NONE                0x0000

/** ML-KEM (Kyber) */
#define QUAC_HW_ALG_KYBER512            0x1100
#define QUAC_HW_ALG_KYBER768            0x1101
#define QUAC_HW_ALG_KYBER1024           0x1102

/** ML-DSA (Dilithium) */
#define QUAC_HW_ALG_DILITHIUM2          0x2100
#define QUAC_HW_ALG_DILITHIUM3          0x2101
#define QUAC_HW_ALG_DILITHIUM5          0x2102

/** SLH-DSA (SPHINCS+) */
#define QUAC_HW_ALG_SPHINCS_SHA2_128S   0x2200
#define QUAC_HW_ALG_SPHINCS_SHA2_128F   0x2201
#define QUAC_HW_ALG_SPHINCS_SHA2_192S   0x2202
#define QUAC_HW_ALG_SPHINCS_SHA2_192F   0x2203
#define QUAC_HW_ALG_SPHINCS_SHA2_256S   0x2204
#define QUAC_HW_ALG_SPHINCS_SHA2_256F   0x2205

/*=============================================================================
 * MSI-X Definitions
 *=============================================================================*/

/** Maximum MSI-X vectors */
#define QUAC_MSIX_MAX_VECTORS           32

/** MSI-X vector assignments */
#define QUAC_MSIX_VEC_ERROR             0   /**< Error interrupt */
#define QUAC_MSIX_VEC_DMA_TX0           1   /**< DMA TX0 complete */
#define QUAC_MSIX_VEC_DMA_TX1           2   /**< DMA TX1 complete */
#define QUAC_MSIX_VEC_DMA_RX0           3   /**< DMA RX0 complete */
#define QUAC_MSIX_VEC_DMA_RX1           4   /**< DMA RX1 complete */
#define QUAC_MSIX_VEC_CRYPTO            5   /**< Crypto complete */
#define QUAC_MSIX_VEC_ENTROPY           6   /**< Entropy ready */
#define QUAC_MSIX_VEC_TEMP              7   /**< Temperature alert */

/*=============================================================================
 * Timing Constants
 *=============================================================================*/

/** Reset delay (microseconds) */
#define QUAC_RESET_DELAY_US             1000

/** Self-test timeout (milliseconds) */
#define QUAC_SELFTEST_TIMEOUT_MS        5000

/** DMA completion timeout (milliseconds) */
#define QUAC_DMA_TIMEOUT_MS             10000

/** Register access timeout (microseconds) */
#define QUAC_REG_TIMEOUT_US             100

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_REGISTERS_H */
