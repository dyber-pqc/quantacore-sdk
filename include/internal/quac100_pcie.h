/**
 * @file quac100_pcie.h
 * @brief QuantaCore SDK - Internal PCIe Interface
 *
 * Low-level PCI Express interface for device enumeration, BAR access,
 * MSI-X interrupt handling, power management, and SR-IOV virtualization.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @internal
 * This header is for internal SDK use only. Applications should use the
 * public API which handles PCIe interactions transparently.
 *
 * @par PCIe Capabilities
 * The QUAC 100 implements:
 * - PCIe Gen4 x8 (up to 16 GT/s per lane, ~16 GB/s total)
 * - 64-bit addressing
 * - MSI-X interrupts (up to 32 vectors)
 * - SR-IOV (up to 16 virtual functions)
 * - Power management (D0, D3hot)
 * - Advanced Error Reporting (AER)
 * - Function Level Reset (FLR)
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

#ifndef QUAC100_PCIE_H
#define QUAC100_PCIE_H

#include "../quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * PCI Device Identification
 *=============================================================================*/

/** Dyber PCI Vendor ID */
#define QUAC_PCI_VENDOR_ID 0x1DYB /* Placeholder - actual ID TBD */

/** QUAC 100 PCI Device ID */
#define QUAC_PCI_DEVICE_ID 0x0100

/** QUAC 100 Subsystem IDs */
#define QUAC_PCI_SUBSYS_STANDARD 0x0001   /**< Standard edition */
#define QUAC_PCI_SUBSYS_ENTERPRISE 0x0002 /**< Enterprise edition */
#define QUAC_PCI_SUBSYS_GOVERNMENT 0x0003 /**< Government/FIPS edition */

/** Device class */
#define QUAC_PCI_CLASS 0x10    /**< Encryption controller */
#define QUAC_PCI_SUBCLASS 0x80 /**< Other encryption */

/*=============================================================================
 * BAR Definitions
 *=============================================================================*/

/** Number of BARs */
#define QUAC_PCIE_NUM_BARS 3

/** BAR indices */
#define QUAC_PCIE_BAR_REGS 0 /**< Control registers (BAR0) */
#define QUAC_PCIE_BAR_MSIX 2 /**< MSI-X table (BAR2) */
#define QUAC_PCIE_BAR_SRAM 4 /**< On-chip SRAM (BAR4) */

/** BAR0 size */
#define QUAC_PCIE_BAR0_SIZE (64 * 1024 * 1024) /* 64 MB */

/** BAR2 size (MSI-X) */
#define QUAC_PCIE_BAR2_SIZE (4 * 1024) /* 4 KB */

/** BAR4 size (optional SRAM) */
#define QUAC_PCIE_BAR4_SIZE (16 * 1024 * 1024) /* 16 MB */

/*=============================================================================
 * Register Map Offsets (BAR0)
 *=============================================================================*/

/** Device control registers (0x0000 - 0x0FFF) */
#define QUAC_REG_DEVICE_ID 0x0000      /**< Device ID (RO) */
#define QUAC_REG_DEVICE_REV 0x0004     /**< Hardware revision (RO) */
#define QUAC_REG_DEVICE_STATUS 0x0008  /**< Device status (RO) */
#define QUAC_REG_DEVICE_CONTROL 0x000C /**< Device control (RW) */
#define QUAC_REG_DEVICE_CAPS 0x0010    /**< Capabilities (RO) */
#define QUAC_REG_FW_VERSION 0x0020     /**< Firmware version (RO) */
#define QUAC_REG_FW_BUILD 0x0024       /**< Firmware build (RO) */
#define QUAC_REG_SCRATCH 0x0080        /**< Scratch register (RW) */
#define QUAC_REG_RESET 0x00F0          /**< Reset control (WO) */

/** Interrupt control registers (0x1000 - 0x1FFF) */
#define QUAC_REG_INT_STATUS 0x1000   /**< Interrupt status (RO/W1C) */
#define QUAC_REG_INT_ENABLE 0x1004   /**< Interrupt enable (RW) */
#define QUAC_REG_INT_MASK 0x1008     /**< Interrupt mask (RW) */
#define QUAC_REG_INT_FORCE 0x100C    /**< Force interrupt (WO) */
#define QUAC_REG_MSIX_CONTROL 0x1010 /**< MSI-X control (RW) */

/** DMA engine registers (0x2000 - 0x2FFF) */
#define QUAC_REG_DMA_CONTROL 0x2000   /**< DMA global control */
#define QUAC_REG_DMA_STATUS 0x2004    /**< DMA global status */
#define QUAC_REG_DMA_CH_BASE 0x2100   /**< Channel 0 base */
#define QUAC_REG_DMA_CH_STRIDE 0x0080 /**< Channel register stride */

/** Per-channel DMA registers (relative to channel base) */
#define QUAC_REG_DMA_CH_CONTROL 0x0000   /**< Channel control */
#define QUAC_REG_DMA_CH_STATUS 0x0004    /**< Channel status */
#define QUAC_REG_DMA_CH_DESC_LO 0x0010   /**< Descriptor base low */
#define QUAC_REG_DMA_CH_DESC_HI 0x0014   /**< Descriptor base high */
#define QUAC_REG_DMA_CH_DESC_SIZE 0x0018 /**< Descriptor ring size */
#define QUAC_REG_DMA_CH_HEAD 0x0020      /**< Head pointer */
#define QUAC_REG_DMA_CH_TAIL 0x0024      /**< Tail pointer */
#define QUAC_REG_DMA_CH_DOORBELL 0x0028  /**< Doorbell (write to start) */

/** Cryptographic engine registers (0x3000 - 0x3FFF) */
#define QUAC_REG_CRYPTO_CONTROL 0x3000 /**< Crypto engine control */
#define QUAC_REG_CRYPTO_STATUS 0x3004  /**< Crypto engine status */
#define QUAC_REG_NTT_CONTROL 0x3100    /**< NTT engine control */
#define QUAC_REG_NTT_STATUS 0x3104     /**< NTT engine status */
#define QUAC_REG_QRNG_CONTROL 0x3200   /**< QRNG control */
#define QUAC_REG_QRNG_STATUS 0x3204    /**< QRNG status */
#define QUAC_REG_QRNG_ENTROPY 0x3208   /**< Available entropy (bits) */

/** Temperature and power registers (0x3800 - 0x38FF) */
#define QUAC_REG_TEMP_CORE 0x3800    /**< Core temperature */
#define QUAC_REG_TEMP_MEMORY 0x3804  /**< Memory temperature */
#define QUAC_REG_VOLTAGE_CORE 0x3810 /**< Core voltage (mV) */
#define QUAC_REG_POWER_DRAW 0x3820   /**< Power consumption (mW) */

/** Descriptor ring memory (0x10000 - 0x1FFFF) */
#define QUAC_REG_DESC_RING_BASE 0x00010000
#define QUAC_REG_DESC_RING_SIZE 0x00010000 /* 64 KB */

/** Key storage (0x100000 - 0x1FFFFF) */
#define QUAC_REG_KEY_STORAGE_BASE 0x00100000
#define QUAC_REG_KEY_STORAGE_SIZE 0x00100000 /* 1 MB */

/** Work memory (0x200000 - 0x3FFFFFF) */
#define QUAC_REG_WORK_MEM_BASE 0x00200000
#define QUAC_REG_WORK_MEM_SIZE 0x03E00000 /* 62 MB */

/*=============================================================================
 * Register Bit Definitions
 *=============================================================================*/

/** Device control register bits */
#define QUAC_DEVCTL_ENABLE (1 << 0)     /**< Device enable */
#define QUAC_DEVCTL_DMA_ENABLE (1 << 1) /**< DMA enable */
#define QUAC_DEVCTL_INT_ENABLE (1 << 2) /**< Interrupts enable */
#define QUAC_DEVCTL_FIPS_MODE (1 << 4)  /**< FIPS mode */
#define QUAC_DEVCTL_ZEROIZE (1 << 8)    /**< Zeroize keys */
#define QUAC_DEVCTL_RESET (1 << 31)     /**< Soft reset */

/** Device status register bits */
#define QUAC_DEVSTS_READY (1 << 0)        /**< Device ready */
#define QUAC_DEVSTS_ERROR (1 << 1)        /**< Error state */
#define QUAC_DEVSTS_BUSY (1 << 2)         /**< Device busy */
#define QUAC_DEVSTS_SELF_TEST_OK (1 << 4) /**< Self-test passed */
#define QUAC_DEVSTS_FIPS_OK (1 << 5)      /**< FIPS mode active */
#define QUAC_DEVSTS_TEMP_WARN (1 << 8)    /**< Temperature warning */
#define QUAC_DEVSTS_TEMP_CRIT (1 << 9)    /**< Temperature critical */
#define QUAC_DEVSTS_TAMPER (1 << 12)      /**< Tamper detected */

/** Interrupt status/enable bits */
#define QUAC_INT_DMA_TX0_DONE (1 << 0) /**< TX0 DMA complete */
#define QUAC_INT_DMA_TX1_DONE (1 << 1) /**< TX1 DMA complete */
#define QUAC_INT_DMA_RX0_DONE (1 << 2) /**< RX0 DMA complete */
#define QUAC_INT_DMA_RX1_DONE (1 << 3) /**< RX1 DMA complete */
#define QUAC_INT_DMA_ERROR (1 << 4)    /**< DMA error */
#define QUAC_INT_CRYPTO_DONE (1 << 8)  /**< Crypto operation done */
#define QUAC_INT_CRYPTO_ERROR (1 << 9) /**< Crypto error */
#define QUAC_INT_ENTROPY_LOW (1 << 12) /**< Entropy pool low */
#define QUAC_INT_TEMP_ALERT (1 << 16)  /**< Temperature alert */
#define QUAC_INT_ERROR (1 << 24)       /**< General error */
#define QUAC_INT_FATAL (1 << 31)       /**< Fatal error */

/** DMA channel control bits */
#define QUAC_DMA_CH_ENABLE (1 << 0)     /**< Channel enable */
#define QUAC_DMA_CH_START (1 << 1)      /**< Start transfers */
#define QUAC_DMA_CH_STOP (1 << 2)       /**< Stop transfers */
#define QUAC_DMA_CH_RESET (1 << 3)      /**< Reset channel */
#define QUAC_DMA_CH_IRQ_ENABLE (1 << 8) /**< IRQ enable */

    /*=============================================================================
     * PCIe Device Structure
     *=============================================================================*/

    /**
     * @brief PCIe device information
     */
    typedef struct quac_pcie_info_s
    {
        uint32_t struct_size; /**< Size of this structure */

        /* PCI identification */
        uint16_t vendor_id;        /**< Vendor ID */
        uint16_t device_id;        /**< Device ID */
        uint16_t subsystem_vendor; /**< Subsystem vendor ID */
        uint16_t subsystem_id;     /**< Subsystem ID */
        uint8_t revision;          /**< Revision ID */

        /* PCI location */
        uint16_t domain;  /**< PCI domain */
        uint8_t bus;      /**< Bus number */
        uint8_t device;   /**< Device number */
        uint8_t function; /**< Function number */

        /* Link status */
        uint8_t link_gen;         /**< PCIe generation (1-5) */
        uint8_t link_width;       /**< Link width (x1-x16) */
        uint8_t max_gen;          /**< Maximum supported gen */
        uint8_t max_width;        /**< Maximum supported width */
        uint32_t link_speed_mbps; /**< Current link speed (MB/s) */

        /* Capabilities */
        bool msi_capable;       /**< MSI support */
        bool msix_capable;      /**< MSI-X support */
        bool sriov_capable;     /**< SR-IOV support */
        bool aer_capable;       /**< AER support */
        bool flr_capable;       /**< FLR support */
        uint16_t msix_count;    /**< Number of MSI-X vectors */
        uint16_t sriov_vfs_max; /**< Max virtual functions */

        /* BAR information */
        struct
        {
            uint64_t phys_addr; /**< Physical address */
            uint64_t size;      /**< BAR size */
            bool is_mem;        /**< Memory BAR (vs I/O) */
            bool is_64bit;      /**< 64-bit BAR */
            bool prefetchable;  /**< Prefetchable */
        } bars[6];

        /* Power state */
        uint8_t power_state; /**< Current power state (D0-D3) */

        /* Error counts */
        uint64_t correctable_errors;   /**< Correctable errors */
        uint64_t uncorrectable_errors; /**< Uncorrectable errors */
    } quac_pcie_info_t;

    /**
     * @brief Internal PCIe device handle
     */
    typedef struct quac_pcie_device_s
    {
        /* Device info */
        quac_pcie_info_t info; /**< Device information */
        uint32_t index;        /**< Device index */

        /* Mapped BARs */
        void *bar_virt[6]; /**< Virtual addresses */

        /* File handle (OS-specific) */
        intptr_t fd; /**< Device file descriptor/handle */

        /* MSI-X */
        uint16_t msix_enabled; /**< MSI-X vectors enabled */
        int *msix_irqs;        /**< IRQ numbers */

        /* State */
        bool initialized; /**< Initialized flag */
        bool enabled;     /**< Device enabled */
        void *lock;       /**< Device lock */
    } quac_pcie_device_t;

    /*=============================================================================
     * Device Enumeration
     *=============================================================================*/

    /**
     * @brief Enumerate QUAC devices
     *
     * @param[out] count        Number of devices found
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_enumerate(uint32_t *count);

    /**
     * @brief Get device information
     *
     * @param[in]  index        Device index
     * @param[out] info         Pointer to receive device info
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_get_info(uint32_t index, quac_pcie_info_t *info);

    /**
     * @brief Open PCIe device
     *
     * @param[in]  index        Device index
     * @param[out] pcie_dev     Pointer to receive device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_open(uint32_t index, quac_pcie_device_t **pcie_dev);

    /**
     * @brief Open device by BDF (Bus:Device.Function)
     *
     * @param[in]  domain       PCI domain
     * @param[in]  bus          Bus number
     * @param[in]  device       Device number
     * @param[in]  function     Function number
     * @param[out] pcie_dev     Pointer to receive device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_open_bdf(uint16_t domain, uint8_t bus,
                                     uint8_t device, uint8_t function,
                                     quac_pcie_device_t **pcie_dev);

    /**
     * @brief Close PCIe device
     *
     * @param[in] pcie_dev      Device handle
     */
    void quac_pcie_close(quac_pcie_device_t *pcie_dev);

    /*=============================================================================
     * Register Access
     *=============================================================================*/

    /**
     * @brief Read 32-bit register
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  offset       Register offset
     * @param[out] value        Pointer to receive value
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_read32(quac_pcie_device_t *pcie_dev,
                                   uint32_t offset,
                                   uint32_t *value);

    /**
     * @brief Write 32-bit register
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] offset        Register offset
     * @param[in] value         Value to write
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_write32(quac_pcie_device_t *pcie_dev,
                                    uint32_t offset,
                                    uint32_t value);

    /**
     * @brief Read 64-bit register
     */
    quac_result_t quac_pcie_read64(quac_pcie_device_t *pcie_dev,
                                   uint32_t offset,
                                   uint64_t *value);

    /**
     * @brief Write 64-bit register
     */
    quac_result_t quac_pcie_write64(quac_pcie_device_t *pcie_dev,
                                    uint32_t offset,
                                    uint64_t value);

    /**
     * @brief Read-modify-write 32-bit register
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] offset        Register offset
     * @param[in] clear_mask    Bits to clear
     * @param[in] set_mask      Bits to set
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_rmw32(quac_pcie_device_t *pcie_dev,
                                  uint32_t offset,
                                  uint32_t clear_mask,
                                  uint32_t set_mask);

    /**
     * @brief Poll register until condition met
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  offset       Register offset
     * @param[in]  mask         Bits to check
     * @param[in]  value        Expected value
     * @param[in]  timeout_us   Timeout in microseconds
     * @param[out] actual       Actual register value (may be NULL)
     *
     * @return QUAC_SUCCESS if condition met
     * @return QUAC_ERROR_TIMEOUT on timeout
     */
    quac_result_t quac_pcie_poll32(quac_pcie_device_t *pcie_dev,
                                   uint32_t offset,
                                   uint32_t mask,
                                   uint32_t value,
                                   uint32_t timeout_us,
                                   uint32_t *actual);

    /*=============================================================================
     * Memory Access
     *=============================================================================*/

    /**
     * @brief Read block from device memory
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  offset       Memory offset
     * @param[out] buffer       Destination buffer
     * @param[in]  length       Number of bytes
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_read_mem(quac_pcie_device_t *pcie_dev,
                                     uint64_t offset,
                                     void *buffer,
                                     size_t length);

    /**
     * @brief Write block to device memory
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] offset        Memory offset
     * @param[in] buffer        Source buffer
     * @param[in] length        Number of bytes
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_write_mem(quac_pcie_device_t *pcie_dev,
                                      uint64_t offset,
                                      const void *buffer,
                                      size_t length);

    /**
     * @brief Get mapped BAR address
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  bar          BAR index
     * @param[out] addr         Pointer to receive virtual address
     * @param[out] size         Pointer to receive BAR size
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_get_bar(quac_pcie_device_t *pcie_dev,
                                    uint32_t bar,
                                    void **addr,
                                    uint64_t *size);

    /*=============================================================================
     * MSI-X Interrupt Handling
     *=============================================================================*/

    /**
     * @brief MSI-X vector allocation
     */
    typedef struct quac_msix_vector_s
    {
        uint16_t vector;    /**< Vector number */
        uint32_t irq;       /**< OS IRQ number */
        void *handler;      /**< Interrupt handler */
        void *handler_data; /**< Handler context */
        uint64_t count;     /**< Interrupt count */
        bool enabled;       /**< Vector enabled */
    } quac_msix_vector_t;

    /**
     * @brief Interrupt handler function type
     */
    typedef void (*quac_irq_handler_t)(quac_pcie_device_t *pcie_dev,
                                       uint16_t vector,
                                       void *user_data);

    /**
     * @brief Enable MSI-X
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  vectors      Number of vectors to enable
     * @param[out] actual       Actual vectors enabled
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_msix_enable(quac_pcie_device_t *pcie_dev,
                                        uint16_t vectors,
                                        uint16_t *actual);

    /**
     * @brief Disable MSI-X
     *
     * @param[in] pcie_dev      Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_msix_disable(quac_pcie_device_t *pcie_dev);

    /**
     * @brief Register interrupt handler
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] vector        MSI-X vector
     * @param[in] handler       Handler function
     * @param[in] user_data     Handler context
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_irq_register(quac_pcie_device_t *pcie_dev,
                                         uint16_t vector,
                                         quac_irq_handler_t handler,
                                         void *user_data);

    /**
     * @brief Unregister interrupt handler
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] vector        MSI-X vector
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_irq_unregister(quac_pcie_device_t *pcie_dev,
                                           uint16_t vector);

    /**
     * @brief Mask interrupt vector
     */
    quac_result_t quac_pcie_irq_mask(quac_pcie_device_t *pcie_dev, uint16_t vector);

    /**
     * @brief Unmask interrupt vector
     */
    quac_result_t quac_pcie_irq_unmask(quac_pcie_device_t *pcie_dev, uint16_t vector);

    /*=============================================================================
     * Power Management
     *=============================================================================*/

    /**
     * @brief PCIe power states
     */
    typedef enum quac_pcie_power_state_e
    {
        QUAC_PCIE_D0 = 0,      /**< Full power (operational) */
        QUAC_PCIE_D1 = 1,      /**< Light sleep */
        QUAC_PCIE_D2 = 2,      /**< Deeper sleep */
        QUAC_PCIE_D3_HOT = 3,  /**< Soft off (power maintained) */
        QUAC_PCIE_D3_COLD = 4, /**< Hard off (power removed) */
    } quac_pcie_power_state_t;

    /**
     * @brief Get current power state
     *
     * @param[in]  pcie_dev     Device handle
     * @param[out] state        Current power state
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_get_power_state(quac_pcie_device_t *pcie_dev,
                                            quac_pcie_power_state_t *state);

    /**
     * @brief Set power state
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] state         Target power state
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_set_power_state(quac_pcie_device_t *pcie_dev,
                                            quac_pcie_power_state_t state);

    /*=============================================================================
     * Reset and Error Handling
     *=============================================================================*/

    /**
     * @brief Reset types
     */
    typedef enum quac_pcie_reset_e
    {
        QUAC_PCIE_RESET_SOFT = 0, /**< Software reset */
        QUAC_PCIE_RESET_FLR = 1,  /**< Function Level Reset */
        QUAC_PCIE_RESET_HOT = 2,  /**< Hot reset (link reset) */
    } quac_pcie_reset_t;

    /**
     * @brief Reset device
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] type          Reset type
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_reset(quac_pcie_device_t *pcie_dev,
                                  quac_pcie_reset_t type);

    /**
     * @brief Get AER (Advanced Error Reporting) status
     *
     * @param[in]  pcie_dev     Device handle
     * @param[out] correctable  Correctable error status
     * @param[out] uncorrectable Uncorrectable error status
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_get_aer_status(quac_pcie_device_t *pcie_dev,
                                           uint32_t *correctable,
                                           uint32_t *uncorrectable);

    /**
     * @brief Clear AER status
     *
     * @param[in] pcie_dev      Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_clear_aer_status(quac_pcie_device_t *pcie_dev);

    /*=============================================================================
     * SR-IOV (Virtual Functions)
     *=============================================================================*/

    /**
     * @brief Enable SR-IOV
     *
     * @param[in]  pcie_dev     Device handle (physical function)
     * @param[in]  num_vfs      Number of VFs to enable
     * @param[out] actual       Actual VFs enabled
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_sriov_enable(quac_pcie_device_t *pcie_dev,
                                         uint16_t num_vfs,
                                         uint16_t *actual);

    /**
     * @brief Disable SR-IOV
     *
     * @param[in] pcie_dev      Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_sriov_disable(quac_pcie_device_t *pcie_dev);

    /**
     * @brief Get number of active VFs
     *
     * @param[in]  pcie_dev     Device handle
     * @param[out] num_vfs      Number of active VFs
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_sriov_get_vfs(quac_pcie_device_t *pcie_dev,
                                          uint16_t *num_vfs);

    /*=============================================================================
     * Link Management
     *=============================================================================*/

    /**
     * @brief PCIe link status
     */
    typedef struct quac_pcie_link_s
    {
        uint8_t gen;           /**< Current generation */
        uint8_t width;         /**< Current width */
        uint8_t max_gen;       /**< Max supported generation */
        uint8_t max_width;     /**< Max supported width */
        uint32_t speed_mbps;   /**< Speed in MB/s */
        bool link_up;          /**< Link is up */
        bool data_link_active; /**< Data link layer active */
        uint64_t ltssm_state;  /**< LTSSM state */
    } quac_pcie_link_t;

    /**
     * @brief Get link status
     *
     * @param[in]  pcie_dev     Device handle
     * @param[out] link         Link status
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_get_link_status(quac_pcie_device_t *pcie_dev,
                                            quac_pcie_link_t *link);

    /**
     * @brief Retrain link (attempt speed/width renegotiation)
     *
     * @param[in] pcie_dev      Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_retrain_link(quac_pcie_device_t *pcie_dev);

    /*=============================================================================
     * Configuration Space Access
     *=============================================================================*/

    /**
     * @brief Read PCI config space
     *
     * @param[in]  pcie_dev     Device handle
     * @param[in]  offset       Config space offset
     * @param[out] value        Value read
     * @param[in]  width        Access width (1, 2, or 4 bytes)
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_config_read(quac_pcie_device_t *pcie_dev,
                                        uint32_t offset,
                                        uint32_t *value,
                                        uint32_t width);

    /**
     * @brief Write PCI config space
     *
     * @param[in] pcie_dev      Device handle
     * @param[in] offset        Config space offset
     * @param[in] value         Value to write
     * @param[in] width         Access width (1, 2, or 4 bytes)
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_config_write(quac_pcie_device_t *pcie_dev,
                                         uint32_t offset,
                                         uint32_t value,
                                         uint32_t width);

    /*=============================================================================
     * PCIe Subsystem Initialization
     *=============================================================================*/

    /**
     * @brief Initialize PCIe subsystem
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_pcie_init(void);

    /**
     * @brief Shutdown PCIe subsystem
     */
    void quac_pcie_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PCIE_H */
