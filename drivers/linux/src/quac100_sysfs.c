// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - sysfs Interface
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/sysfs.h>
#include <linux/device.h>

#include "quac100_drv.h"

/*=============================================================================
 * Device Information Attributes
 *=============================================================================*/

static ssize_t device_info_show(struct device *dev,
                                struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);

    return sprintf(buf, "Device: %s\n"
                        "Index: %d\n"
                        "Vendor ID: 0x%04x\n"
                        "Device ID: 0x%04x\n"
                        "Revision: 0x%02x\n"
                        "HW Version: 0x%08x\n"
                        "FW Version: 0x%08x\n"
                        "Capabilities: 0x%08x\n"
                        "Status: 0x%08x\n",
                   qdev->name,
                   qdev->dev_index,
                   qdev->pdev->vendor,
                   qdev->pdev->device,
                   qdev->pdev->revision,
                   qdev->hw_version,
                   qdev->fw_version,
                   qdev->capabilities,
                   quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS));
}
static DEVICE_ATTR_RO(device_info);

static ssize_t firmware_version_show(struct device *dev,
                                     struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    u32 fw = qdev->fw_version;

    return sprintf(buf, "%u.%u.%u\n",
                   (fw >> 24) & 0xFF,
                   (fw >> 16) & 0xFF,
                   fw & 0xFFFF);
}
static DEVICE_ATTR_RO(firmware_version);

static ssize_t serial_number_show(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);

    return sprintf(buf, "%s\n", qdev->serial_number[0] ? qdev->serial_number : "N/A");
}
static DEVICE_ATTR_RO(serial_number);

static ssize_t driver_version_show(struct device *dev,
                                   struct device_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", QUAC100_DRIVER_VERSION);
}
static DEVICE_ATTR_RO(driver_version);

/*=============================================================================
 * Status Attributes
 *=============================================================================*/

static ssize_t temperature_show(struct device *dev,
                                struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    s32 core_temp, mem_temp;

    core_temp = quac100_read32(qdev, QUAC100_REG_TEMP_CORE);
    mem_temp = quac100_read32(qdev, QUAC100_REG_TEMP_MEMORY);

    return sprintf(buf, "Core: %d C\nMemory: %d C\n", core_temp, mem_temp);
}
static DEVICE_ATTR_RO(temperature);

static ssize_t power_show(struct device *dev,
                          struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    u32 voltage, power;

    voltage = quac100_read32(qdev, QUAC100_REG_VOLTAGE_CORE);
    power = quac100_read32(qdev, QUAC100_REG_POWER_DRAW);

    return sprintf(buf, "Voltage: %u mV\nPower: %u mW\n", voltage, power);
}
static DEVICE_ATTR_RO(power);

static ssize_t entropy_show(struct device *dev,
                            struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    u32 entropy;

    entropy = quac100_read32(qdev, QUAC100_REG_QRNG_ENTROPY);

    return sprintf(buf, "%u bits\n", entropy);
}
static DEVICE_ATTR_RO(entropy);

static ssize_t status_show(struct device *dev,
                           struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    u32 status = quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS);
    int len = 0;

    len += sprintf(buf + len, "Raw: 0x%08x\n", status);
    len += sprintf(buf + len, "Ready: %s\n",
                   (status & QUAC100_DEVSTS_READY) ? "Yes" : "No");
    len += sprintf(buf + len, "Error: %s\n",
                   (status & QUAC100_DEVSTS_ERROR) ? "Yes" : "No");
    len += sprintf(buf + len, "Busy: %s\n",
                   (status & QUAC100_DEVSTS_BUSY) ? "Yes" : "No");
    len += sprintf(buf + len, "Self-test OK: %s\n",
                   (status & QUAC100_DEVSTS_SELFTEST_OK) ? "Yes" : "No");
    len += sprintf(buf + len, "FIPS Mode: %s\n",
                   (status & QUAC100_DEVSTS_FIPS_OK) ? "Active" : "Inactive");
    len += sprintf(buf + len, "Temp Warning: %s\n",
                   (status & QUAC100_DEVSTS_TEMP_WARN) ? "Yes" : "No");
    len += sprintf(buf + len, "Temp Critical: %s\n",
                   (status & QUAC100_DEVSTS_TEMP_CRIT) ? "Yes" : "No");
    len += sprintf(buf + len, "Tamper Alert: %s\n",
                   (status & QUAC100_DEVSTS_TAMPER) ? "Yes" : "No");

    return len;
}
static DEVICE_ATTR_RO(status);

/*=============================================================================
 * Statistics Attributes
 *=============================================================================*/

static ssize_t stats_show(struct device *dev,
                          struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    int len = 0;

    len += sprintf(buf + len, "KEM Key Generations: %llu\n",
                   atomic64_read(&qdev->stats.kem_keygen_count));
    len += sprintf(buf + len, "KEM Encapsulations: %llu\n",
                   atomic64_read(&qdev->stats.kem_encaps_count));
    len += sprintf(buf + len, "KEM Decapsulations: %llu\n",
                   atomic64_read(&qdev->stats.kem_decaps_count));
    len += sprintf(buf + len, "Sign Key Generations: %llu\n",
                   atomic64_read(&qdev->stats.sign_keygen_count));
    len += sprintf(buf + len, "Signatures: %llu\n",
                   atomic64_read(&qdev->stats.sign_count));
    len += sprintf(buf + len, "Verifications: %llu\n",
                   atomic64_read(&qdev->stats.verify_count));
    len += sprintf(buf + len, "Random Bytes: %llu\n",
                   atomic64_read(&qdev->stats.random_bytes));
    len += sprintf(buf + len, "DMA Read Bytes: %llu\n",
                   atomic64_read(&qdev->stats.dma_read_bytes));
    len += sprintf(buf + len, "DMA Write Bytes: %llu\n",
                   atomic64_read(&qdev->stats.dma_write_bytes));
    len += sprintf(buf + len, "Operations Completed: %llu\n",
                   atomic64_read(&qdev->stats.ops_completed));
    len += sprintf(buf + len, "Operations Failed: %llu\n",
                   atomic64_read(&qdev->stats.ops_failed));
    len += sprintf(buf + len, "Errors: %llu\n",
                   atomic64_read(&qdev->stats.errors));

    return len;
}
static DEVICE_ATTR_RO(stats);

static ssize_t stats_reset_store(struct device *dev,
                                 struct device_attribute *attr,
                                 const char *buf, size_t count)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);

    atomic64_set(&qdev->stats.kem_keygen_count, 0);
    atomic64_set(&qdev->stats.kem_encaps_count, 0);
    atomic64_set(&qdev->stats.kem_decaps_count, 0);
    atomic64_set(&qdev->stats.sign_keygen_count, 0);
    atomic64_set(&qdev->stats.sign_count, 0);
    atomic64_set(&qdev->stats.verify_count, 0);
    atomic64_set(&qdev->stats.random_bytes, 0);
    atomic64_set(&qdev->stats.dma_read_bytes, 0);
    atomic64_set(&qdev->stats.dma_write_bytes, 0);
    atomic64_set(&qdev->stats.ops_completed, 0);
    atomic64_set(&qdev->stats.ops_failed, 0);
    atomic64_set(&qdev->stats.errors, 0);

    quac100_info(qdev, "Statistics reset\n");
    return count;
}
static DEVICE_ATTR_WO(stats_reset);

/*=============================================================================
 * Control Attributes
 *=============================================================================*/

static ssize_t reset_store(struct device *dev,
                           struct device_attribute *attr,
                           const char *buf, size_t count)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    int type, ret;

    ret = kstrtoint(buf, 0, &type);
    if (ret)
        return ret;

    ret = quac100_device_reset(qdev, type);
    if (ret)
        return ret;

    return count;
}
static DEVICE_ATTR_WO(reset);

static ssize_t debug_level_show(struct device *dev,
                                struct device_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", debug_level);
}

static ssize_t debug_level_store(struct device *dev,
                                 struct device_attribute *attr,
                                 const char *buf, size_t count)
{
    int level, ret;

    ret = kstrtoint(buf, 0, &level);
    if (ret)
        return ret;

    if (level < 0 || level > QUAC100_DEBUG_TRACE)
        return -EINVAL;

    debug_level = level;
    return count;
}
static DEVICE_ATTR_RW(debug_level);

/*=============================================================================
 * PCIe Link Attributes
 *=============================================================================*/

static ssize_t pcie_link_show(struct device *dev,
                              struct device_attribute *attr, char *buf)
{
    struct quac100_device *qdev = dev_get_drvdata(dev);
    struct pci_dev *pdev = qdev->pdev;
    u16 linkstat;
    int gen, width;

    pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &linkstat);

    gen = linkstat & PCI_EXP_LNKSTA_CLS;
    width = (linkstat & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

    return sprintf(buf, "Gen%d x%d\n", gen, width);
}
static DEVICE_ATTR_RO(pcie_link);

/*=============================================================================
 * Attribute Groups
 *=============================================================================*/

static struct attribute *quac100_device_attrs[] = {
    &dev_attr_device_info.attr,
    &dev_attr_firmware_version.attr,
    &dev_attr_serial_number.attr,
    &dev_attr_driver_version.attr,
    &dev_attr_temperature.attr,
    &dev_attr_power.attr,
    &dev_attr_entropy.attr,
    &dev_attr_status.attr,
    &dev_attr_stats.attr,
    &dev_attr_stats_reset.attr,
    &dev_attr_reset.attr,
    &dev_attr_debug_level.attr,
    &dev_attr_pcie_link.attr,
    NULL,
};

static const struct attribute_group quac100_attr_group = {
    .attrs = quac100_device_attrs,
};

/*=============================================================================
 * sysfs Initialization
 *=============================================================================*/

int quac100_sysfs_init(struct quac100_device *qdev)
{
    int ret;

    ret = sysfs_create_group(&qdev->dev->kobj, &quac100_attr_group);
    if (ret)
    {
        quac100_err(qdev, "Failed to create sysfs group: %d\n", ret);
        return ret;
    }

    quac100_dbg(qdev, "sysfs interface created\n");
    return 0;
}

void quac100_sysfs_cleanup(struct quac100_device *qdev)
{
    sysfs_remove_group(&qdev->dev->kobj, &quac100_attr_group);
}