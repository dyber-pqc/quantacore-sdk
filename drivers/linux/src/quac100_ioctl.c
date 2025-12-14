// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - IOCTL Handler
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/uaccess.h>
#include <linux/slab.h>

#include "quac100_drv.h"

/*=============================================================================
 * Helper Functions
 *=============================================================================*/

static int quac100_copy_from_user_safe(void *dst, const void __user *src,
                                       size_t size)
{
    if (!src || !dst)
        return -EINVAL;

    if (copy_from_user(dst, src, size))
        return -EFAULT;

    return 0;
}

static int quac100_copy_to_user_safe(void __user *dst, const void *src,
                                     size_t size)
{
    if (!dst || !src)
        return -EINVAL;

    if (copy_to_user(dst, src, size))
        return -EFAULT;

    return 0;
}

/*=============================================================================
 * Device Information IOCTLs
 *=============================================================================*/

static int quac100_ioctl_get_version(struct quac100_device *qdev,
                                     void __user *arg)
{
    u32 version = (QUAC100_API_VERSION_MAJOR << 16) |
                  (QUAC100_API_VERSION_MINOR << 8) |
                  QUAC100_API_VERSION_PATCH;

    return quac100_copy_to_user_safe(arg, &version, sizeof(version));
}

static int quac100_ioctl_get_info(struct quac100_device *qdev,
                                  void __user *arg)
{
    struct quac100_device_info info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    info.driver_version = (QUAC100_API_VERSION_MAJOR << 16) |
                          (QUAC100_API_VERSION_MINOR << 8) |
                          QUAC100_API_VERSION_PATCH;
    info.device_index = qdev->dev_index;
    strncpy(info.device_name, qdev->name, sizeof(info.device_name) - 1);
    strncpy(info.serial_number, qdev->serial_number,
            sizeof(info.serial_number) - 1);
    info.vendor_id = qdev->pdev->vendor;
    info.device_id = qdev->pdev->device;
    info.subsystem_id = qdev->pdev->subsystem_device;
    info.revision = qdev->pdev->revision;
    info.fw_version = qdev->fw_version;
    info.capabilities = qdev->capabilities;
    info.status = quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS);
    info.max_batch_size = QUAC100_MAX_BATCH_SIZE;
    info.max_pending_jobs = QUAC100_MAX_PENDING_JOBS;
    info.key_slots_total = QUAC100_MAX_KEY_SLOTS;
    info.key_slots_used = qdev->key_slots_used;

    return quac100_copy_to_user_safe(arg, &info, sizeof(info));
}

static int quac100_ioctl_get_caps(struct quac100_device *qdev,
                                  void __user *arg)
{
    return quac100_copy_to_user_safe(arg, &qdev->capabilities,
                                     sizeof(qdev->capabilities));
}

static int quac100_ioctl_get_status(struct quac100_device *qdev,
                                    void __user *arg)
{
    u32 status = quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS);
    return quac100_copy_to_user_safe(arg, &status, sizeof(status));
}

static int quac100_ioctl_reset(struct quac100_device *qdev,
                               void __user *arg)
{
    u32 type;
    int ret;

    ret = quac100_copy_from_user_safe(&type, arg, sizeof(type));
    if (ret)
        return ret;

    return quac100_device_reset(qdev, type);
}

/*=============================================================================
 * Cryptographic Operation IOCTLs
 *=============================================================================*/

static int quac100_ioctl_random(struct quac100_device *qdev,
                                void __user *arg)
{
    struct quac100_random req;
    u8 *buffer = NULL;
    int ret;

    ret = quac100_copy_from_user_safe(&req, arg, sizeof(req));
    if (ret)
        return ret;

    if (req.length == 0 || req.length > 1024 * 1024)
    {
        req.result = -EINVAL;
        goto out;
    }

    buffer = kmalloc(req.length, GFP_KERNEL);
    if (!buffer)
    {
        req.result = -ENOMEM;
        goto out;
    }

    /* Read from hardware QRNG */
    /* For now, read from QRNG status register as placeholder */
    {
        u32 entropy = quac100_read32(qdev, QUAC100_REG_QRNG_ENTROPY);
        size_t i;

        /* Simple placeholder - real implementation would use hardware QRNG */
        for (i = 0; i < req.length; i++)
        {
            if (i % 4 == 0)
                entropy = quac100_read32(qdev, QUAC100_REG_QRNG_STATUS);
            buffer[i] = (entropy >> ((i % 4) * 8)) & 0xFF;
        }
    }

    /* Copy to user buffer */
    if (copy_to_user((void __user *)req.buf_addr, buffer, req.length))
    {
        req.result = -EFAULT;
        goto out;
    }

    atomic64_add(req.length, &qdev->stats.random_bytes);
    req.result = 0;

out:
    kfree(buffer);
    return quac100_copy_to_user_safe(arg, &req, sizeof(req));
}

/*=============================================================================
 * Diagnostic IOCTLs
 *=============================================================================*/

static int quac100_ioctl_get_temp(struct quac100_device *qdev,
                                  void __user *arg)
{
    s32 temp = quac100_read32(qdev, QUAC100_REG_TEMP_CORE);
    return quac100_copy_to_user_safe(arg, &temp, sizeof(temp));
}

static int quac100_ioctl_get_health(struct quac100_device *qdev,
                                    void __user *arg)
{
    struct quac100_health health;

    memset(&health, 0, sizeof(health));

    health.state = 0; /* OK */
    health.flags = 0;
    health.temp_core = quac100_read32(qdev, QUAC100_REG_TEMP_CORE);
    health.temp_memory = quac100_read32(qdev, QUAC100_REG_TEMP_MEMORY);
    health.voltage_mv = quac100_read32(qdev, QUAC100_REG_VOLTAGE_CORE);
    health.power_mw = quac100_read32(qdev, QUAC100_REG_POWER_DRAW);
    health.entropy_bits = quac100_read32(qdev, QUAC100_REG_QRNG_ENTROPY);
    health.ops_completed = atomic64_read(&qdev->stats.ops_completed);
    health.ops_failed = atomic64_read(&qdev->stats.ops_failed);

    return quac100_copy_to_user_safe(arg, &health, sizeof(health));
}

static int quac100_ioctl_get_counters(struct quac100_device *qdev,
                                      void __user *arg)
{
    struct quac100_counters counters;

    counters.kem_keygen_count = atomic64_read(&qdev->stats.kem_keygen_count);
    counters.kem_encaps_count = atomic64_read(&qdev->stats.kem_encaps_count);
    counters.kem_decaps_count = atomic64_read(&qdev->stats.kem_decaps_count);
    counters.sign_keygen_count = atomic64_read(&qdev->stats.sign_keygen_count);
    counters.sign_count = atomic64_read(&qdev->stats.sign_count);
    counters.verify_count = atomic64_read(&qdev->stats.verify_count);
    counters.random_bytes = atomic64_read(&qdev->stats.random_bytes);
    counters.dma_read_bytes = atomic64_read(&qdev->stats.dma_read_bytes);
    counters.dma_write_bytes = atomic64_read(&qdev->stats.dma_write_bytes);
    counters.errors_total = atomic64_read(&qdev->stats.errors);

    return quac100_copy_to_user_safe(arg, &counters, sizeof(counters));
}

static int quac100_ioctl_self_test(struct quac100_device *qdev,
                                   void __user *arg)
{
    struct quac100_self_test test;
    int ret;
    ktime_t start, end;

    ret = quac100_copy_from_user_safe(&test, arg, sizeof(test));
    if (ret)
        return ret;

    start = ktime_get();

    /* Placeholder: Run self-tests based on test.tests bitmask */
    test.tests_passed = test.tests;
    test.tests_failed = 0;
    test.result = 0;

    end = ktime_get();
    test.duration_us = ktime_us_delta(end, start);

    return quac100_copy_to_user_safe(arg, &test, sizeof(test));
}

/*=============================================================================
 * Main IOCTL Handler
 *=============================================================================*/

long quac100_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct quac100_device *qdev = file->private_data;
    void __user *argp = (void __user *)arg;
    int ret = -ENOTTY;

    if (!qdev)
        return -ENODEV;

    if (_IOC_TYPE(cmd) != QUAC100_IOCTL_MAGIC)
        return -ENOTTY;

    /* Check device state for operations that require it */
    if (!qdev->initialized && cmd != QUAC100_IOCTL_GET_VERSION)
        return -ENODEV;

    mutex_lock(&qdev->dev_lock);

    switch (cmd)
    {
    /* Device management */
    case QUAC100_IOCTL_GET_VERSION:
        ret = quac100_ioctl_get_version(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_INFO:
        ret = quac100_ioctl_get_info(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_CAPS:
        ret = quac100_ioctl_get_caps(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_STATUS:
        ret = quac100_ioctl_get_status(qdev, argp);
        break;

    case QUAC100_IOCTL_RESET:
        ret = quac100_ioctl_reset(qdev, argp);
        break;

    /* Random generation */
    case QUAC100_IOCTL_RANDOM:
        ret = quac100_ioctl_random(qdev, argp);
        break;

    /* Diagnostics */
    case QUAC100_IOCTL_SELF_TEST:
        ret = quac100_ioctl_self_test(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_HEALTH:
        ret = quac100_ioctl_get_health(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_TEMP:
        ret = quac100_ioctl_get_temp(qdev, argp);
        break;

    case QUAC100_IOCTL_GET_COUNTERS:
        ret = quac100_ioctl_get_counters(qdev, argp);
        break;

    /* Unimplemented IOCTLs - placeholder */
    case QUAC100_IOCTL_KEM_KEYGEN:
    case QUAC100_IOCTL_KEM_ENCAPS:
    case QUAC100_IOCTL_KEM_DECAPS:
    case QUAC100_IOCTL_SIGN_KEYGEN:
    case QUAC100_IOCTL_SIGN:
    case QUAC100_IOCTL_VERIFY:
        quac100_dbg(qdev, "IOCTL 0x%x not yet implemented\n", cmd);
        ret = -ENOTTY;
        break;

    default:
        quac100_dbg(qdev, "Unknown IOCTL: 0x%x\n", cmd);
        ret = -ENOTTY;
        break;
    }

    mutex_unlock(&qdev->dev_lock);
    return ret;
}

/*=============================================================================
 * IOCTL Init/Cleanup
 *=============================================================================*/

int quac100_ioctl_init(struct quac100_device *qdev)
{
    /* Nothing specific to initialize */
    return 0;
}

void quac100_ioctl_cleanup(struct quac100_device *qdev)
{
    /* Nothing specific to cleanup */
}