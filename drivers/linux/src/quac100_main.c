// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - Main Module
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/mutex.h>

#include "quac100_drv.h"

/*=============================================================================
 * Module Parameters
 *=============================================================================*/

int max_devices = QUAC100_MAX_DEVICES;
module_param(max_devices, int, 0444);
MODULE_PARM_DESC(max_devices, "Maximum number of devices to support (default: 16)");

int dma_ring_size = QUAC100_DEFAULT_RING_SIZE;
module_param(dma_ring_size, int, 0444);
MODULE_PARM_DESC(dma_ring_size, "DMA descriptor ring size (default: 256, max: 4096)");

int msix_vectors = QUAC100_DEFAULT_MSIX;
module_param(msix_vectors, int, 0444);
MODULE_PARM_DESC(msix_vectors, "Number of MSI-X vectors (default: 8, max: 32)");

int enable_sriov = 0;
module_param(enable_sriov, int, 0444);
MODULE_PARM_DESC(enable_sriov, "Enable SR-IOV support (default: 0)");

int num_vfs = 0;
module_param(num_vfs, int, 0644);
MODULE_PARM_DESC(num_vfs, "Number of VFs to enable (default: 0, max: 16)");

int debug_level = QUAC100_DEBUG_INFO;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0=none, 1=error, 2=warn, 3=info, 4=debug, 5=trace)");

/*=============================================================================
 * Global Variables
 *=============================================================================*/

struct class *quac100_class;
int quac100_major;
DEFINE_IDR(quac100_idr);
DEFINE_MUTEX(quac100_idr_lock);

static dev_t quac100_devno;
static int quac100_device_count;

/*=============================================================================
 * PCI Device Table
 *=============================================================================*/

static const struct pci_device_id quac100_pci_ids[] = {
    {PCI_DEVICE(QUAC100_PCI_VENDOR_ID, QUAC100_PCI_DEVICE_ID)},
    /* Add additional device IDs as needed */
    {PCI_DEVICE(0x1234, 0x0100)}, /* Development/test ID */
    {
        0,
    }};
MODULE_DEVICE_TABLE(pci, quac100_pci_ids);

/*=============================================================================
 * File Operations
 *=============================================================================*/

static int quac100_open(struct inode *inode, struct file *file)
{
    struct quac100_device *qdev;

    qdev = container_of(inode->i_cdev, struct quac100_device, cdev);
    if (!qdev)
        return -ENODEV;

    file->private_data = qdev;

    quac100_dbg(qdev, "Device opened\n");
    return 0;
}

static int quac100_release(struct inode *inode, struct file *file)
{
    struct quac100_device *qdev = file->private_data;

    if (qdev)
        quac100_dbg(qdev, "Device closed\n");

    return 0;
}

static int quac100_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct quac100_device *qdev = file->private_data;
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    phys_addr_t phys;

    if (!qdev)
        return -ENODEV;

    /* Validate offset and size */
    if (offset + size > qdev->bar0_len)
        return -EINVAL;

    /* Get physical address */
    phys = pci_resource_start(qdev->pdev, QUAC100_BAR_REGS) + offset;

    /* Set non-cacheable */
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    /* Map to userspace */
    if (remap_pfn_range(vma, vma->vm_start, phys >> PAGE_SHIFT,
                        size, vma->vm_page_prot))
        return -EAGAIN;

    quac100_dbg(qdev, "mmap: offset=%lu size=%lu\n", offset, size);
    return 0;
}

static const struct file_operations quac100_fops = {
    .owner = THIS_MODULE,
    .open = quac100_open,
    .release = quac100_release,
    .unlocked_ioctl = quac100_ioctl,
    .compat_ioctl = quac100_ioctl,
    .mmap = quac100_mmap,
};

/*=============================================================================
 * Device Initialization
 *=============================================================================*/

int quac100_device_init(struct quac100_device *qdev)
{
    int ret;

    /* Read device identification */
    qdev->hw_version = quac100_read32(qdev, QUAC100_REG_DEVICE_REV);
    qdev->fw_version = quac100_read32(qdev, QUAC100_REG_FW_VERSION);
    qdev->capabilities = quac100_read32(qdev, QUAC100_REG_DEVICE_CAPS);

    quac100_info(qdev, "HW version: 0x%08x, FW version: 0x%08x\n",
                 qdev->hw_version, qdev->fw_version);

    /* Initialize DMA */
    ret = quac100_dma_init(qdev);
    if (ret)
    {
        quac100_err(qdev, "Failed to initialize DMA: %d\n", ret);
        return ret;
    }

    /* Initialize interrupts */
    ret = quac100_irq_init(qdev);
    if (ret)
    {
        quac100_err(qdev, "Failed to initialize IRQ: %d\n", ret);
        goto err_dma;
    }

    /* Initialize job management */
    idr_init(&qdev->job_idr);
    spin_lock_init(&qdev->job_lock);
    INIT_LIST_HEAD(&qdev->job_pending);
    INIT_LIST_HEAD(&qdev->job_running);
    qdev->next_job_id = 1;

    /* Create workqueue */
    qdev->work_queue = alloc_workqueue("quac100_%d", WQ_UNBOUND | WQ_HIGHPRI,
                                       0, qdev->dev_index);
    if (!qdev->work_queue)
    {
        quac100_err(qdev, "Failed to create workqueue\n");
        ret = -ENOMEM;
        goto err_irq;
    }

    /* Initialize key storage */
    idr_init(&qdev->key_idr);
    mutex_init(&qdev->key_lock);
    qdev->key_slots_used = 0;

    /* Initialize statistics */
    atomic64_set(&qdev->stats.kem_keygen_count, 0);
    atomic64_set(&qdev->stats.kem_encaps_count, 0);
    atomic64_set(&qdev->stats.kem_decaps_count, 0);
    atomic64_set(&qdev->stats.sign_keygen_count, 0);
    atomic64_set(&qdev->stats.sign_count, 0);
    atomic64_set(&qdev->stats.verify_count, 0);
    atomic64_set(&qdev->stats.random_bytes, 0);
    atomic64_set(&qdev->stats.dma_read_bytes, 0);
    atomic64_set(&qdev->stats.dma_write_bytes, 0);
    atomic64_set(&qdev->stats.errors, 0);
    atomic64_set(&qdev->stats.ops_completed, 0);
    atomic64_set(&qdev->stats.ops_failed, 0);

    /* Initialize sysfs */
    ret = quac100_sysfs_init(qdev);
    if (ret)
    {
        quac100_err(qdev, "Failed to initialize sysfs: %d\n", ret);
        goto err_wq;
    }

    /* Initialize SR-IOV if enabled */
    if (enable_sriov)
    {
        ret = quac100_sriov_init(qdev);
        if (ret)
            quac100_warn(qdev, "SR-IOV initialization failed: %d\n", ret);
    }

    qdev->initialized = true;
    quac100_info(qdev, "Device initialized successfully\n");
    return 0;

err_wq:
    destroy_workqueue(qdev->work_queue);
err_irq:
    quac100_irq_cleanup(qdev);
err_dma:
    quac100_dma_cleanup(qdev);
    return ret;
}

void quac100_device_cleanup(struct quac100_device *qdev)
{
    if (!qdev->initialized)
        return;

    quac100_device_disable(qdev);

    if (enable_sriov)
        quac100_sriov_cleanup(qdev);

    quac100_sysfs_cleanup(qdev);

    if (qdev->work_queue)
        destroy_workqueue(qdev->work_queue);

    idr_destroy(&qdev->key_idr);
    idr_destroy(&qdev->job_idr);

    quac100_irq_cleanup(qdev);
    quac100_dma_cleanup(qdev);

    qdev->initialized = false;
}

int quac100_device_enable(struct quac100_device *qdev)
{
    u32 ctrl;

    if (qdev->enabled)
        return 0;

    /* Enable device */
    ctrl = QUAC100_DEVCTL_ENABLE | QUAC100_DEVCTL_DMA_ENABLE |
           QUAC100_DEVCTL_INT_ENABLE;
    quac100_write32(qdev, QUAC100_REG_DEVICE_CONTROL, ctrl);

    /* Wait for ready */
    msleep(10);

    /* Check status */
    qdev->status = quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS);
    if (!(qdev->status & QUAC100_DEVSTS_READY))
    {
        quac100_err(qdev, "Device not ready after enable\n");
        return -EIO;
    }

    /* Enable interrupts */
    quac100_irq_enable(qdev);

    /* Start DMA channels */
    for (int i = 0; i < QUAC100_DMA_CHANNELS; i++)
    {
        int ret = quac100_dma_channel_start(qdev, i);
        if (ret)
            quac100_warn(qdev, "Failed to start DMA channel %d: %d\n", i, ret);
    }

    qdev->enabled = true;
    quac100_info(qdev, "Device enabled\n");
    return 0;
}

void quac100_device_disable(struct quac100_device *qdev)
{
    if (!qdev->enabled)
        return;

    /* Stop DMA channels */
    for (int i = 0; i < QUAC100_DMA_CHANNELS; i++)
        quac100_dma_channel_stop(qdev, i);

    /* Disable interrupts */
    quac100_irq_disable(qdev);

    /* Disable device */
    quac100_write32(qdev, QUAC100_REG_DEVICE_CONTROL, 0);

    qdev->enabled = false;
    quac100_info(qdev, "Device disabled\n");
}

int quac100_device_reset(struct quac100_device *qdev, u32 type)
{
    u32 ctrl;
    int timeout = 1000;

    quac100_info(qdev, "Resetting device (type=%u)\n", type);

    quac100_device_disable(qdev);

    /* Perform reset */
    switch (type)
    {
    case 0: /* Soft reset */
        quac100_write32(qdev, QUAC100_REG_RESET, QUAC100_DEVCTL_RESET);
        break;
    case 1: /* Hard reset (FLR) */
        pcie_flr(qdev->pdev);
        break;
    default:
        return -EINVAL;
    }

    /* Wait for reset to complete */
    msleep(100);

    /* Wait for device ready */
    while (timeout--)
    {
        ctrl = quac100_read32(qdev, QUAC100_REG_DEVICE_STATUS);
        if (ctrl & QUAC100_DEVSTS_READY)
            break;
        msleep(1);
    }

    if (timeout <= 0)
    {
        quac100_err(qdev, "Device reset timeout\n");
        return -ETIMEDOUT;
    }

    /* Re-enable device */
    return quac100_device_enable(qdev);
}

/*=============================================================================
 * PCI Probe/Remove
 *=============================================================================*/

static int quac100_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct quac100_device *qdev;
    int ret, dev_index;

    /* Check device count limit */
    mutex_lock(&quac100_idr_lock);
    if (quac100_device_count >= max_devices)
    {
        mutex_unlock(&quac100_idr_lock);
        dev_err(&pdev->dev, "Maximum device count (%d) reached\n", max_devices);
        return -ENODEV;
    }

    /* Allocate device index */
    dev_index = idr_alloc(&quac100_idr, NULL, 0, max_devices, GFP_KERNEL);
    if (dev_index < 0)
    {
        mutex_unlock(&quac100_idr_lock);
        dev_err(&pdev->dev, "Failed to allocate device index\n");
        return dev_index;
    }
    quac100_device_count++;
    mutex_unlock(&quac100_idr_lock);

    /* Allocate device structure */
    qdev = kzalloc(sizeof(*qdev), GFP_KERNEL);
    if (!qdev)
    {
        ret = -ENOMEM;
        goto err_idr;
    }

    qdev->pdev = pdev;
    qdev->dev_index = dev_index;
    snprintf(qdev->name, sizeof(qdev->name), "quac100_%d", dev_index);
    mutex_init(&qdev->dev_lock);

    pci_set_drvdata(pdev, qdev);

    /* Initialize PCIe */
    ret = quac100_pcie_init(qdev);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to initialize PCIe: %d\n", ret);
        goto err_free;
    }

    /* Enable PCIe device */
    ret = quac100_pcie_enable_device(qdev);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to enable PCIe device: %d\n", ret);
        goto err_pcie;
    }

    /* Initialize character device */
    qdev->devno = MKDEV(quac100_major, dev_index);
    cdev_init(&qdev->cdev, &quac100_fops);
    qdev->cdev.owner = THIS_MODULE;

    ret = cdev_add(&qdev->cdev, qdev->devno, 1);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to add character device: %d\n", ret);
        goto err_enable;
    }

    /* Create device node */
    qdev->dev = device_create(quac100_class, &pdev->dev, qdev->devno,
                              qdev, "quac100_%d", dev_index);
    if (IS_ERR(qdev->dev))
    {
        ret = PTR_ERR(qdev->dev);
        dev_err(&pdev->dev, "Failed to create device: %d\n", ret);
        goto err_cdev;
    }

    /* Update IDR with device pointer */
    mutex_lock(&quac100_idr_lock);
    idr_replace(&quac100_idr, qdev, dev_index);
    mutex_unlock(&quac100_idr_lock);

    /* Initialize device */
    ret = quac100_device_init(qdev);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to initialize device: %d\n", ret);
        goto err_device;
    }

    /* Enable device */
    ret = quac100_device_enable(qdev);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to enable device: %d\n", ret);
        goto err_init;
    }

    dev_info(&pdev->dev, "QUAC 100 device %d initialized successfully\n", dev_index);
    return 0;

err_init:
    quac100_device_cleanup(qdev);
err_device:
    device_destroy(quac100_class, qdev->devno);
err_cdev:
    cdev_del(&qdev->cdev);
err_enable:
    quac100_pcie_disable_device(qdev);
err_pcie:
    quac100_pcie_cleanup(qdev);
err_free:
    kfree(qdev);
err_idr:
    mutex_lock(&quac100_idr_lock);
    idr_remove(&quac100_idr, dev_index);
    quac100_device_count--;
    mutex_unlock(&quac100_idr_lock);
    return ret;
}

static void quac100_remove(struct pci_dev *pdev)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    if (!qdev)
        return;

    dev_info(&pdev->dev, "Removing QUAC 100 device %d\n", qdev->dev_index);

    quac100_device_cleanup(qdev);
    device_destroy(quac100_class, qdev->devno);
    cdev_del(&qdev->cdev);
    quac100_pcie_disable_device(qdev);
    quac100_pcie_cleanup(qdev);

    mutex_lock(&quac100_idr_lock);
    idr_remove(&quac100_idr, qdev->dev_index);
    quac100_device_count--;
    mutex_unlock(&quac100_idr_lock);

    kfree(qdev);
}

static void quac100_shutdown(struct pci_dev *pdev)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    if (qdev)
        quac100_device_disable(qdev);
}

/*=============================================================================
 * Power Management
 *=============================================================================*/

#ifdef CONFIG_PM_SLEEP
static int quac100_suspend(struct device *dev)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    quac100_info(qdev, "Suspending device\n");
    quac100_device_disable(qdev);
    return 0;
}

static int quac100_resume(struct device *dev)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    quac100_info(qdev, "Resuming device\n");
    return quac100_device_enable(qdev);
}

static SIMPLE_DEV_PM_OPS(quac100_pm_ops, quac100_suspend, quac100_resume);
#endif

/*=============================================================================
 * Error Recovery
 *=============================================================================*/

static pci_ers_result_t quac100_error_detected(struct pci_dev *pdev,
                                               pci_channel_state_t state)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    quac100_err(qdev, "PCI error detected, state=%d\n", state);

    if (state == pci_channel_io_perm_failure)
        return PCI_ERS_RESULT_DISCONNECT;

    quac100_device_disable(qdev);
    return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t quac100_slot_reset(struct pci_dev *pdev)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    quac100_info(qdev, "Slot reset\n");

    if (quac100_pcie_enable_device(qdev))
        return PCI_ERS_RESULT_DISCONNECT;

    return PCI_ERS_RESULT_RECOVERED;
}

static void quac100_error_resume(struct pci_dev *pdev)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    quac100_info(qdev, "Error recovery complete\n");
    quac100_device_enable(qdev);
}

static const struct pci_error_handlers quac100_err_handlers = {
    .error_detected = quac100_error_detected,
    .slot_reset = quac100_slot_reset,
    .resume = quac100_error_resume,
};

/*=============================================================================
 * PCI Driver Structure
 *=============================================================================*/

static struct pci_driver quac100_driver = {
    .name = QUAC100_DRIVER_NAME,
    .id_table = quac100_pci_ids,
    .probe = quac100_probe,
    .remove = quac100_remove,
    .shutdown = quac100_shutdown,
#ifdef CONFIG_PM_SLEEP
    .driver.pm = &quac100_pm_ops,
#endif
    .err_handler = &quac100_err_handlers,
};

/*=============================================================================
 * Module Init/Exit
 *=============================================================================*/

static int __init quac100_init(void)
{
    int ret;

    pr_info("Loading %s v%s\n", QUAC100_DRIVER_DESC, QUAC100_DRIVER_VERSION);

    /* Validate parameters */
    if (max_devices < 1 || max_devices > QUAC100_MAX_DEVICES)
    {
        pr_err("Invalid max_devices parameter (1-%d)\n", QUAC100_MAX_DEVICES);
        return -EINVAL;
    }

    if (dma_ring_size < 16 || dma_ring_size > QUAC100_MAX_DMA_RING_SIZE)
    {
        pr_err("Invalid dma_ring_size parameter (16-%d)\n",
               QUAC100_MAX_DMA_RING_SIZE);
        return -EINVAL;
    }

    if (msix_vectors < 1 || msix_vectors > QUAC100_MAX_MSIX_VECTORS)
    {
        pr_err("Invalid msix_vectors parameter (1-%d)\n",
               QUAC100_MAX_MSIX_VECTORS);
        return -EINVAL;
    }

    /* Allocate character device region */
    ret = alloc_chrdev_region(&quac100_devno, 0, max_devices,
                              QUAC100_DRIVER_NAME);
    if (ret)
    {
        pr_err("Failed to allocate chrdev region: %d\n", ret);
        return ret;
    }
    quac100_major = MAJOR(quac100_devno);

    /* Create device class */
    quac100_class = class_create(QUAC100_DRIVER_NAME);
    if (IS_ERR(quac100_class))
    {
        ret = PTR_ERR(quac100_class);
        pr_err("Failed to create device class: %d\n", ret);
        goto err_chrdev;
    }

    /* Register PCI driver */
    ret = pci_register_driver(&quac100_driver);
    if (ret)
    {
        pr_err("Failed to register PCI driver: %d\n", ret);
        goto err_class;
    }

    pr_info("%s loaded successfully\n", QUAC100_DRIVER_NAME);
    return 0;

err_class:
    class_destroy(quac100_class);
err_chrdev:
    unregister_chrdev_region(quac100_devno, max_devices);
    return ret;
}

static void __exit quac100_exit(void)
{
    pr_info("Unloading %s\n", QUAC100_DRIVER_NAME);

    pci_unregister_driver(&quac100_driver);
    class_destroy(quac100_class);
    unregister_chrdev_region(quac100_devno, max_devices);
    idr_destroy(&quac100_idr);

    pr_info("%s unloaded\n", QUAC100_DRIVER_NAME);
}

module_init(quac100_init);
module_exit(quac100_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(QUAC100_DRIVER_AUTHOR);
MODULE_DESCRIPTION(QUAC100_DRIVER_DESC);
MODULE_VERSION(QUAC100_DRIVER_VERSION);