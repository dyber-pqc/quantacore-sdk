// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - SR-IOV Support
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/pci.h>

#include "quac100_drv.h"

/*=============================================================================
 * SR-IOV Callback Handlers
 *=============================================================================*/

#ifdef CONFIG_PCI_IOV

static int quac100_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    if (num_vfs == 0)
    {
        quac100_sriov_disable(qdev);
        return 0;
    }

    return quac100_sriov_enable(qdev, num_vfs);
}

/*=============================================================================
 * SR-IOV Enable/Disable
 *=============================================================================*/

int quac100_sriov_enable(struct quac100_device *qdev, int num_vfs_requested)
{
    struct pci_dev *pdev = qdev->pdev;
    int ret, actual_vfs;

    if (!enable_sriov)
    {
        quac100_warn(qdev, "SR-IOV disabled by module parameter\n");
        return -EPERM;
    }

    if (qdev->sriov_enabled)
    {
        quac100_warn(qdev, "SR-IOV already enabled with %d VFs\n",
                     qdev->num_vfs);
        return -EBUSY;
    }

    /* Limit to maximum supported VFs */
    actual_vfs = min_t(int, num_vfs_requested, QUAC100_MAX_VFS);
    if (actual_vfs <= 0)
    {
        quac100_err(qdev, "Invalid number of VFs requested: %d\n",
                    num_vfs_requested);
        return -EINVAL;
    }

    quac100_info(qdev, "Enabling SR-IOV with %d VFs\n", actual_vfs);

    /* Enable SR-IOV */
    ret = pci_enable_sriov(pdev, actual_vfs);
    if (ret)
    {
        quac100_err(qdev, "Failed to enable SR-IOV: %d\n", ret);
        return ret;
    }

    qdev->num_vfs = actual_vfs;
    qdev->sriov_enabled = true;

    quac100_info(qdev, "SR-IOV enabled with %d VFs\n", actual_vfs);
    return actual_vfs;
}

void quac100_sriov_disable(struct quac100_device *qdev)
{
    if (!qdev->sriov_enabled)
        return;

    quac100_info(qdev, "Disabling SR-IOV\n");

    pci_disable_sriov(qdev->pdev);

    qdev->num_vfs = 0;
    qdev->sriov_enabled = false;

    quac100_info(qdev, "SR-IOV disabled\n");
}

/*=============================================================================
 * SR-IOV Initialization
 *=============================================================================*/

int quac100_sriov_init(struct quac100_device *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    int total_vfs;

    /* Check if SR-IOV is supported */
    if (!pdev->is_physfn)
    {
        quac100_info(qdev, "Not a physical function, SR-IOV not available\n");
        return 0;
    }

    total_vfs = pci_sriov_get_totalvfs(pdev);
    if (total_vfs <= 0)
    {
        quac100_info(qdev, "SR-IOV not supported by device\n");
        return 0;
    }

    quac100_info(qdev, "SR-IOV supported: %d total VFs available\n", total_vfs);

    /* Enable VFs if requested via module parameter */
    if (num_vfs > 0)
    {
        return quac100_sriov_enable(qdev, num_vfs);
    }

    return 0;
}

void quac100_sriov_cleanup(struct quac100_device *qdev)
{
    quac100_sriov_disable(qdev);
}

#else /* !CONFIG_PCI_IOV */

int quac100_sriov_init(struct quac100_device *qdev)
{
    if (enable_sriov)
        quac100_warn(qdev, "SR-IOV requested but kernel not configured "
                           "with CONFIG_PCI_IOV\n");
    return 0;
}

void quac100_sriov_cleanup(struct quac100_device *qdev)
{
    /* Nothing to do */
}

int quac100_sriov_enable(struct quac100_device *qdev, int num_vfs)
{
    quac100_err(qdev, "SR-IOV not supported (CONFIG_PCI_IOV not enabled)\n");
    return -ENODEV;
}

void quac100_sriov_disable(struct quac100_device *qdev)
{
    /* Nothing to do */
}

#endif /* CONFIG_PCI_IOV */

/*=============================================================================
 * SR-IOV sysfs Interface
 *=============================================================================*/

ssize_t quac100_sriov_num_vfs_show(struct device *dev,
                                   struct device_attribute *attr,
                                   char *buf)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct quac100_device *qdev = pci_get_drvdata(pdev);

    return sprintf(buf, "%d\n", qdev->num_vfs);
}

ssize_t quac100_sriov_num_vfs_store(struct device *dev,
                                    struct device_attribute *attr,
                                    const char *buf, size_t count)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct quac100_device *qdev = pci_get_drvdata(pdev);
    int num_vfs, ret;

    ret = kstrtoint(buf, 0, &num_vfs);
    if (ret)
        return ret;

    if (num_vfs < 0 || num_vfs > QUAC100_MAX_VFS)
        return -EINVAL;

    if (num_vfs == 0)
    {
        quac100_sriov_disable(qdev);
    }
    else
    {
        ret = quac100_sriov_enable(qdev, num_vfs);
        if (ret < 0)
            return ret;
    }

    return count;
}