/**
 * @file device_linux.c
 * @brief QuantaCore SDK - Linux Device Discovery and Management
 *
 * Implements Linux-specific device enumeration, PCIe device discovery via sysfs,
 * device file management, and hardware initialization.
 *
 * Device Discovery Methods:
 * 1. Sysfs enumeration (/sys/bus/pci/devices)
 * 2. Device file detection (/dev/quac*)
 * 3. Udev integration for hotplug support
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/pci.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_pcie.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Dyber PCI Vendor ID */
#define QUAC_PCI_VENDOR_ID 0x1FC0

/** QUAC 100 PCI Device ID */
#define QUAC_PCI_DEVICE_ID 0x0100

/** Maximum devices to enumerate */
#define QUAC_MAX_DEVICES 16

/** Sysfs PCI devices path */
#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"

/** Device file prefix */
#define QUAC_DEV_PREFIX "/dev/quac"

/** Device file pattern */
#define QUAC_DEV_PATTERN "/dev/quac%d"

/** Control device file */
#define QUAC_DEV_CONTROL "/dev/quac_control"

/** Sysfs attribute buffer size */
#define SYSFS_ATTR_SIZE 256

/** PCIe config space size */
#define PCIE_CONFIG_SPACE_SIZE 4096

/** PCIe BAR0 expected size (16 MB) */
#define QUAC_BAR0_SIZE (16 * 1024 * 1024)

/** PCIe BAR2 expected size (256 MB for DMA) */
#define QUAC_BAR2_SIZE (256 * 1024 * 1024)

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Linux device information
 */
typedef struct quac_linux_device_s
{
    /* Identification */
    uint32_t index;       /**< Device index */
    char pci_slot[32];    /**< PCI slot (DDDD:BB:DD.F) */
    char dev_path[64];    /**< Device file path */
    char sysfs_path[256]; /**< Sysfs path */

    /* PCI IDs */
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor;
    uint16_t subsystem_device;
    uint8_t revision;

    /* PCIe capabilities */
    uint8_t pcie_gen;     /**< PCIe generation (1-5) */
    uint8_t pcie_width;   /**< Link width (x1-x16) */
    uint8_t max_payload;  /**< Max payload size */
    uint8_t max_read_req; /**< Max read request size */

    /* BAR information */
    uint64_t bar0_addr; /**< BAR0 physical address */
    uint64_t bar0_size; /**< BAR0 size */
    uint64_t bar2_addr; /**< BAR2 physical address */
    uint64_t bar2_size; /**< BAR2 size */

    /* State */
    bool available;       /**< Device is available */
    bool driver_bound;    /**< Kernel driver is bound */
    char driver_name[64]; /**< Bound driver name */

    /* Serial number (from device) */
    char serial[32];

} quac_linux_device_t;

/**
 * @brief Device enumeration state
 */
typedef struct quac_enum_state_s
{
    quac_linux_device_t devices[QUAC_MAX_DEVICES];
    uint32_t count;
    bool initialized;
} quac_enum_state_t;

/** Global enumeration state */
static quac_enum_state_t g_enum = {0};

/*=============================================================================
 * Sysfs Helpers
 *=============================================================================*/

/**
 * @brief Read sysfs attribute as string
 */
static int sysfs_read_string(const char *path, char *buffer, size_t size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return -errno;
    }

    ssize_t n = read(fd, buffer, size - 1);
    close(fd);

    if (n < 0)
    {
        return -errno;
    }

    buffer[n] = '\0';

    /* Remove trailing newline */
    while (n > 0 && (buffer[n - 1] == '\n' || buffer[n - 1] == '\r'))
    {
        buffer[--n] = '\0';
    }

    return (int)n;
}

/**
 * @brief Read sysfs attribute as hex value
 */
static int sysfs_read_hex(const char *path, uint64_t *value)
{
    char buffer[SYSFS_ATTR_SIZE];

    if (sysfs_read_string(path, buffer, sizeof(buffer)) < 0)
    {
        return -1;
    }

    *value = strtoull(buffer, NULL, 16);
    return 0;
}

/**
 * @brief Read sysfs attribute as decimal value
 */
static int sysfs_read_dec(const char *path, uint64_t *value)
{
    char buffer[SYSFS_ATTR_SIZE];

    if (sysfs_read_string(path, buffer, sizeof(buffer)) < 0)
    {
        return -1;
    }

    *value = strtoull(buffer, NULL, 10);
    return 0;
}

/**
 * @brief Check if file/directory exists
 */
static bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/**
 * @brief Read PCI resource file to get BAR info
 * Format: start_addr end_addr flags
 */
static int read_pci_resource(const char *sysfs_path, int bar,
                             uint64_t *addr, uint64_t *size)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/resource", sysfs_path);

    FILE *f = fopen(path, "r");
    if (!f)
    {
        return -errno;
    }

    char line[256];
    int current_bar = 0;

    while (fgets(line, sizeof(line), f))
    {
        if (current_bar == bar)
        {
            uint64_t start, end, flags;
            if (sscanf(line, "0x%lx 0x%lx 0x%lx", &start, &end, &flags) == 3)
            {
                *addr = start;
                *size = (end > start) ? (end - start + 1) : 0;
                fclose(f);
                return 0;
            }
        }
        current_bar++;
    }

    fclose(f);
    return -ENOENT;
}

/*=============================================================================
 * PCIe Link Information
 *=============================================================================*/

/**
 * @brief Read PCIe link status from sysfs
 */
static void read_pcie_link_info(quac_linux_device_t *dev)
{
    char path[512];
    uint64_t value;

    /* Current link speed */
    snprintf(path, sizeof(path), "%s/current_link_speed", dev->sysfs_path);
    if (path_exists(path))
    {
        char speed[64];
        if (sysfs_read_string(path, speed, sizeof(speed)) > 0)
        {
            if (strstr(speed, "32"))
                dev->pcie_gen = 5;
            else if (strstr(speed, "16"))
                dev->pcie_gen = 4;
            else if (strstr(speed, "8"))
                dev->pcie_gen = 3;
            else if (strstr(speed, "5"))
                dev->pcie_gen = 2;
            else if (strstr(speed, "2.5"))
                dev->pcie_gen = 1;
        }
    }

    /* Current link width */
    snprintf(path, sizeof(path), "%s/current_link_width", dev->sysfs_path);
    if (path_exists(path))
    {
        if (sysfs_read_dec(path, &value) == 0)
        {
            dev->pcie_width = (uint8_t)value;
        }
    }

    /* Max payload size */
    snprintf(path, sizeof(path), "%s/max_link_speed", dev->sysfs_path);
    if (path_exists(path))
    {
        /* Would read from PCIe capabilities */
        dev->max_payload = 256; /* Default */
    }
}

/**
 * @brief Read driver binding information
 */
static void read_driver_info(quac_linux_device_t *dev)
{
    char path[512];
    char link_target[256];

    snprintf(path, sizeof(path), "%s/driver", dev->sysfs_path);

    ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
    if (len > 0)
    {
        link_target[len] = '\0';

        /* Extract driver name from path */
        char *name = strrchr(link_target, '/');
        if (name)
        {
            strncpy(dev->driver_name, name + 1, sizeof(dev->driver_name) - 1);
        }
        else
        {
            strncpy(dev->driver_name, link_target, sizeof(dev->driver_name) - 1);
        }

        dev->driver_bound = true;
    }
    else
    {
        dev->driver_bound = false;
        dev->driver_name[0] = '\0';
    }
}

/*=============================================================================
 * Device Discovery
 *=============================================================================*/

/**
 * @brief Scan single PCI device directory
 */
static int scan_pci_device(const char *slot_name, quac_linux_device_t *dev)
{
    char path[512];
    uint64_t value;

    /* Build sysfs path */
    snprintf(dev->sysfs_path, sizeof(dev->sysfs_path),
             "%s/%s", SYSFS_PCI_DEVICES, slot_name);

    /* Read vendor ID */
    snprintf(path, sizeof(path), "%s/vendor", dev->sysfs_path);
    if (sysfs_read_hex(path, &value) < 0)
    {
        return -1;
    }
    dev->vendor_id = (uint16_t)value;

    /* Check if it's our vendor */
    if (dev->vendor_id != QUAC_PCI_VENDOR_ID)
    {
        return -1;
    }

    /* Read device ID */
    snprintf(path, sizeof(path), "%s/device", dev->sysfs_path);
    if (sysfs_read_hex(path, &value) < 0)
    {
        return -1;
    }
    dev->device_id = (uint16_t)value;

    /* Check if it's our device */
    if (dev->device_id != QUAC_PCI_DEVICE_ID)
    {
        return -1;
    }

    /* Found a QUAC device! */
    strncpy(dev->pci_slot, slot_name, sizeof(dev->pci_slot) - 1);

    /* Read subsystem IDs */
    snprintf(path, sizeof(path), "%s/subsystem_vendor", dev->sysfs_path);
    if (sysfs_read_hex(path, &value) == 0)
    {
        dev->subsystem_vendor = (uint16_t)value;
    }

    snprintf(path, sizeof(path), "%s/subsystem_device", dev->sysfs_path);
    if (sysfs_read_hex(path, &value) == 0)
    {
        dev->subsystem_device = (uint16_t)value;
    }

    /* Read revision */
    snprintf(path, sizeof(path), "%s/revision", dev->sysfs_path);
    if (sysfs_read_hex(path, &value) == 0)
    {
        dev->revision = (uint8_t)value;
    }

    /* Read BAR information */
    read_pci_resource(dev->sysfs_path, 0, &dev->bar0_addr, &dev->bar0_size);
    read_pci_resource(dev->sysfs_path, 2, &dev->bar2_addr, &dev->bar2_size);

    /* Read PCIe link info */
    read_pcie_link_info(dev);

    /* Read driver info */
    read_driver_info(dev);

    /* Check for device file */
    snprintf(dev->dev_path, sizeof(dev->dev_path), QUAC_DEV_PATTERN, dev->index);
    dev->available = path_exists(dev->dev_path);

    /* Generate serial from PCI slot if not available from device */
    if (dev->serial[0] == '\0')
    {
        snprintf(dev->serial, sizeof(dev->serial), "QUAC-%s", slot_name);
    }

    return 0;
}

/**
 * @brief Enumerate devices via sysfs
 */
static int enumerate_sysfs(void)
{
    DIR *dir = opendir(SYSFS_PCI_DEVICES);
    if (!dir)
    {
        return -errno;
    }

    struct dirent *entry;
    uint32_t count = 0;

    while ((entry = readdir(dir)) != NULL && count < QUAC_MAX_DEVICES)
    {
        /* Skip . and .. */
        if (entry->d_name[0] == '.')
        {
            continue;
        }

        quac_linux_device_t *dev = &g_enum.devices[count];
        memset(dev, 0, sizeof(*dev));
        dev->index = count;

        if (scan_pci_device(entry->d_name, dev) == 0)
        {
            count++;
        }
    }

    closedir(dir);

    g_enum.count = count;
    return (int)count;
}

/**
 * @brief Enumerate devices via device files
 */
static int enumerate_devfiles(void)
{
    uint32_t count = 0;

    for (int i = 0; i < QUAC_MAX_DEVICES; i++)
    {
        char path[64];
        snprintf(path, sizeof(path), QUAC_DEV_PATTERN, i);

        if (path_exists(path))
        {
            quac_linux_device_t *dev = &g_enum.devices[count];

            /* If we already found this via sysfs, skip */
            bool found = false;
            for (uint32_t j = 0; j < count; j++)
            {
                if (strcmp(g_enum.devices[j].dev_path, path) == 0)
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                memset(dev, 0, sizeof(*dev));
                dev->index = count;
                strncpy(dev->dev_path, path, sizeof(dev->dev_path) - 1);
                dev->available = true;
                snprintf(dev->serial, sizeof(dev->serial), "QUAC-DEV%d", i);
                count++;
            }
        }
    }

    g_enum.count = count;
    return (int)count;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

/**
 * @brief Initialize Linux device subsystem
 */
quac_result_t quac_linux_device_init(void)
{
    if (g_enum.initialized)
    {
        return QUAC_SUCCESS;
    }

    memset(&g_enum, 0, sizeof(g_enum));

    /* Try sysfs enumeration first */
    int count = enumerate_sysfs();

    /* Fall back to device file enumeration */
    if (count <= 0)
    {
        count = enumerate_devfiles();
    }

    g_enum.initialized = true;

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown Linux device subsystem
 */
void quac_linux_device_shutdown(void)
{
    memset(&g_enum, 0, sizeof(g_enum));
}

/**
 * @brief Get number of devices
 */
quac_result_t quac_linux_device_count(uint32_t *count)
{
    if (!count)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    *count = g_enum.count;
    return QUAC_SUCCESS;
}

/**
 * @brief Refresh device enumeration
 */
quac_result_t quac_linux_device_refresh(void)
{
    g_enum.initialized = false;
    return quac_linux_device_init();
}

/**
 * @brief Get device info by index
 */
quac_result_t quac_linux_device_get_info(uint32_t index,
                                         quac_pcie_device_info_t *info)
{
    if (!info)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_linux_device_t *dev = &g_enum.devices[index];

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->index = index;

    strncpy(info->pci_slot, dev->pci_slot, sizeof(info->pci_slot) - 1);
    strncpy(info->serial, dev->serial, sizeof(info->serial) - 1);

    info->vendor_id = dev->vendor_id;
    info->device_id = dev->device_id;
    info->subsystem_vendor = dev->subsystem_vendor;
    info->subsystem_device = dev->subsystem_device;
    info->revision = dev->revision;

    info->pcie_gen = dev->pcie_gen;
    info->pcie_width = dev->pcie_width;

    info->bar0_addr = dev->bar0_addr;
    info->bar0_size = dev->bar0_size;
    info->bar2_addr = dev->bar2_addr;
    info->bar2_size = dev->bar2_size;

    info->available = dev->available;
    info->driver_bound = dev->driver_bound;
    strncpy(info->driver_name, dev->driver_name, sizeof(info->driver_name) - 1);

    return QUAC_SUCCESS;
}

/**
 * @brief Find device by serial number
 */
quac_result_t quac_linux_device_find_by_serial(const char *serial,
                                               uint32_t *index)
{
    if (!serial || !index)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        if (strcmp(g_enum.devices[i].serial, serial) == 0)
        {
            *index = i;
            return QUAC_SUCCESS;
        }
    }

    return QUAC_ERROR_DEVICE_NOT_FOUND;
}

/**
 * @brief Open device file
 */
quac_result_t quac_linux_device_open(uint32_t index, int *fd)
{
    if (!fd)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_linux_device_t *dev = &g_enum.devices[index];

    if (!dev->available)
    {
        return QUAC_ERROR_DEVICE_NOT_READY;
    }

    *fd = open(dev->dev_path, O_RDWR);
    if (*fd < 0)
    {
        int err = errno;

        if (err == ENOENT)
        {
            return QUAC_ERROR_DEVICE_NOT_FOUND;
        }
        else if (err == EACCES || err == EPERM)
        {
            return QUAC_ERROR_AUTHORIZATION;
        }
        else if (err == EBUSY)
        {
            return QUAC_ERROR_DEVICE_BUSY;
        }

        return QUAC_ERROR_DEVICE_OPEN_FAILED;
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Close device file
 */
quac_result_t quac_linux_device_close(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
    return QUAC_SUCCESS;
}

/**
 * @brief Get device path
 */
quac_result_t quac_linux_device_get_path(uint32_t index,
                                         char *path, size_t size)
{
    if (!path || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    strncpy(path, g_enum.devices[index].dev_path, size - 1);
    path[size - 1] = '\0';

    return QUAC_SUCCESS;
}

/**
 * @brief Get sysfs path
 */
quac_result_t quac_linux_device_get_sysfs_path(uint32_t index,
                                               char *path, size_t size)
{
    if (!path || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    strncpy(path, g_enum.devices[index].sysfs_path, size - 1);
    path[size - 1] = '\0';

    return QUAC_SUCCESS;
}

/*=============================================================================
 * PCIe Configuration Space
 *=============================================================================*/

/**
 * @brief Read PCIe configuration space
 */
quac_result_t quac_linux_pcie_config_read(uint32_t index,
                                          uint32_t offset,
                                          void *data,
                                          size_t size)
{
    if (!data)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    if (offset + size > PCIE_CONFIG_SPACE_SIZE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/config", g_enum.devices[index].sysfs_path);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    if (lseek(fd, offset, SEEK_SET) != (off_t)offset)
    {
        close(fd);
        return QUAC_ERROR_DEVICE_ERROR;
    }

    ssize_t n = read(fd, data, size);
    close(fd);

    if (n != (ssize_t)size)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Write PCIe configuration space
 */
quac_result_t quac_linux_pcie_config_write(uint32_t index,
                                           uint32_t offset,
                                           const void *data,
                                           size_t size)
{
    if (!data)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    if (offset + size > PCIE_CONFIG_SPACE_SIZE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/config", g_enum.devices[index].sysfs_path);

    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    if (lseek(fd, offset, SEEK_SET) != (off_t)offset)
    {
        close(fd);
        return QUAC_ERROR_DEVICE_ERROR;
    }

    ssize_t n = write(fd, data, size);
    close(fd);

    if (n != (ssize_t)size)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Driver Binding Control
 *=============================================================================*/

/**
 * @brief Unbind device from current driver
 */
quac_result_t quac_linux_device_unbind(uint32_t index)
{
    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_linux_device_t *dev = &g_enum.devices[index];

    if (!dev->driver_bound)
    {
        return QUAC_SUCCESS; /* Already unbound */
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/driver/unbind", dev->sysfs_path);

    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    ssize_t n = write(fd, dev->pci_slot, strlen(dev->pci_slot));
    close(fd);

    if (n < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    dev->driver_bound = false;
    dev->driver_name[0] = '\0';

    return QUAC_SUCCESS;
}

/**
 * @brief Bind device to QUAC driver
 */
quac_result_t quac_linux_device_bind(uint32_t index, const char *driver)
{
    if (!driver)
    {
        driver = "quac100"; /* Default driver name */
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_linux_device_t *dev = &g_enum.devices[index];

    /* First unbind if necessary */
    if (dev->driver_bound)
    {
        quac_result_t result = quac_linux_device_unbind(index);
        if (result != QUAC_SUCCESS)
        {
            return result;
        }
    }

    /* Bind to new driver */
    char path[512];
    snprintf(path, sizeof(path), "/sys/bus/pci/drivers/%s/bind", driver);

    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return QUAC_ERROR_DRIVER_ERROR;
    }

    ssize_t n = write(fd, dev->pci_slot, strlen(dev->pci_slot));
    close(fd);

    if (n < 0)
    {
        return QUAC_ERROR_DRIVER_ERROR;
    }

    /* Update driver info */
    strncpy(dev->driver_name, driver, sizeof(dev->driver_name) - 1);
    dev->driver_bound = true;

    /* Check for device file */
    usleep(100000); /* Wait for udev */
    dev->available = path_exists(dev->dev_path);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Power Management
 *=============================================================================*/

/**
 * @brief Get device power state
 */
quac_result_t quac_linux_device_get_power_state(uint32_t index,
                                                uint32_t *state)
{
    if (!state)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/power_state",
             g_enum.devices[index].sysfs_path);

    char buffer[32];
    if (sysfs_read_string(path, buffer, sizeof(buffer)) < 0)
    {
        *state = 0; /* Assume D0 if can't read */
        return QUAC_SUCCESS;
    }

    if (strcmp(buffer, "D0") == 0)
        *state = 0;
    else if (strcmp(buffer, "D1") == 0)
        *state = 1;
    else if (strcmp(buffer, "D2") == 0)
        *state = 2;
    else if (strcmp(buffer, "D3hot") == 0)
        *state = 3;
    else if (strcmp(buffer, "D3cold") == 0)
        *state = 4;
    else
        *state = 0;

    return QUAC_SUCCESS;
}

/**
 * @brief Trigger device reset
 */
quac_result_t quac_linux_device_reset(uint32_t index)
{
    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reset",
             g_enum.devices[index].sysfs_path);

    if (!path_exists(path))
    {
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    ssize_t n = write(fd, "1", 1);
    close(fd);

    if (n != 1)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    /* Wait for device to come back */
    usleep(500000);

    /* Refresh device info */
    read_driver_info(&g_enum.devices[index]);
    g_enum.devices[index].available = path_exists(g_enum.devices[index].dev_path);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Debug and Diagnostics
 *=============================================================================*/

/**
 * @brief Print device information to file
 */
quac_result_t quac_linux_device_dump_info(uint32_t index, FILE *f)
{
    if (!f)
    {
        f = stdout;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    if (index >= g_enum.count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_linux_device_t *dev = &g_enum.devices[index];

    fprintf(f, "QUAC Device %u:\n", index);
    fprintf(f, "  PCI Slot:     %s\n", dev->pci_slot);
    fprintf(f, "  Device Path:  %s\n", dev->dev_path);
    fprintf(f, "  Sysfs Path:   %s\n", dev->sysfs_path);
    fprintf(f, "  Serial:       %s\n", dev->serial);
    fprintf(f, "  Vendor ID:    0x%04X\n", dev->vendor_id);
    fprintf(f, "  Device ID:    0x%04X\n", dev->device_id);
    fprintf(f, "  Subsystem:    0x%04X:0x%04X\n",
            dev->subsystem_vendor, dev->subsystem_device);
    fprintf(f, "  Revision:     0x%02X\n", dev->revision);
    fprintf(f, "  PCIe:         Gen%u x%u\n", dev->pcie_gen, dev->pcie_width);
    fprintf(f, "  BAR0:         0x%016lX (%lu MB)\n",
            dev->bar0_addr, dev->bar0_size / (1024 * 1024));
    fprintf(f, "  BAR2:         0x%016lX (%lu MB)\n",
            dev->bar2_addr, dev->bar2_size / (1024 * 1024));
    fprintf(f, "  Available:    %s\n", dev->available ? "Yes" : "No");
    fprintf(f, "  Driver:       %s\n",
            dev->driver_bound ? dev->driver_name : "(none)");

    return QUAC_SUCCESS;
}

/**
 * @brief Dump all devices
 */
quac_result_t quac_linux_device_dump_all(FILE *f)
{
    if (!f)
    {
        f = stdout;
    }

    if (!g_enum.initialized)
    {
        quac_linux_device_init();
    }

    fprintf(f, "QUAC Device Enumeration: %u device(s) found\n\n", g_enum.count);

    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        quac_linux_device_dump_info(i, f);
        fprintf(f, "\n");
    }

    return QUAC_SUCCESS;
}
