/**
 * @file device_win.c
 * @brief QuantaCore SDK - Windows Device Discovery and Management
 *
 * Implements Windows-specific device enumeration using SetupAPI,
 * device file management via CreateFile, and PnP integration.
 *
 * Device Discovery Methods:
 * 1. SetupAPI device enumeration
 * 2. Device interface class (GUID) matching
 * 3. WMI for additional device information
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define INITGUID

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_pcie.h"

/* Link with SetupAPI */
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

/*=============================================================================
 * Constants and GUIDs
 *=============================================================================*/

/** QUAC device interface GUID */
/* {A5DCBF10-6530-11D2-901F-00C04FB951ED} - example, should be device-specific */
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100,
            0xA5DCBF10, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);

/** Dyber PCI Vendor ID */
#define QUAC_PCI_VENDOR_ID 0x1FC0

/** QUAC 100 PCI Device ID */
#define QUAC_PCI_DEVICE_ID 0x0100

/** Maximum devices to enumerate */
#define QUAC_MAX_DEVICES 16

/** Device path prefix */
#define QUAC_DEV_PREFIX L"\\\\.\\QUAC"

/** Device symbolic link format */
#define QUAC_DEV_FORMAT L"\\\\.\\QUAC%d"

/** Registry key for device configuration */
#define QUAC_REG_KEY L"SOFTWARE\\Dyber\\QUAC100"

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Windows device information
 */
typedef struct quac_win_device_s
{
    /* Identification */
    uint32_t index;              /**< Device index */
    WCHAR device_path[MAX_PATH]; /**< Device path */
    WCHAR instance_id[MAX_PATH]; /**< PnP instance ID */
    WCHAR friendly_name[256];    /**< Friendly name */
    WCHAR location[256];         /**< Location information */

    /* PCI IDs */
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor;
    uint16_t subsystem_device;
    uint8_t revision;

    /* Bus location */
    uint32_t bus_number;
    uint32_t device_number;
    uint32_t function_number;

    /* State */
    BOOL available;     /**< Device is available */
    BOOL driver_loaded; /**< Driver is loaded */
    DWORD config_flags; /**< Configuration flags */
    DWORD capabilities; /**< Device capabilities */

    /* Serial number */
    char serial[32];

    /* Device handle (when opened) */
    HANDLE handle;

} quac_win_device_t;

/**
 * @brief Device enumeration state
 */
typedef struct quac_win_enum_state_s
{
    quac_win_device_t devices[QUAC_MAX_DEVICES];
    uint32_t count;
    BOOL initialized;
    CRITICAL_SECTION lock;
} quac_win_enum_state_t;

/** Global enumeration state */
static quac_win_enum_state_t g_enum = {0};
static BOOL g_enum_lock_initialized = FALSE;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Initialize enumeration lock
 */
static void init_enum_lock(void)
{
    if (!g_enum_lock_initialized)
    {
        InitializeCriticalSection(&g_enum.lock);
        g_enum_lock_initialized = TRUE;
    }
}

/**
 * @brief Convert wide string to narrow string
 */
static void wide_to_narrow(const WCHAR *wide, char *narrow, size_t size)
{
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, narrow, (int)size, NULL, NULL);
}

/**
 * @brief Convert narrow string to wide string
 */
static void narrow_to_wide(const char *narrow, WCHAR *wide, size_t size)
{
    MultiByteToWideChar(CP_UTF8, 0, narrow, -1, wide, (int)size);
}

/**
 * @brief Parse PCI IDs from hardware ID string
 * Format: PCI\VEN_xxxx&DEV_xxxx&SUBSYS_xxxxxxxx&REV_xx
 */
static BOOL parse_hardware_id(const WCHAR *hwid, quac_win_device_t *dev)
{
    WCHAR *ven = wcsstr(hwid, L"VEN_");
    WCHAR *device = wcsstr(hwid, L"DEV_");
    WCHAR *subsys = wcsstr(hwid, L"SUBSYS_");
    WCHAR *rev = wcsstr(hwid, L"REV_");

    if (ven)
    {
        dev->vendor_id = (uint16_t)wcstoul(ven + 4, NULL, 16);
    }
    if (device)
    {
        dev->device_id = (uint16_t)wcstoul(device + 4, NULL, 16);
    }
    if (subsys)
    {
        uint32_t ss = (uint32_t)wcstoul(subsys + 7, NULL, 16);
        dev->subsystem_device = (uint16_t)(ss >> 16);
        dev->subsystem_vendor = (uint16_t)(ss & 0xFFFF);
    }
    if (rev)
    {
        dev->revision = (uint8_t)wcstoul(rev + 4, NULL, 16);
    }

    return (dev->vendor_id == QUAC_PCI_VENDOR_ID &&
            dev->device_id == QUAC_PCI_DEVICE_ID);
}

/**
 * @brief Get device registry property (string)
 */
static BOOL get_device_property_string(HDEVINFO devinfo,
                                       PSP_DEVINFO_DATA devdata,
                                       DWORD property,
                                       WCHAR *buffer,
                                       DWORD size)
{
    DWORD type = 0;
    DWORD required = 0;

    if (SetupDiGetDeviceRegistryPropertyW(devinfo, devdata, property,
                                          &type, (PBYTE)buffer, size, &required))
    {
        return TRUE;
    }

    buffer[0] = L'\0';
    return FALSE;
}

/**
 * @brief Get device registry property (DWORD)
 */
static BOOL get_device_property_dword(HDEVINFO devinfo,
                                      PSP_DEVINFO_DATA devdata,
                                      DWORD property,
                                      DWORD *value)
{
    DWORD type = 0;
    DWORD required = 0;

    return SetupDiGetDeviceRegistryPropertyW(devinfo, devdata, property,
                                             &type, (PBYTE)value, sizeof(DWORD),
                                             &required);
}

/**
 * @brief Get device interface detail
 */
static BOOL get_device_interface_path(HDEVINFO devinfo,
                                      PSP_DEVICE_INTERFACE_DATA ifdata,
                                      WCHAR *path,
                                      DWORD size)
{
    DWORD required = 0;

    /* Get required size */
    SetupDiGetDeviceInterfaceDetailW(devinfo, ifdata, NULL, 0, &required, NULL);

    if (required == 0 || required > 65536)
    {
        return FALSE;
    }

    /* Allocate buffer */
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail =
        (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(required);
    if (!detail)
    {
        return FALSE;
    }

    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    BOOL result = SetupDiGetDeviceInterfaceDetailW(devinfo, ifdata, detail,
                                                   required, NULL, NULL);
    if (result)
    {
        wcsncpy_s(path, size, detail->DevicePath, _TRUNCATE);
    }

    free(detail);
    return result;
}

/**
 * @brief Parse location information for bus/device/function
 */
static void parse_location_info(const WCHAR *location, quac_win_device_t *dev)
{
    /* Format: "PCI bus X, device Y, function Z" */
    const WCHAR *bus = wcsstr(location, L"bus ");
    const WCHAR *device = wcsstr(location, L"device ");
    const WCHAR *func = wcsstr(location, L"function ");

    if (bus)
    {
        dev->bus_number = (uint32_t)wcstoul(bus + 4, NULL, 10);
    }
    if (device)
    {
        dev->device_number = (uint32_t)wcstoul(device + 7, NULL, 10);
    }
    if (func)
    {
        dev->function_number = (uint32_t)wcstoul(func + 9, NULL, 10);
    }
}

/*=============================================================================
 * Device Enumeration
 *=============================================================================*/

/**
 * @brief Enumerate devices using SetupAPI
 */
static int enumerate_setupapi(void)
{
    HDEVINFO devinfo;
    SP_DEVINFO_DATA devdata;
    SP_DEVICE_INTERFACE_DATA ifdata;
    DWORD index = 0;
    uint32_t count = 0;

    /* Get device information set for our interface class */
    devinfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_QUAC100,
                                   NULL, NULL,
                                   DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    if (devinfo == INVALID_HANDLE_VALUE)
    {
        /* Try enumerating all PCI devices */
        devinfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_SYSTEM,
                                       NULL, NULL,
                                       DIGCF_PRESENT);

        if (devinfo == INVALID_HANDLE_VALUE)
        {
            return -1;
        }
    }

    /* Enumerate devices */
    devdata.cbSize = sizeof(SP_DEVINFO_DATA);

    while (SetupDiEnumDeviceInfo(devinfo, index++, &devdata))
    {
        if (count >= QUAC_MAX_DEVICES)
        {
            break;
        }

        quac_win_device_t *dev = &g_enum.devices[count];
        memset(dev, 0, sizeof(*dev));
        dev->index = count;
        dev->handle = INVALID_HANDLE_VALUE;

        /* Get hardware ID */
        WCHAR hwid[512] = {0};
        if (!get_device_property_string(devinfo, &devdata, SPDRP_HARDWAREID,
                                        hwid, sizeof(hwid)))
        {
            continue;
        }

        /* Check if it's our device */
        if (!parse_hardware_id(hwid, dev))
        {
            continue;
        }

        /* Found a QUAC device! */

        /* Get instance ID */
        CM_Get_Device_IDW(devdata.DevInst, dev->instance_id,
                          ARRAYSIZE(dev->instance_id), 0);

        /* Get friendly name */
        get_device_property_string(devinfo, &devdata, SPDRP_FRIENDLYNAME,
                                   dev->friendly_name, sizeof(dev->friendly_name));

        if (dev->friendly_name[0] == L'\0')
        {
            get_device_property_string(devinfo, &devdata, SPDRP_DEVICEDESC,
                                       dev->friendly_name, sizeof(dev->friendly_name));
        }

        /* Get location information */
        get_device_property_string(devinfo, &devdata, SPDRP_LOCATION_INFORMATION,
                                   dev->location, sizeof(dev->location));
        parse_location_info(dev->location, dev);

        /* Get configuration flags */
        get_device_property_dword(devinfo, &devdata, SPDRP_CONFIGFLAGS,
                                  &dev->config_flags);

        /* Get capabilities */
        get_device_property_dword(devinfo, &devdata, SPDRP_CAPABILITIES,
                                  &dev->capabilities);

        /* Build device path */
        swprintf_s(dev->device_path, ARRAYSIZE(dev->device_path),
                   QUAC_DEV_FORMAT, count);

        /* Try to enumerate device interfaces */
        ifdata.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
        if (SetupDiEnumDeviceInterfaces(devinfo, &devdata,
                                        &GUID_DEVINTERFACE_QUAC100,
                                        0, &ifdata))
        {
            WCHAR path[MAX_PATH];
            if (get_device_interface_path(devinfo, &ifdata, path, ARRAYSIZE(path)))
            {
                wcscpy_s(dev->device_path, ARRAYSIZE(dev->device_path), path);
            }
        }

        /* Check if device is available */
        HANDLE test = CreateFileW(dev->device_path,
                                  0, /* No access needed for test */
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  NULL);

        if (test != INVALID_HANDLE_VALUE)
        {
            dev->available = TRUE;
            dev->driver_loaded = TRUE;
            CloseHandle(test);
        }
        else
        {
            dev->available = FALSE;
            dev->driver_loaded = (GetLastError() != ERROR_FILE_NOT_FOUND);
        }

        /* Generate serial from instance ID if not available */
        if (dev->serial[0] == '\0')
        {
            snprintf(dev->serial, sizeof(dev->serial), "QUAC-%02X%02X%02X",
                     dev->bus_number, dev->device_number, dev->function_number);
        }

        count++;
    }

    SetupDiDestroyDeviceInfoList(devinfo);

    return (int)count;
}

/**
 * @brief Enumerate devices via direct device file access
 */
static int enumerate_direct(void)
{
    uint32_t count = 0;

    for (int i = 0; i < QUAC_MAX_DEVICES; i++)
    {
        WCHAR path[MAX_PATH];
        swprintf_s(path, ARRAYSIZE(path), QUAC_DEV_FORMAT, i);

        HANDLE h = CreateFileW(path,
                               0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);

        if (h != INVALID_HANDLE_VALUE)
        {
            /* Check if we already found this device */
            BOOL found = FALSE;
            for (uint32_t j = 0; j < count; j++)
            {
                if (wcscmp(g_enum.devices[j].device_path, path) == 0)
                {
                    found = TRUE;
                    break;
                }
            }

            if (!found && count < QUAC_MAX_DEVICES)
            {
                quac_win_device_t *dev = &g_enum.devices[count];
                memset(dev, 0, sizeof(*dev));
                dev->index = count;
                dev->handle = INVALID_HANDLE_VALUE;
                wcscpy_s(dev->device_path, ARRAYSIZE(dev->device_path), path);
                dev->available = TRUE;
                dev->driver_loaded = TRUE;
                snprintf(dev->serial, sizeof(dev->serial), "QUAC-DEV%d", i);
                count++;
            }

            CloseHandle(h);
        }
    }

    return (int)count;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

/**
 * @brief Initialize Windows device subsystem
 */
quac_result_t quac_win_device_init(void)
{
    init_enum_lock();

    EnterCriticalSection(&g_enum.lock);

    if (g_enum.initialized)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_SUCCESS;
    }

    memset(&g_enum, 0, sizeof(g_enum));
    InitializeCriticalSection(&g_enum.lock);

    /* Try SetupAPI enumeration first */
    int count = enumerate_setupapi();

    /* Fall back to direct enumeration */
    if (count <= 0)
    {
        count = enumerate_direct();
    }

    g_enum.count = (count > 0) ? (uint32_t)count : 0;
    g_enum.initialized = TRUE;

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown Windows device subsystem
 */
void quac_win_device_shutdown(void)
{
    if (!g_enum_lock_initialized)
    {
        return;
    }

    EnterCriticalSection(&g_enum.lock);

    /* Close any open handles */
    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        if (g_enum.devices[i].handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_enum.devices[i].handle);
            g_enum.devices[i].handle = INVALID_HANDLE_VALUE;
        }
    }

    memset(g_enum.devices, 0, sizeof(g_enum.devices));
    g_enum.count = 0;
    g_enum.initialized = FALSE;

    LeaveCriticalSection(&g_enum.lock);
}

/**
 * @brief Get number of devices
 */
quac_result_t quac_win_device_count(uint32_t *count)
{
    if (!count)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);
    *count = g_enum.count;
    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Refresh device enumeration
 */
quac_result_t quac_win_device_refresh(void)
{
    EnterCriticalSection(&g_enum.lock);
    g_enum.initialized = FALSE;
    LeaveCriticalSection(&g_enum.lock);

    return quac_win_device_init();
}

/**
 * @brief Get device info by index
 */
quac_result_t quac_win_device_get_info(uint32_t index,
                                       quac_pcie_device_info_t *info)
{
    if (!info)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_win_device_t *dev = &g_enum.devices[index];

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->index = index;

    /* Convert wide strings */
    char pci_slot[64];
    snprintf(pci_slot, sizeof(pci_slot), "%04X:%02X:%02X.%X",
             0, dev->bus_number, dev->device_number, dev->function_number);
    strncpy_s(info->pci_slot, sizeof(info->pci_slot), pci_slot, _TRUNCATE);
    strncpy_s(info->serial, sizeof(info->serial), dev->serial, _TRUNCATE);

    info->vendor_id = dev->vendor_id;
    info->device_id = dev->device_id;
    info->subsystem_vendor = dev->subsystem_vendor;
    info->subsystem_device = dev->subsystem_device;
    info->revision = dev->revision;

    info->available = dev->available ? true : false;
    info->driver_bound = dev->driver_loaded ? true : false;

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Find device by serial number
 */
quac_result_t quac_win_device_find_by_serial(const char *serial,
                                             uint32_t *index)
{
    if (!serial || !index)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        if (strcmp(g_enum.devices[i].serial, serial) == 0)
        {
            *index = i;
            LeaveCriticalSection(&g_enum.lock);
            return QUAC_SUCCESS;
        }
    }

    LeaveCriticalSection(&g_enum.lock);
    return QUAC_ERROR_DEVICE_NOT_FOUND;
}

/**
 * @brief Open device
 */
quac_result_t quac_win_device_open(uint32_t index, HANDLE *handle)
{
    if (!handle)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    *handle = INVALID_HANDLE_VALUE;

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_win_device_t *dev = &g_enum.devices[index];

    if (!dev->available)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_READY;
    }

    HANDLE h = CreateFileW(dev->device_path,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                           NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        LeaveCriticalSection(&g_enum.lock);

        switch (err)
        {
        case ERROR_FILE_NOT_FOUND:
            return QUAC_ERROR_DEVICE_NOT_FOUND;
        case ERROR_ACCESS_DENIED:
            return QUAC_ERROR_AUTHORIZATION;
        case ERROR_SHARING_VIOLATION:
            return QUAC_ERROR_DEVICE_BUSY;
        default:
            return QUAC_ERROR_DEVICE_OPEN_FAILED;
        }
    }

    dev->handle = h;
    *handle = h;

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Close device
 */
quac_result_t quac_win_device_close(HANDLE handle)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_SUCCESS;
    }

    EnterCriticalSection(&g_enum.lock);

    /* Clear handle from device record */
    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        if (g_enum.devices[i].handle == handle)
        {
            g_enum.devices[i].handle = INVALID_HANDLE_VALUE;
            break;
        }
    }

    LeaveCriticalSection(&g_enum.lock);

    CloseHandle(handle);

    return QUAC_SUCCESS;
}

/**
 * @brief Get device path
 */
quac_result_t quac_win_device_get_path(uint32_t index,
                                       WCHAR *path, size_t size)
{
    if (!path || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    wcsncpy_s(path, size, g_enum.devices[index].device_path, _TRUNCATE);

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Get device instance ID
 */
quac_result_t quac_win_device_get_instance_id(uint32_t index,
                                              WCHAR *instance_id, size_t size)
{
    if (!instance_id || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    wcsncpy_s(instance_id, size, g_enum.devices[index].instance_id, _TRUNCATE);

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Device Power Management
 *=============================================================================*/

/**
 * @brief Get device power state
 */
quac_result_t quac_win_device_get_power_state(uint32_t index,
                                              uint32_t *state)
{
    if (!state)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    /* Query device node for power state */
    DEVINST devInst;
    WCHAR instanceId[MAX_PATH];
    wcscpy_s(instanceId, ARRAYSIZE(instanceId), g_enum.devices[index].instance_id);

    LeaveCriticalSection(&g_enum.lock);

    CONFIGRET cr = CM_Locate_DevNodeW(&devInst, instanceId, CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS)
    {
        *state = 0; /* Assume D0 */
        return QUAC_SUCCESS;
    }

    /* Get power data */
    CM_POWER_DATA powerData;
    ULONG size = sizeof(powerData);

    cr = CM_Get_DevNode_Registry_PropertyW(devInst, CM_DRP_DEVICE_POWER_DATA,
                                           NULL, &powerData, &size, 0);
    if (cr == CR_SUCCESS)
    {
        *state = powerData.PD_MostRecentPowerState;
    }
    else
    {
        *state = 0; /* Assume D0 */
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Enable/disable device
 */
quac_result_t quac_win_device_set_enabled(uint32_t index, BOOL enabled)
{
    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    WCHAR instanceId[MAX_PATH];
    wcscpy_s(instanceId, ARRAYSIZE(instanceId), g_enum.devices[index].instance_id);

    LeaveCriticalSection(&g_enum.lock);

    /* This requires administrator privileges */
    DEVINST devInst;
    CONFIGRET cr = CM_Locate_DevNodeW(&devInst, instanceId, CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    if (enabled)
    {
        cr = CM_Enable_DevNode(devInst, 0);
    }
    else
    {
        cr = CM_Disable_DevNode(devInst, 0);
    }

    if (cr != CR_SUCCESS)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    /* Refresh enumeration */
    quac_win_device_refresh();

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Debug and Diagnostics
 *=============================================================================*/

/**
 * @brief Print device information
 */
quac_result_t quac_win_device_dump_info(uint32_t index, FILE *f)
{
    if (!f)
    {
        f = stdout;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    if (index >= g_enum.count)
    {
        LeaveCriticalSection(&g_enum.lock);
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    quac_win_device_t *dev = &g_enum.devices[index];

    fprintf(f, "QUAC Device %u:\n", index);
    fwprintf(f, L"  Device Path:   %s\n", dev->device_path);
    fwprintf(f, L"  Instance ID:   %s\n", dev->instance_id);
    fwprintf(f, L"  Friendly Name: %s\n", dev->friendly_name);
    fwprintf(f, L"  Location:      %s\n", dev->location);
    fprintf(f, "  Serial:        %s\n", dev->serial);
    fprintf(f, "  Vendor ID:     0x%04X\n", dev->vendor_id);
    fprintf(f, "  Device ID:     0x%04X\n", dev->device_id);
    fprintf(f, "  Subsystem:     0x%04X:0x%04X\n",
            dev->subsystem_vendor, dev->subsystem_device);
    fprintf(f, "  Revision:      0x%02X\n", dev->revision);
    fprintf(f, "  Bus Location:  %u:%u.%u\n",
            dev->bus_number, dev->device_number, dev->function_number);
    fprintf(f, "  Available:     %s\n", dev->available ? "Yes" : "No");
    fprintf(f, "  Driver:        %s\n", dev->driver_loaded ? "Loaded" : "Not loaded");
    fprintf(f, "  Config Flags:  0x%08lX\n", dev->config_flags);
    fprintf(f, "  Capabilities:  0x%08lX\n", dev->capabilities);

    LeaveCriticalSection(&g_enum.lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Dump all devices
 */
quac_result_t quac_win_device_dump_all(FILE *f)
{
    if (!f)
    {
        f = stdout;
    }

    if (!g_enum.initialized)
    {
        quac_win_device_init();
    }

    EnterCriticalSection(&g_enum.lock);

    fprintf(f, "QUAC Device Enumeration: %u device(s) found\n\n", g_enum.count);

    LeaveCriticalSection(&g_enum.lock);

    for (uint32_t i = 0; i < g_enum.count; i++)
    {
        quac_win_device_dump_info(i, f);
        fprintf(f, "\n");
    }

    return QUAC_SUCCESS;
}

#endif /* _WIN32 */