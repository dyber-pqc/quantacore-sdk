/**
 * @file registry_win.c
 * @brief QuantaCore SDK - Windows Registry Interface Implementation
 *
 * Implements Windows Registry operations for device configuration,
 * persistent settings, licensing information, and device tracking.
 *
 * Registry Hierarchy:
 * - HKLM\SOFTWARE\Dyber\QUAC100           - System-wide settings
 *   - Config                               - Global configuration
 *   - Devices\{SerialNumber}              - Per-device settings
 *   - License                              - Licensing information
 * - HKCU\SOFTWARE\Dyber\QUAC100           - User-specific settings
 *   - Preferences                          - User preferences
 *   - Cache                                - Cached data
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"

/* Link with Shlwapi */
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Base registry keys */
#define QUAC_REG_KEY_SYSTEM L"SOFTWARE\\Dyber\\QUAC100"
#define QUAC_REG_KEY_USER L"SOFTWARE\\Dyber\\QUAC100"

/** Subkey names */
#define QUAC_REG_SUBKEY_CONFIG L"Config"
#define QUAC_REG_SUBKEY_DEVICES L"Devices"
#define QUAC_REG_SUBKEY_LICENSE L"License"
#define QUAC_REG_SUBKEY_PREFS L"Preferences"
#define QUAC_REG_SUBKEY_CACHE L"Cache"
#define QUAC_REG_SUBKEY_STATS L"Statistics"

/** Value names - Global Config */
#define QUAC_REG_VAL_VERSION L"Version"
#define QUAC_REG_VAL_INSTALL_DATE L"InstallDate"
#define QUAC_REG_VAL_LOG_LEVEL L"LogLevel"
#define QUAC_REG_VAL_LOG_PATH L"LogPath"
#define QUAC_REG_VAL_SIMULATOR_MODE L"SimulatorMode"
#define QUAC_REG_VAL_AUTO_RESET L"AutoReset"
#define QUAC_REG_VAL_TIMEOUT_MS L"TimeoutMs"
#define QUAC_REG_VAL_MAX_BATCH L"MaxBatchSize"
#define QUAC_REG_VAL_THREAD_COUNT L"ThreadCount"

/** Value names - Device Config */
#define QUAC_REG_VAL_DEV_NAME L"Name"
#define QUAC_REG_VAL_DEV_SERIAL L"Serial"
#define QUAC_REG_VAL_DEV_LOCATION L"Location"
#define QUAC_REG_VAL_DEV_FIRST_SEEN L"FirstSeen"
#define QUAC_REG_VAL_DEV_LAST_SEEN L"LastSeen"
#define QUAC_REG_VAL_DEV_FW_VERSION L"FirmwareVersion"
#define QUAC_REG_VAL_DEV_HW_VERSION L"HardwareVersion"
#define QUAC_REG_VAL_DEV_OPS_TOTAL L"OperationsTotal"
#define QUAC_REG_VAL_DEV_OPS_FAILED L"OperationsFailed"
#define QUAC_REG_VAL_DEV_ENABLED L"Enabled"
#define QUAC_REG_VAL_DEV_PRIORITY L"Priority"

/** Value names - License */
#define QUAC_REG_VAL_LIC_KEY L"LicenseKey"
#define QUAC_REG_VAL_LIC_TYPE L"LicenseType"
#define QUAC_REG_VAL_LIC_EXPIRY L"ExpiryDate"
#define QUAC_REG_VAL_LIC_FEATURES L"Features"
#define QUAC_REG_VAL_LIC_MAX_DEVS L"MaxDevices"
#define QUAC_REG_VAL_LIC_CUSTOMER L"CustomerName"
#define QUAC_REG_VAL_LIC_EMAIL L"CustomerEmail"

/** Value names - Preferences */
#define QUAC_REG_VAL_PREF_ALGORITHM L"DefaultAlgorithm"
#define QUAC_REG_VAL_PREF_KEM_ALG L"DefaultKEMAlgorithm"
#define QUAC_REG_VAL_PREF_SIGN_ALG L"DefaultSignAlgorithm"
#define QUAC_REG_VAL_PREF_ENTROPY L"EntropyQuality"

/** Default values */
#define QUAC_REG_DEF_LOG_LEVEL 2
#define QUAC_REG_DEF_TIMEOUT_MS 5000
#define QUAC_REG_DEF_MAX_BATCH 256
#define QUAC_REG_DEF_THREAD_COUNT 4

/** Maximum string length */
#define QUAC_REG_MAX_STRING 1024

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Registry configuration structure
 */
typedef struct quac_reg_config_s
{
    uint32_t version;
    uint32_t log_level;
    WCHAR log_path[MAX_PATH];
    BOOL simulator_mode;
    BOOL auto_reset;
    uint32_t timeout_ms;
    uint32_t max_batch_size;
    uint32_t thread_count;
} quac_reg_config_t;

/**
 * @brief Device registry information
 */
typedef struct quac_reg_device_s
{
    WCHAR serial[64];
    WCHAR name[128];
    WCHAR location[256];
    FILETIME first_seen;
    FILETIME last_seen;
    uint32_t firmware_version;
    uint32_t hardware_version;
    uint64_t operations_total;
    uint64_t operations_failed;
    BOOL enabled;
    uint32_t priority;
} quac_reg_device_t;

/**
 * @brief License information
 */
typedef struct quac_reg_license_s
{
    WCHAR key[256];
    uint32_t type;
    FILETIME expiry;
    uint32_t features;
    uint32_t max_devices;
    WCHAR customer_name[128];
    WCHAR customer_email[256];
} quac_reg_license_t;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Open or create registry key
 */
static HKEY open_reg_key(HKEY root, const WCHAR *subkey, BOOL create, REGSAM access)
{
    HKEY hKey = NULL;
    LONG result;

    if (create)
    {
        DWORD disposition;
        result = RegCreateKeyExW(root, subkey, 0, NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 access, NULL, &hKey, &disposition);
    }
    else
    {
        result = RegOpenKeyExW(root, subkey, 0, access, &hKey);
    }

    return (result == ERROR_SUCCESS) ? hKey : NULL;
}

/**
 * @brief Build full registry path
 */
static void build_reg_path(WCHAR *path, size_t size, const WCHAR *base, const WCHAR *subkey)
{
    if (subkey && subkey[0])
    {
        swprintf_s(path, size, L"%s\\%s", base, subkey);
    }
    else
    {
        wcscpy_s(path, size, base);
    }
}

/**
 * @brief Read DWORD value
 */
static BOOL reg_read_dword(HKEY hKey, const WCHAR *name, DWORD *value)
{
    DWORD type = 0;
    DWORD size = sizeof(DWORD);

    LONG result = RegQueryValueExW(hKey, name, NULL, &type,
                                   (LPBYTE)value, &size);

    return (result == ERROR_SUCCESS && type == REG_DWORD);
}

/**
 * @brief Read QWORD value
 */
static BOOL reg_read_qword(HKEY hKey, const WCHAR *name, uint64_t *value)
{
    DWORD type = 0;
    DWORD size = sizeof(uint64_t);

    LONG result = RegQueryValueExW(hKey, name, NULL, &type,
                                   (LPBYTE)value, &size);

    return (result == ERROR_SUCCESS && type == REG_QWORD);
}

/**
 * @brief Read string value
 */
static BOOL reg_read_string(HKEY hKey, const WCHAR *name, WCHAR *buffer, DWORD size)
{
    DWORD type = 0;
    DWORD bytes = size * sizeof(WCHAR);

    LONG result = RegQueryValueExW(hKey, name, NULL, &type,
                                   (LPBYTE)buffer, &bytes);

    if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
    {
        buffer[size - 1] = L'\0';
        return TRUE;
    }

    buffer[0] = L'\0';
    return FALSE;
}

/**
 * @brief Read binary value
 */
static BOOL reg_read_binary(HKEY hKey, const WCHAR *name, void *buffer, DWORD size)
{
    DWORD type = 0;
    DWORD bytes = size;

    LONG result = RegQueryValueExW(hKey, name, NULL, &type,
                                   (LPBYTE)buffer, &bytes);

    return (result == ERROR_SUCCESS && type == REG_BINARY);
}

/**
 * @brief Write DWORD value
 */
static BOOL reg_write_dword(HKEY hKey, const WCHAR *name, DWORD value)
{
    LONG result = RegSetValueExW(hKey, name, 0, REG_DWORD,
                                 (LPBYTE)&value, sizeof(DWORD));
    return (result == ERROR_SUCCESS);
}

/**
 * @brief Write QWORD value
 */
static BOOL reg_write_qword(HKEY hKey, const WCHAR *name, uint64_t value)
{
    LONG result = RegSetValueExW(hKey, name, 0, REG_QWORD,
                                 (LPBYTE)&value, sizeof(uint64_t));
    return (result == ERROR_SUCCESS);
}

/**
 * @brief Write string value
 */
static BOOL reg_write_string(HKEY hKey, const WCHAR *name, const WCHAR *value)
{
    DWORD size = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, name, 0, REG_SZ,
                                 (LPBYTE)value, size);
    return (result == ERROR_SUCCESS);
}

/**
 * @brief Write binary value
 */
static BOOL reg_write_binary(HKEY hKey, const WCHAR *name, const void *data, DWORD size)
{
    LONG result = RegSetValueExW(hKey, name, 0, REG_BINARY,
                                 (LPBYTE)data, size);
    return (result == ERROR_SUCCESS);
}

/**
 * @brief Delete value
 */
static BOOL reg_delete_value(HKEY hKey, const WCHAR *name)
{
    LONG result = RegDeleteValueW(hKey, name);
    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
}

/**
 * @brief Map Windows error to quac_result_t
 */
static quac_result_t win_error_to_result(LONG err)
{
    switch (err)
    {
    case ERROR_SUCCESS:
        return QUAC_SUCCESS;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return QUAC_ERROR_NOT_FOUND;
    case ERROR_ACCESS_DENIED:
        return QUAC_ERROR_AUTHORIZATION;
    case ERROR_OUTOFMEMORY:
        return QUAC_ERROR_OUT_OF_MEMORY;
    default:
        return QUAC_ERROR_UNKNOWN;
    }
}

/*=============================================================================
 * Public API - Initialization
 *=============================================================================*/

/**
 * @brief Initialize registry subsystem
 */
quac_result_t quac_win_registry_init(void)
{
    /* Ensure base keys exist */
    HKEY hKey;

    /* System key (HKLM) */
    hKey = open_reg_key(HKEY_LOCAL_MACHINE, QUAC_REG_KEY_SYSTEM, TRUE,
                        KEY_READ | KEY_WRITE);
    if (hKey)
    {
        /* Create subkeys */
        HKEY hSubKey;

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_CONFIG, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_DEVICES, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_LICENSE, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_STATS, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        RegCloseKey(hKey);
    }

    /* User key (HKCU) - always succeeds for current user */
    hKey = open_reg_key(HKEY_CURRENT_USER, QUAC_REG_KEY_USER, TRUE,
                        KEY_READ | KEY_WRITE);
    if (hKey)
    {
        HKEY hSubKey;

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_PREFS, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        hSubKey = open_reg_key(hKey, QUAC_REG_SUBKEY_CACHE, TRUE, KEY_WRITE);
        if (hSubKey)
            RegCloseKey(hSubKey);

        RegCloseKey(hKey);
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown registry subsystem
 */
void quac_win_registry_shutdown(void)
{
    /* Nothing to clean up */
}

/*=============================================================================
 * Public API - Global Configuration
 *=============================================================================*/

/**
 * @brief Read global configuration from registry
 */
quac_result_t quac_win_registry_get_config(quac_reg_config_t *config)
{
    if (!config)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    memset(config, 0, sizeof(*config));

    /* Set defaults */
    config->log_level = QUAC_REG_DEF_LOG_LEVEL;
    config->timeout_ms = QUAC_REG_DEF_TIMEOUT_MS;
    config->max_batch_size = QUAC_REG_DEF_MAX_BATCH;
    config->thread_count = QUAC_REG_DEF_THREAD_COUNT;

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        /* Try user key */
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (hKey)
    {
        DWORD dword;

        if (reg_read_dword(hKey, QUAC_REG_VAL_VERSION, &dword))
        {
            config->version = dword;
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_LOG_LEVEL, &dword))
        {
            config->log_level = dword;
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_SIMULATOR_MODE, &dword))
        {
            config->simulator_mode = (dword != 0);
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_AUTO_RESET, &dword))
        {
            config->auto_reset = (dword != 0);
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_TIMEOUT_MS, &dword))
        {
            config->timeout_ms = dword;
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_MAX_BATCH, &dword))
        {
            config->max_batch_size = dword;
        }
        if (reg_read_dword(hKey, QUAC_REG_VAL_THREAD_COUNT, &dword))
        {
            config->thread_count = dword;
        }

        reg_read_string(hKey, QUAC_REG_VAL_LOG_PATH, config->log_path,
                        ARRAYSIZE(config->log_path));

        RegCloseKey(hKey);
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Write global configuration to registry
 */
quac_result_t quac_win_registry_set_config(const quac_reg_config_t *config)
{
    if (!config)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE,
                             KEY_READ | KEY_WRITE);
    if (!hKey)
    {
        /* Fall back to user key */
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_READ | KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    reg_write_dword(hKey, QUAC_REG_VAL_VERSION, config->version);
    reg_write_dword(hKey, QUAC_REG_VAL_LOG_LEVEL, config->log_level);
    reg_write_dword(hKey, QUAC_REG_VAL_SIMULATOR_MODE, config->simulator_mode ? 1 : 0);
    reg_write_dword(hKey, QUAC_REG_VAL_AUTO_RESET, config->auto_reset ? 1 : 0);
    reg_write_dword(hKey, QUAC_REG_VAL_TIMEOUT_MS, config->timeout_ms);
    reg_write_dword(hKey, QUAC_REG_VAL_MAX_BATCH, config->max_batch_size);
    reg_write_dword(hKey, QUAC_REG_VAL_THREAD_COUNT, config->thread_count);

    if (config->log_path[0])
    {
        reg_write_string(hKey, QUAC_REG_VAL_LOG_PATH, config->log_path);
    }

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Get individual configuration value (DWORD)
 */
quac_result_t quac_win_registry_get_dword(const WCHAR *name, DWORD *value)
{
    if (!name || !value)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    BOOL success = reg_read_dword(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Set individual configuration value (DWORD)
 */
quac_result_t quac_win_registry_set_dword(const WCHAR *name, DWORD value)
{
    if (!name)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    BOOL success = reg_write_dword(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Get string configuration value
 */
quac_result_t quac_win_registry_get_string(const WCHAR *name, WCHAR *buffer, size_t size)
{
    if (!name || !buffer || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    BOOL success = reg_read_string(hKey, name, buffer, (DWORD)size);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Set string configuration value
 */
quac_result_t quac_win_registry_set_string(const WCHAR *name, const WCHAR *value)
{
    if (!name || !value)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_CONFIG);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        build_reg_path(path, ARRAYSIZE(path), QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CONFIG);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    BOOL success = reg_write_string(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
}

/*=============================================================================
 * Public API - Device Registry
 *=============================================================================*/

/**
 * @brief Register a device in the registry
 */
quac_result_t quac_win_registry_register_device(const char *serial,
                                                const quac_device_info_t *info)
{
    if (!serial || !info)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR wSerial[64];
    MultiByteToWideChar(CP_UTF8, 0, serial, -1, wSerial, ARRAYSIZE(wSerial));

    /* Build device key path */
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_DEVICES, wSerial);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        /* Try user key */
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_DEVICES, wSerial);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    /* Write device information */
    reg_write_string(hKey, QUAC_REG_VAL_DEV_SERIAL, wSerial);

    WCHAR wName[128];
    MultiByteToWideChar(CP_UTF8, 0, info->name, -1, wName, ARRAYSIZE(wName));
    reg_write_string(hKey, QUAC_REG_VAL_DEV_NAME, wName);

    reg_write_dword(hKey, QUAC_REG_VAL_DEV_FW_VERSION, info->firmware_version);
    reg_write_dword(hKey, QUAC_REG_VAL_DEV_HW_VERSION, info->hardware_version);
    reg_write_dword(hKey, QUAC_REG_VAL_DEV_ENABLED, 1);
    reg_write_dword(hKey, QUAC_REG_VAL_DEV_PRIORITY, 0);

    /* Update timestamps */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    /* Check if first_seen exists */
    FILETIME existing;
    if (!reg_read_binary(hKey, QUAC_REG_VAL_DEV_FIRST_SEEN, &existing, sizeof(existing)))
    {
        reg_write_binary(hKey, QUAC_REG_VAL_DEV_FIRST_SEEN, &ft, sizeof(ft));
    }

    reg_write_binary(hKey, QUAC_REG_VAL_DEV_LAST_SEEN, &ft, sizeof(ft));

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Unregister a device from the registry
 */
quac_result_t quac_win_registry_unregister_device(const char *serial)
{
    if (!serial)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR wSerial[64];
    MultiByteToWideChar(CP_UTF8, 0, serial, -1, wSerial, ARRAYSIZE(wSerial));

    /* Build device key path */
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_DEVICES, wSerial);

    LONG result = SHDeleteKeyW(HKEY_LOCAL_MACHINE, path);

    if (result != ERROR_SUCCESS)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_DEVICES, wSerial);
        result = SHDeleteKeyW(HKEY_CURRENT_USER, path);
    }

    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND)
               ? QUAC_SUCCESS
               : QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Get device information from registry
 */
quac_result_t quac_win_registry_get_device(const char *serial,
                                           quac_reg_device_t *device)
{
    if (!serial || !device)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    memset(device, 0, sizeof(*device));

    WCHAR wSerial[64];
    MultiByteToWideChar(CP_UTF8, 0, serial, -1, wSerial, ARRAYSIZE(wSerial));

    /* Build device key path */
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_DEVICES, wSerial);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_DEVICES, wSerial);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    wcscpy_s(device->serial, ARRAYSIZE(device->serial), wSerial);

    reg_read_string(hKey, QUAC_REG_VAL_DEV_NAME, device->name, ARRAYSIZE(device->name));
    reg_read_string(hKey, QUAC_REG_VAL_DEV_LOCATION, device->location, ARRAYSIZE(device->location));

    DWORD dword;
    if (reg_read_dword(hKey, QUAC_REG_VAL_DEV_FW_VERSION, &dword))
    {
        device->firmware_version = dword;
    }
    if (reg_read_dword(hKey, QUAC_REG_VAL_DEV_HW_VERSION, &dword))
    {
        device->hardware_version = dword;
    }
    if (reg_read_dword(hKey, QUAC_REG_VAL_DEV_ENABLED, &dword))
    {
        device->enabled = (dword != 0);
    }
    if (reg_read_dword(hKey, QUAC_REG_VAL_DEV_PRIORITY, &dword))
    {
        device->priority = dword;
    }

    reg_read_qword(hKey, QUAC_REG_VAL_DEV_OPS_TOTAL, &device->operations_total);
    reg_read_qword(hKey, QUAC_REG_VAL_DEV_OPS_FAILED, &device->operations_failed);

    reg_read_binary(hKey, QUAC_REG_VAL_DEV_FIRST_SEEN, &device->first_seen, sizeof(FILETIME));
    reg_read_binary(hKey, QUAC_REG_VAL_DEV_LAST_SEEN, &device->last_seen, sizeof(FILETIME));

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Update device operation statistics
 */
quac_result_t quac_win_registry_update_device_stats(const char *serial,
                                                    uint64_t ops_completed,
                                                    uint64_t ops_failed)
{
    if (!serial)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR wSerial[64];
    MultiByteToWideChar(CP_UTF8, 0, serial, -1, wSerial, ARRAYSIZE(wSerial));

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_DEVICES, wSerial);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_WRITE);
    if (!hKey)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_DEVICES, wSerial);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    reg_write_qword(hKey, QUAC_REG_VAL_DEV_OPS_TOTAL, ops_completed);
    reg_write_qword(hKey, QUAC_REG_VAL_DEV_OPS_FAILED, ops_failed);

    /* Update last seen */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    reg_write_binary(hKey, QUAC_REG_VAL_DEV_LAST_SEEN, &ft, sizeof(ft));

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Enumerate registered devices
 */
quac_result_t quac_win_registry_enumerate_devices(WCHAR **serials,
                                                  uint32_t *count,
                                                  uint32_t max_devices)
{
    if (!count)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    *count = 0;

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_DEVICES);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_DEVICES);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (!hKey)
    {
        return QUAC_SUCCESS; /* No devices registered */
    }

    DWORD index = 0;
    WCHAR subkeyName[64];
    DWORD nameSize;

    while (*count < max_devices)
    {
        nameSize = ARRAYSIZE(subkeyName);

        LONG result = RegEnumKeyExW(hKey, index++, subkeyName, &nameSize,
                                    NULL, NULL, NULL, NULL);

        if (result == ERROR_NO_MORE_ITEMS)
        {
            break;
        }

        if (result == ERROR_SUCCESS && serials)
        {
            wcscpy_s(serials[*count], 64, subkeyName);
        }

        (*count)++;
    }

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - License Management
 *=============================================================================*/

/**
 * @brief Get license information
 */
quac_result_t quac_win_registry_get_license(quac_reg_license_t *license)
{
    if (!license)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    memset(license, 0, sizeof(*license));

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_LICENSE);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    reg_read_string(hKey, QUAC_REG_VAL_LIC_KEY, license->key, ARRAYSIZE(license->key));

    DWORD dword;
    if (reg_read_dword(hKey, QUAC_REG_VAL_LIC_TYPE, &dword))
    {
        license->type = dword;
    }
    if (reg_read_dword(hKey, QUAC_REG_VAL_LIC_FEATURES, &dword))
    {
        license->features = dword;
    }
    if (reg_read_dword(hKey, QUAC_REG_VAL_LIC_MAX_DEVS, &dword))
    {
        license->max_devices = dword;
    }

    reg_read_binary(hKey, QUAC_REG_VAL_LIC_EXPIRY, &license->expiry, sizeof(FILETIME));
    reg_read_string(hKey, QUAC_REG_VAL_LIC_CUSTOMER, license->customer_name,
                    ARRAYSIZE(license->customer_name));
    reg_read_string(hKey, QUAC_REG_VAL_LIC_EMAIL, license->customer_email,
                    ARRAYSIZE(license->customer_email));

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Set license information
 */
quac_result_t quac_win_registry_set_license(const quac_reg_license_t *license)
{
    if (!license)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_LICENSE);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    reg_write_string(hKey, QUAC_REG_VAL_LIC_KEY, license->key);
    reg_write_dword(hKey, QUAC_REG_VAL_LIC_TYPE, license->type);
    reg_write_dword(hKey, QUAC_REG_VAL_LIC_FEATURES, license->features);
    reg_write_dword(hKey, QUAC_REG_VAL_LIC_MAX_DEVS, license->max_devices);
    reg_write_binary(hKey, QUAC_REG_VAL_LIC_EXPIRY, &license->expiry, sizeof(FILETIME));
    reg_write_string(hKey, QUAC_REG_VAL_LIC_CUSTOMER, license->customer_name);
    reg_write_string(hKey, QUAC_REG_VAL_LIC_EMAIL, license->customer_email);

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Validate license
 */
quac_result_t quac_win_registry_validate_license(BOOL *valid, uint32_t *days_remaining)
{
    if (!valid)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    *valid = FALSE;
    if (days_remaining)
        *days_remaining = 0;

    quac_reg_license_t license;
    quac_result_t result = quac_win_registry_get_license(&license);

    if (result != QUAC_SUCCESS)
    {
        return result;
    }

    /* Check if license key exists */
    if (license.key[0] == L'\0')
    {
        return QUAC_SUCCESS; /* No license */
    }

    /* Check expiry */
    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    ULARGE_INTEGER nowInt, expiryInt;
    nowInt.LowPart = now.dwLowDateTime;
    nowInt.HighPart = now.dwHighDateTime;
    expiryInt.LowPart = license.expiry.dwLowDateTime;
    expiryInt.HighPart = license.expiry.dwHighDateTime;

    if (expiryInt.QuadPart > nowInt.QuadPart)
    {
        *valid = TRUE;

        if (days_remaining)
        {
            /* Calculate days remaining */
            uint64_t diff = expiryInt.QuadPart - nowInt.QuadPart;
            /* Convert 100-nanosecond intervals to days */
            *days_remaining = (uint32_t)(diff / (10000000ULL * 60 * 60 * 24));
        }
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - User Preferences
 *=============================================================================*/

/**
 * @brief Get user preference (DWORD)
 */
quac_result_t quac_win_registry_get_user_pref_dword(const WCHAR *name, DWORD *value)
{
    if (!name || !value)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_PREFS);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    BOOL success = reg_read_dword(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Set user preference (DWORD)
 */
quac_result_t quac_win_registry_set_user_pref_dword(const WCHAR *name, DWORD value)
{
    if (!name)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_PREFS);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        return QUAC_ERROR_UNKNOWN;
    }

    BOOL success = reg_write_dword(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Get user preference (string)
 */
quac_result_t quac_win_registry_get_user_pref_string(const WCHAR *name,
                                                     WCHAR *buffer, size_t size)
{
    if (!name || !buffer || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_PREFS);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    BOOL success = reg_read_string(hKey, name, buffer, (DWORD)size);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Set user preference (string)
 */
quac_result_t quac_win_registry_set_user_pref_string(const WCHAR *name,
                                                     const WCHAR *value)
{
    if (!name || !value)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_PREFS);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        return QUAC_ERROR_UNKNOWN;
    }

    BOOL success = reg_write_string(hKey, name, value);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
}

/*=============================================================================
 * Public API - Cache Management
 *=============================================================================*/

/**
 * @brief Store cached data
 */
quac_result_t quac_win_registry_cache_put(const WCHAR *key,
                                          const void *data, size_t size)
{
    if (!key || !data || size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CACHE);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        return QUAC_ERROR_UNKNOWN;
    }

    BOOL success = reg_write_binary(hKey, key, data, (DWORD)size);
    RegCloseKey(hKey);

    return success ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Retrieve cached data
 */
quac_result_t quac_win_registry_cache_get(const WCHAR *key,
                                          void *buffer, size_t *size)
{
    if (!key || !buffer || !size || *size == 0)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CACHE);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    if (!hKey)
    {
        return QUAC_ERROR_NOT_FOUND;
    }

    DWORD type = 0;
    DWORD bytes = (DWORD)*size;

    LONG result = RegQueryValueExW(hKey, key, NULL, &type,
                                   (LPBYTE)buffer, &bytes);

    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_BINARY)
    {
        *size = bytes;
        return QUAC_SUCCESS;
    }

    return (result == ERROR_MORE_DATA) ? QUAC_ERROR_BUFFER_TOO_SMALL : QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Delete cached data
 */
quac_result_t quac_win_registry_cache_delete(const WCHAR *key)
{
    if (!key)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CACHE);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_WRITE);
    if (!hKey)
    {
        return QUAC_SUCCESS; /* Key doesn't exist */
    }

    reg_delete_value(hKey, key);
    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Clear all cached data
 */
quac_result_t quac_win_registry_cache_clear(void)
{
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_CACHE);

    /* Delete and recreate the cache key */
    SHDeleteKeyW(HKEY_CURRENT_USER, path);

    HKEY hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    if (hKey)
    {
        RegCloseKey(hKey);
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Statistics
 *=============================================================================*/

/**
 * @brief Update global statistics
 */
quac_result_t quac_win_registry_update_stats(uint64_t total_ops,
                                             uint64_t failed_ops,
                                             uint64_t bytes_processed)
{
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_STATS);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, TRUE, KEY_WRITE);
    if (!hKey)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_STATS);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, TRUE, KEY_WRITE);
    }

    if (!hKey)
    {
        return QUAC_ERROR_AUTHORIZATION;
    }

    reg_write_qword(hKey, L"TotalOperations", total_ops);
    reg_write_qword(hKey, L"FailedOperations", failed_ops);
    reg_write_qword(hKey, L"BytesProcessed", bytes_processed);

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    reg_write_binary(hKey, L"LastUpdated", &ft, sizeof(ft));

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/**
 * @brief Get global statistics
 */
quac_result_t quac_win_registry_get_stats(uint64_t *total_ops,
                                          uint64_t *failed_ops,
                                          uint64_t *bytes_processed)
{
    WCHAR path[MAX_PATH];
    swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
               QUAC_REG_KEY_SYSTEM, QUAC_REG_SUBKEY_STATS);

    HKEY hKey = open_reg_key(HKEY_LOCAL_MACHINE, path, FALSE, KEY_READ);
    if (!hKey)
    {
        swprintf_s(path, ARRAYSIZE(path), L"%s\\%s",
                   QUAC_REG_KEY_USER, QUAC_REG_SUBKEY_STATS);
        hKey = open_reg_key(HKEY_CURRENT_USER, path, FALSE, KEY_READ);
    }

    if (!hKey)
    {
        if (total_ops)
            *total_ops = 0;
        if (failed_ops)
            *failed_ops = 0;
        if (bytes_processed)
            *bytes_processed = 0;
        return QUAC_SUCCESS;
    }

    uint64_t value;

    if (total_ops)
    {
        if (reg_read_qword(hKey, L"TotalOperations", &value))
        {
            *total_ops = value;
        }
        else
        {
            *total_ops = 0;
        }
    }

    if (failed_ops)
    {
        if (reg_read_qword(hKey, L"FailedOperations", &value))
        {
            *failed_ops = value;
        }
        else
        {
            *failed_ops = 0;
        }
    }

    if (bytes_processed)
    {
        if (reg_read_qword(hKey, L"BytesProcessed", &value))
        {
            *bytes_processed = value;
        }
        else
        {
            *bytes_processed = 0;
        }
    }

    RegCloseKey(hKey);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Debug and Diagnostics
 *=============================================================================*/

/**
 * @brief Export registry settings to file
 */
quac_result_t quac_win_registry_export(const WCHAR *filename)
{
    if (!filename)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    /* Use reg.exe to export */
    WCHAR cmd[MAX_PATH * 2];
    swprintf_s(cmd, ARRAYSIZE(cmd),
               L"reg export \"%s\" \"%s\" /y",
               QUAC_REG_KEY_SYSTEM, filename);

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return QUAC_SUCCESS;
    }

    return QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Import registry settings from file
 */
quac_result_t quac_win_registry_import(const WCHAR *filename)
{
    if (!filename)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    /* Use reg.exe to import */
    WCHAR cmd[MAX_PATH * 2];
    swprintf_s(cmd, ARRAYSIZE(cmd),
               L"reg import \"%s\"", filename);

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 10000);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (exitCode == 0) ? QUAC_SUCCESS : QUAC_ERROR_UNKNOWN;
    }

    return QUAC_ERROR_UNKNOWN;
}

/**
 * @brief Dump registry contents for debugging
 */
quac_result_t quac_win_registry_dump(FILE *f)
{
    if (!f)
    {
        f = stdout;
    }

    fprintf(f, "QUAC Registry Dump\n");
    fprintf(f, "==================\n\n");

    /* Dump configuration */
    quac_reg_config_t config;
    if (quac_win_registry_get_config(&config) == QUAC_SUCCESS)
    {
        fprintf(f, "Configuration:\n");
        fprintf(f, "  Version:        0x%08X\n", config.version);
        fprintf(f, "  Log Level:      %u\n", config.log_level);
        fwprintf(f, L"  Log Path:       %s\n", config.log_path);
        fprintf(f, "  Simulator Mode: %s\n", config.simulator_mode ? "Yes" : "No");
        fprintf(f, "  Auto Reset:     %s\n", config.auto_reset ? "Yes" : "No");
        fprintf(f, "  Timeout (ms):   %u\n", config.timeout_ms);
        fprintf(f, "  Max Batch:      %u\n", config.max_batch_size);
        fprintf(f, "  Thread Count:   %u\n", config.thread_count);
        fprintf(f, "\n");
    }

    /* Dump license */
    quac_reg_license_t license;
    if (quac_win_registry_get_license(&license) == QUAC_SUCCESS && license.key[0])
    {
        fprintf(f, "License:\n");
        fwprintf(f, L"  Key:            %.16s...\n", license.key);
        fprintf(f, "  Type:           %u\n", license.type);
        fprintf(f, "  Features:       0x%08X\n", license.features);
        fprintf(f, "  Max Devices:    %u\n", license.max_devices);
        fwprintf(f, L"  Customer:       %s\n", license.customer_name);
        fprintf(f, "\n");
    }

    /* Dump statistics */
    uint64_t total_ops, failed_ops, bytes_processed;
    if (quac_win_registry_get_stats(&total_ops, &failed_ops, &bytes_processed) == QUAC_SUCCESS)
    {
        fprintf(f, "Statistics:\n");
        fprintf(f, "  Total Operations:   %llu\n", (unsigned long long)total_ops);
        fprintf(f, "  Failed Operations:  %llu\n", (unsigned long long)failed_ops);
        fprintf(f, "  Bytes Processed:    %llu\n", (unsigned long long)bytes_processed);
        fprintf(f, "\n");
    }

    /* Dump registered devices */
    uint32_t device_count = 0;
    quac_win_registry_enumerate_devices(NULL, &device_count, 16);

    if (device_count > 0)
    {
        fprintf(f, "Registered Devices: %u\n", device_count);

        WCHAR *serials[16];
        for (uint32_t i = 0; i < device_count && i < 16; i++)
        {
            serials[i] = (WCHAR *)malloc(64 * sizeof(WCHAR));
        }

        quac_win_registry_enumerate_devices(serials, &device_count, 16);

        for (uint32_t i = 0; i < device_count && i < 16; i++)
        {
            fwprintf(f, L"  Device %u: %s\n", i, serials[i]);

            /* Get device details */
            char serial[64];
            WideCharToMultiByte(CP_UTF8, 0, serials[i], -1, serial, sizeof(serial), NULL, NULL);

            quac_reg_device_t device;
            if (quac_win_registry_get_device(serial, &device) == QUAC_SUCCESS)
            {
                fwprintf(f, L"    Name:       %s\n", device.name);
                fprintf(f, "    FW Version: 0x%08X\n", device.firmware_version);
                fprintf(f, "    HW Version: 0x%08X\n", device.hardware_version);
                fprintf(f, "    Enabled:    %s\n", device.enabled ? "Yes" : "No");
                fprintf(f, "    Ops Total:  %llu\n", (unsigned long long)device.operations_total);
                fprintf(f, "    Ops Failed: %llu\n", (unsigned long long)device.operations_failed);
            }

            free(serials[i]);
        }
        fprintf(f, "\n");
    }

    return QUAC_SUCCESS;
}

#endif /* _WIN32 */