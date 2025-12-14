/**
 * @file basic.c
 * @brief Basic QUAC 100 SDK Usage Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <quac100/quac100.h>

int main(void)
{
    printf("QUAC 100 SDK Basic Example\n");
    printf("==========================\n\n");

    /* Initialize the library */
    quac_status_t status = quac_init(QUAC_FLAG_DEFAULT);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Failed to initialize: %s\n", quac_error_string(status));
        return 1;
    }

    printf("Library version: %s\n", quac_version());
    printf("Build info:\n%s\n", quac_build_info());

    /* Enumerate devices */
    quac_device_info_t devices[QUAC_MAX_DEVICES];
    int device_count;

    status = quac_enumerate_devices(devices, QUAC_MAX_DEVICES, &device_count);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Failed to enumerate devices: %s\n", quac_error_string(status));
        quac_cleanup();
        return 1;
    }

    printf("Found %d device(s)\n\n", device_count);

    for (int i = 0; i < device_count; i++)
    {
        printf("Device %d:\n", i);
        printf("  Model:       %s\n", devices[i].model_name);
        printf("  Serial:      %s\n", devices[i].serial_number);
        printf("  Firmware:    %s\n", devices[i].firmware_version);
        printf("  Hardware:    %s\n", devices[i].hardware_version);
        printf("  Key Slots:   %d\n", devices[i].key_slots);
        printf("  FIPS Mode:   %s\n", devices[i].fips_mode ? "Yes" : "No");
        printf("  HW Accel:    %s\n", devices[i].hardware_available ? "Yes" : "No (Simulation)");
        printf("\n");
    }

    if (device_count == 0)
    {
        printf("No devices found. Exiting.\n");
        quac_cleanup();
        return 0;
    }

    /* Open the first device */
    quac_device_t device;
    status = quac_open_device(0, QUAC_FLAG_DEFAULT, &device);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Failed to open device: %s\n", quac_error_string(status));
        quac_cleanup();
        return 1;
    }

    printf("Device opened successfully\n\n");

    /* Get device status */
    quac_device_status_t dev_status;
    status = quac_get_device_status(device, &dev_status);
    if (status == QUAC_SUCCESS)
    {
        printf("Device Status:\n");
        printf("  Temperature:     %.1f°C\n", dev_status.temperature);
        printf("  Power:           %u mW\n", dev_status.power_mw);
        printf("  Uptime:          %lu seconds\n", (unsigned long)dev_status.uptime_seconds);
        printf("  Total Ops:       %lu\n", (unsigned long)dev_status.total_operations);
        printf("  Ops/Second:      %u\n", dev_status.ops_per_second);
        printf("  Entropy Level:   %d%%\n", dev_status.entropy_level);
        printf("  Active Sessions: %d\n", dev_status.active_sessions);
        printf("  Used Key Slots:  %d\n", dev_status.used_key_slots);
        printf("\n");
    }

    /* Run self-test */
    printf("Running self-test... ");
    fflush(stdout);
    status = quac_self_test(device);
    if (status == QUAC_SUCCESS)
    {
        printf("PASSED\n");
    }
    else
    {
        printf("FAILED: %s\n", quac_error_string(status));
    }

    /* Close device */
    quac_close_device(device);

    /* Cleanup */
    quac_cleanup();

    printf("\nBasic example completed successfully!\n");
    return 0;
}