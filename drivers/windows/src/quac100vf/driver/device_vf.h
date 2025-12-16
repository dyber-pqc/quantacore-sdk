/*
 * QUAC 100 VF Driver - Device Header
 * Copyright (c) 2024 Dyber, Inc. All rights reserved.
 */

#ifndef QUAC100VF_DEVICE_H
#define QUAC100VF_DEVICE_H

#include "driver_vf.h"

/* Device add callback */
EVT_WDF_DRIVER_DEVICE_ADD Quac100VfEvtDeviceAdd;

/* PnP callbacks */
EVT_WDF_DEVICE_PREPARE_HARDWARE Quac100VfEvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE Quac100VfEvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY Quac100VfEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT Quac100VfEvtDeviceD0Exit;

/* Queue callbacks */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Quac100VfEvtIoDeviceControl;

#endif /* QUAC100VF_DEVICE_H */
