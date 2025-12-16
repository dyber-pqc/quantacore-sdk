/**
 * @file quac100_guid.h
 * @brief QUAC 100 Device Interface GUIDs
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_GUID_H
#define QUAC100_GUID_H

#include <initguid.h>

//
// Device Interface GUID for QUAC 100 Physical Function
// {F7D5E47A-3B2C-4D8E-9F1A-6C5B4A3D2E1F}
//
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100,
    0xf7d5e47a, 0x3b2c, 0x4d8e,
    0x9f, 0x1a,
    0x6c, 0x5b,
    0x4a, 0x3d,
    0x2e, 0x1f);

//
// Device Interface GUID for QUAC 100 Virtual Function (SR-IOV)
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
//
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100_VF,
    0xa1b2c3d4, 0xe5f6, 0x7890,
    0xab, 0xcd,
    0xef, 0x12,
    0x34, 0x56,
    0x78, 0x90);

//
// Device Setup Class GUID
// {8C2D3E4F-5A6B-7C8D-9E0F-1A2B3C4D5E6F}
//
DEFINE_GUID(GUID_DEVCLASS_QUAC100,
    0x8c2d3e4f, 0x5a6b, 0x7c8d,
    0x9e, 0x0f,
    0x1a, 0x2b,
    0x3c, 0x4d,
    0x5e, 0x6f);

#endif /* QUAC100_GUID_H */