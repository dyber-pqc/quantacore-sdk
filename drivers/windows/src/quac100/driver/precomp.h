/**
 * @file precomp.h
 * @brief QUAC 100 KMDF Driver - Precompiled Header
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PRECOMP_H
#define QUAC100_PRECOMP_H

//
// Windows kernel headers
//
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

//
// Project version
//
#include "../common/version.h"

//
// WPP tracing
//
#include "trace.h"

#endif /* QUAC100_PRECOMP_H */