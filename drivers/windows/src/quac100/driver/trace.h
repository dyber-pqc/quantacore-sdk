/**
 * @file trace.h
 * @brief QUAC 100 KMDF Driver - WPP Tracing Definitions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_TRACE_H
#define QUAC100_TRACE_H

//
// Define the tracing flags
//
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID( \
        Quac100TraceGuid, (f7d5e47a,3b2c,4d8e,9f1a,6c5b4a3d2e1f), \
        WPP_DEFINE_BIT(TRACE_DRIVER)    \
        WPP_DEFINE_BIT(TRACE_DEVICE)    \
        WPP_DEFINE_BIT(TRACE_QUEUE)     \
        WPP_DEFINE_BIT(TRACE_IOCTL)     \
        WPP_DEFINE_BIT(TRACE_DMA)       \
        WPP_DEFINE_BIT(TRACE_CRYPTO)    \
        WPP_DEFINE_BIT(TRACE_INTERRUPT) \
        WPP_DEFINE_BIT(TRACE_POWER)     \
        )

#define WPP_FLAG_LEVEL_LOGGER(flag, level) \
    WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level) \
    (WPP_LEVEL_ENABLED(flag) && WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

//
// WPP_DEFINE_BIT creates log levels
//
#define WPP_LEVEL_FLAGS_LOGGER(lvl, flags) \
    WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
    (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

//
// TraceEvents macro
//
// begin_wpp config
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// end_wpp
//

#endif /* QUAC100_TRACE_H */