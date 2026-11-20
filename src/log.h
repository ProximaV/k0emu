#pragma once

#include <cstdio>

using LogCallback = void(*)(const char *msg);
void set_log_callback(LogCallback cb);
void log_printf(const char *fmt, ...);

#if defined(_MSC_VER)
#define K0_FUNC __FUNCTION__
#else
#define K0_FUNC __PRETTY_FUNCTION__
#endif

#define LOG(fmt, ...) \
    do { \
        log_printf("[k0emu] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define LOG_WARN(fmt, ...) \
    do { \
        log_printf("[k0emu WARN] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_ERR(fmt, ...) \
    do { \
        log_printf("[k0emu ERROR] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
