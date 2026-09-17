/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _VG_LOG_H_INCLUDED_
#define _VG_LOG_H_INCLUDED_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


static inline void
vg_log_prefix(void)
{
    struct timespec ts;
    struct tm tm;
    char tbuf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);
    fprintf(stderr, "%s voidgate: ", tbuf);
}


__attribute__((format(printf, 1, 2)))
static inline void
vg_log(const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix();
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


__attribute__((format(printf, 3, 4)))
static inline void
vg_warn_at(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix();
    fputs("warning: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " at %s:%d\n", file, line);
}


__attribute__((noreturn, format(printf, 3, 4)))
static inline void
vg_die_at(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix();
    fputs("fatal: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " at %s:%d\n", file, line);
    exit(1);
}


#define vg_warn(...) vg_warn_at(__FILE__, __LINE__, __VA_ARGS__)
#define vg_die(...)  vg_die_at(__FILE__, __LINE__, __VA_ARGS__)

#endif /* _VG_LOG_H_INCLUDED_ */
