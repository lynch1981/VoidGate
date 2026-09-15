/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _VG_LOG_H_INCLUDED_
#define _VG_LOG_H_INCLUDED_

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static inline void
vg_log(const char *fmt, ...)
{
    struct timespec ts;
    struct tm tm;
    char tbuf[32];
    va_list ap;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);
    fprintf(stderr, "%s voidgate: ", tbuf);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#endif /* _VG_LOG_H_INCLUDED_ */
