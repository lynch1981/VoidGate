/* SPDX-License-Identifier: Apache-2.0 */
#include "ipaddr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int bits_equal(const uint8_t *a, const uint8_t *b, int bits);


int
vg_parse_cidr(const char *s, struct vg_prefix *out)
{
    int    plen;
    char  *slash;
    char   tmp[128];

    if (s == NULL || out == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    snprintf(tmp, sizeof(tmp), "%s", s);
    slash = strchr(tmp, '/');

    if (slash != NULL) {
        *slash = 0;
        plen = atoi(slash + 1);

    } else {
        plen = -1;
    }

    if (strchr(tmp, ':') != NULL) {
        out->family = AF_INET6;

        if (inet_pton(AF_INET6, tmp, out->addr) != 1) {
            return -1;
        }

        out->prefixlen = (uint8_t) (plen < 0 ? 128 : plen);

        if (out->prefixlen > 128) {
            return -1;
        }

        vg_prefix_mask(out);
        return 0;
    }

    out->family = AF_INET;

    if (inet_pton(AF_INET, tmp, out->addr) != 1) {
        return -1;
    }

    out->prefixlen = (uint8_t) (plen < 0 ? 32 : plen);

    if (out->prefixlen > 32) {
        return -1;
    }

    vg_prefix_mask(out);
    return 0;
}


void
vg_prefix_mask(struct vg_prefix *p)
{
    int nbytes, i, bits;

    if (p == NULL) {
        return;
    }

    nbytes = p->family == AF_INET ? 4 : 16;
    bits = p->prefixlen;

    for (i = 0; i < nbytes; i++) {
        if (bits >= 8) {
            bits -= 8;
            continue;
        }

        if (bits > 0) {
            p->addr[i] &= (uint8_t) (0xff << (8 - bits));
            bits = 0;

        } else {
            p->addr[i] = 0;
        }
    }
}


static int
bits_equal(const uint8_t *a, const uint8_t *b, int bits)
{
    int bytes = bits / 8;
    int rem = bits % 8;

    if (bytes && memcmp(a, b, (size_t) bytes) != 0) {
        return 0;
    }

    if (rem) {
        uint8_t mask = (uint8_t) (0xff << (8 - rem));

        if ((a[bytes] & mask) != (b[bytes] & mask)) {
            return 0;
        }
    }

    return 1;
}


int
vg_prefix_contains(const struct vg_prefix *hay,
    const struct vg_prefix *needle)
{
    if (hay == NULL || needle == NULL || hay->family != needle->family) {
        return 0;
    }

    if (hay->prefixlen > needle->prefixlen) {
        return 0;
    }

    return bits_equal(hay->addr, needle->addr, hay->prefixlen);
}


int
vg_prefix_covers_or_overlaps(const struct vg_prefix *a,
    const struct vg_prefix *b)
{
    return vg_prefix_contains(a, b) || vg_prefix_contains(b, a);
}


void
vg_prefix_to_str(const struct vg_prefix *p, char *buf, size_t buflen)
{
    char ip[INET6_ADDRSTRLEN];

    if (p == NULL || buf == NULL || buflen == 0) {
        return;
    }

    inet_ntop(p->family, p->addr, ip, sizeof(ip));
    snprintf(buf, buflen, "%s/%u", ip, p->prefixlen);
}


int
vg_prefix_v4_slash24(const struct vg_prefix *host, struct vg_prefix *net)
{
    if (host == NULL || host->family != AF_INET) {
        return -1;
    }

    *net = *host;
    net->prefixlen = 24;
    vg_prefix_mask(net);
    return 0;
}


int
vg_prefix_v6_slash64(const struct vg_prefix *host, struct vg_prefix *net)
{
    if (host == NULL || host->family != AF_INET6) {
        return -1;
    }

    *net = *host;
    net->prefixlen = 64;
    vg_prefix_mask(net);
    return 0;
}


int
vg_netmask_to_prefixlen(int family, const void *mask)
{
    int i, bits = 0;

    if (family == AF_INET) {
        uint32_t m = ntohl(*(const uint32_t *) mask);

        for (i = 31; i >= 0; i--) {
            if (m & (1u << i)) {
                bits++;

            } else {
                break;
            }
        }

        return bits;
    }

    {
        const uint8_t *b = mask;

        for (i = 0; i < 16; i++) {
            uint8_t c = b[i];
            int k;

            if (c == 0xff) {
                bits += 8;
                continue;
            }

            for (k = 7; k >= 0; k--) {
                if (c & (1u << k)) {
                    bits++;

                } else {
                    return bits;
                }
            }

            return bits;
        }

        return bits;
    }
}
