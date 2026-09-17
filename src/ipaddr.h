/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _VG_IPADDR_H_INCLUDED_
#define _VG_IPADDR_H_INCLUDED_

#include <stdint.h>
#include <netinet/in.h>

struct vg_prefix {
    int      family; /* AF_INET or AF_INET6 */
    uint8_t  addr[16];
    uint8_t  prefixlen;
};


int vg_parse_cidr(const char *s, struct vg_prefix *out);
void vg_prefix_mask(struct vg_prefix *p);
int vg_prefix_contains(const struct vg_prefix *hay,
    const struct vg_prefix *needle);
int vg_prefix_covers_or_overlaps(const struct vg_prefix *a,
    const struct vg_prefix *b);
void vg_prefix_to_str(const struct vg_prefix *p, char *buf, size_t buflen);
int vg_prefix_v4_slash24(const struct vg_prefix *host, struct vg_prefix *net);
int vg_prefix_v6_slash64(const struct vg_prefix *host, struct vg_prefix *net);
int vg_netmask_to_prefixlen(int family, const void *mask);

#endif /* _VG_IPADDR_H_INCLUDED_ */
