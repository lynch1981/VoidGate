/* SPDX-License-Identifier: Apache-2.0 */
#include "policy.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


struct vg_snap_ent {
    int                  family;
    uint8_t              addr[16];
    uint64_t             in_pkts;
    uint64_t             in_bytes;
    uint32_t             gen;
    struct vg_snap_ent  *next;
};


static unsigned snap_hash(int family, const uint8_t *addr);
static void snap_reset_pool(struct vg_ctrl *c);
static void snap_clear(struct vg_ctrl *c);
static void snap_prune(struct vg_ctrl *c);
static struct vg_snap_ent *snap_get(struct vg_ctrl *c, int family,
    const uint8_t *addr, int *created);
static int drops_find(struct vg_ctrl *c, const struct vg_cidr *p);
static int maybe_aggregate(struct vg_ctrl *c, const struct vg_cidr *host);
static void policy_one_remote(struct vg_ctrl *c, int family,
    const uint8_t *addr, const struct host_counters *cur, double dt);
static void remote_cb(int family, const uint8_t *addr,
    const struct host_counters *sum, void *arg);
static void walk_remotes(struct vg_ctrl *c, double dt);
static void expire_drops(struct vg_ctrl *c);
static double tick_dt(struct vg_ctrl *c);


static unsigned
snap_hash(int family, const uint8_t *addr)
{
    unsigned h = (unsigned) family * 16777619u;
    int n = family == AF_INET ? 4 : 16;
    int i;

    for (i = 0; i < n; i++) {
        h = (h ^ addr[i]) * 16777619u;
    }

    return h % VG_SNAP_BUCKETS;
}


static void
snap_reset_pool(struct vg_ctrl *c)
{
    unsigned i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        c->snaps[i] = NULL;
    }

    c->snap_free = NULL;

    if (c->snap_pool == NULL || !c->snap_cap) {
        return;
    }

    for (i = 0; i < c->snap_cap; i++) {
        c->snap_pool[i].gen = 0;
        c->snap_pool[i].next = i + 1 < c->snap_cap
                               ? &c->snap_pool[i + 1] : NULL;
    }

    c->snap_free = c->snap_pool;
}


static void
snap_clear(struct vg_ctrl *c)
{
    snap_reset_pool(c);
}


/* Reclaim remotes missing from a complete map scan. Truncated walks must not
 * call this — rate snapshots for unvisited keys have to survive churn.
 */
static void
snap_prune(struct vg_ctrl *c)
{
    int i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        struct vg_snap_ent **link = &c->snaps[i];

        while (*link != NULL) {
            struct vg_snap_ent *e = *link;

            if (e->gen != c->snap_gen) {
                *link = e->next;
                e->gen = 0;
                e->next = c->snap_free;
                c->snap_free = e;

            } else {
                link = &e->next;
            }
        }
    }
}


static struct vg_snap_ent *
snap_get(struct vg_ctrl *c, int family, const uint8_t *addr, int *created)
{
    unsigned h = snap_hash(family, addr);
    struct vg_snap_ent *e;
    int n = family == AF_INET ? 4 : 16;

    *created = 0;

    for (e = c->snaps[h]; e != NULL; e = e->next) {
        if (e->family == family && memcmp(e->addr, addr, (size_t) n) == 0) {
            e->gen = c->snap_gen;
            return e;
        }
    }

    e = c->snap_free;

    if (e == NULL) {
        return NULL;
    }

    c->snap_free = e->next;
    e->family = family;
    memcpy(e->addr, addr, (size_t) n);
    e->in_pkts = 0;
    e->in_bytes = 0;
    e->gen = c->snap_gen;
    e->next = c->snaps[h];
    c->snaps[h] = e;
    *created = 1;
    return e;
}


int
vg_ctrl_init(struct vg_ctrl *c, struct vg_config_file *cfg,
    struct vg_maps *maps, const char *cfg_path,
    const char *iface_ov)
{
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    c->maps = maps;
    c->state = VG_IDLE;
    c->drop_cap = 1024;
    c->drops = calloc((size_t) c->drop_cap, sizeof(*c->drops));

    if (c->drops == NULL) {
        return -1;
    }

    c->snap_cap = (cfg != NULL && cfg->remote_map_size != 0)
                  ? cfg->remote_map_size * 2 : VG_REMOTE_MAP_MAX * 2;
    c->snap_pool = calloc((size_t) c->snap_cap, sizeof(*c->snap_pool));

    if (c->snap_pool == NULL) {
        free(c->drops);
        c->drops = NULL;
        return -1;
    }

    snap_reset_pool(c);

    if (cfg_path != NULL) {
        snprintf(c->cfg_path, sizeof(c->cfg_path), "%s", cfg_path);
    }

    if (iface_ov != NULL) {
        snprintf(c->iface_override, sizeof(c->iface_override), "%s", iface_ov);
    }

    return 0;
}


void
vg_ctrl_free(struct vg_ctrl *c)
{
    free(c->drops);
    c->drops = NULL;
    free(c->snap_pool);
    c->snap_pool = NULL;
    c->snap_free = NULL;
    c->snap_cap = 0;
}


static int
drops_find(struct vg_ctrl *c, const struct vg_cidr *p)
{
    int i;

    for (i = 0; i < c->drop_count; i++) {
        if (c->drops[i].cidr.family == p->family
            && c->drops[i].cidr.prefixlen == p->prefixlen
            && memcmp(c->drops[i].cidr.addr, p->addr,
                      p->family == AF_INET ? 4 : 16) == 0)
        {
            return i;
        }
    }

    return -1;
}


int
vg_ctrl_drop(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason)
{
    char buf[80];
    time_t now = time(NULL);
    int idx;

    vg_cidr_to_str(p, buf, sizeof(buf));

    if (vg_cidr_is_protected(c->cfg, p)) {
        vg_log("refuse drop %s (covers local/allow)", buf);
        return -1;
    }

    if (c->state != VG_ACTIVE && vg_ctrl_arm(c, "manual drop") < 0) {
        return -1;
    }

    idx = drops_find(c, p);

    if (idx < 0) {
        if (c->drop_count == c->drop_cap) {
            int ncap = c->drop_cap * 2;
            struct vg_drop_rec *n = realloc(c->drops,
                                            (size_t) ncap * sizeof(*n));

            if (n == NULL) {
                return -1;
            }

            c->drops = n;
            c->drop_cap = ncap;
        }

        c->drops[c->drop_count].cidr = *p;
        c->drops[c->drop_count].reason = reason;
        c->drops[c->drop_count].inserted = now;

        if (vg_drop_add(c->maps, p, reason, (uint32_t) now) < 0) {
            vg_warn("drop map update %s failed: %s", buf, strerror(errno));
            return -1;
        }

        c->drop_count++;

    } else {
        if (vg_drop_add(c->maps, p, reason, (uint32_t) now) < 0) {
            vg_warn("drop map update %s failed: %s", buf, strerror(errno));
            return -1;
        }

        if (reason == VG_REASON_MANUAL) {
            c->drops[idx].reason = VG_REASON_MANUAL;
            c->drops[idx].inserted = now;
        }
    }

    vg_log("drop %s reason %u", buf, reason);
    return 0;
}


int
vg_ctrl_undrop(struct vg_ctrl *c, const struct vg_cidr *p)
{
    struct vg_cidr cidr = *p;
    int i = drops_find(c, &cidr);
    char buf[80];

    vg_cidr_to_str(p, buf, sizeof(buf));

    if (i >= 0) {
        c->drops[i] = c->drops[c->drop_count - 1];
        c->drop_count--;
    }

    if (vg_drop_del(c->maps, &cidr) < 0 && errno != ENOENT) {
        vg_warn("undrop map delete %s failed: %s", buf, strerror(errno));
    }

    vg_log("undrop %s", buf);
    return 0;
}


int
vg_ctrl_arm(struct vg_ctrl *c, const char *why)
{
    if (c->state == VG_ACTIVE) {
        return 0;
    }

    snap_clear(c);
    c->quiet_since = 0;

    if (vg_cfg_commit(c->maps, 1, c->cfg) < 0) {
        vg_warn("arm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    c->state = VG_ACTIVE;
    vg_log("armed (%s)", why != NULL ? why : "");
    return 0;
}


int
vg_ctrl_disarm(struct vg_ctrl *c, const char *why)
{
    vg_drop_flush(c->maps);
    c->drop_count = 0;

    if (vg_cfg_commit(c->maps, 0, c->cfg) < 0) {
        vg_warn("disarm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    c->state = VG_IDLE;
    c->quiet_since = 0;
    vg_log("disarmed (%s)", why != NULL ? why : "");
    return 0;
}


int
vg_ctrl_reload(struct vg_ctrl *c)
{
    struct vg_config_file n;
    char iface[VG_MAX_IFACE];
    char mode[16];
    uint32_t rsz, dsz;

    if (c->cfg_path[0] == '\0') {
        return -1;
    }

    snprintf(iface, sizeof(iface), "%s", c->cfg->interface);
    snprintf(mode, sizeof(mode), "%s", c->cfg->xdp_mode);
    rsz = c->cfg->remote_map_size;
    dsz = c->cfg->drop_map_size;

    if (vg_config_load(c->cfg_path, &n) < 0) {
        return -1;
    }

    snprintf(n.interface, sizeof(n.interface), "%s", iface);
    snprintf(n.xdp_mode, sizeof(n.xdp_mode), "%s", mode);
    n.remote_map_size = rsz;
    n.drop_map_size = dsz;

    if (c->iface_override[0]) {
        snprintf(n.interface, sizeof(n.interface), "%s", c->iface_override);
    }

    *c->cfg = n;

    if (vg_cfg_commit(c->maps, c->state == VG_ACTIVE, c->cfg) < 0) {
        return -1;
    }

    if (vg_populate_allow(c->maps, c->cfg) < 0
        || vg_populate_local(c->maps, c->cfg) < 0)
    {
        return -1;
    }

    vg_log("reloaded %s", c->cfg_path);
    return 0;
}


static int
maybe_aggregate(struct vg_ctrl *c, const struct vg_cidr *host)
{
    struct vg_cidr net;
    int i, n = 0;

    if (host->family == AF_INET) {
        if (vg_cidr_v4_slash24(host, &net) < 0) {
            return 0;
        }

    } else {
        if (vg_cidr_v6_slash64(host, &net) < 0) {
            return 0;
        }
    }

    for (i = 0; i < c->drop_count; i++) {
        if (vg_cidr_contains(&net, &c->drops[i].cidr)) {
            n++;
        }
    }

    if (n >= c->cfg->aggregate_k) {
        return vg_ctrl_drop(c, &net, VG_REASON_AGGREGATE);
    }

    return 0;
}


static void
policy_one_remote(struct vg_ctrl *c, int family,
    const uint8_t *addr,
    const struct host_counters *cur, double dt)
{
    int created = 0;
    struct vg_snap_ent *s = snap_get(c, family, addr, &created);
    uint64_t dp, db;
    double pps, bps;
    struct vg_cidr p;

    if (s == NULL) {
        return;
    }

    if (created) {
        s->in_pkts = cur->in_pkts;
        s->in_bytes = cur->in_bytes;
        return;
    }

    dp = cur->in_pkts >= s->in_pkts ? cur->in_pkts - s->in_pkts : 0;
    db = cur->in_bytes >= s->in_bytes ? cur->in_bytes - s->in_bytes : 0;
    s->in_pkts = cur->in_pkts;
    s->in_bytes = cur->in_bytes;

    if (dt <= 0) {
        return;
    }

    pps = (double) dp / dt;
    bps = (double) db * 8.0 / dt;

    if (pps < (double) c->cfg->threshold_pps
        && bps < (double) c->cfg->threshold_mbps * 1000000.0)
    {
        return;
    }

    memset(&p, 0, sizeof(p));
    p.family = family;
    memcpy(p.addr, addr, family == AF_INET ? 4 : 16);
    p.prefixlen = family == AF_INET ? 32 : 128;

    if (vg_ctrl_drop(c, &p, VG_REASON_POLICY) == 0) {
        maybe_aggregate(c, &p);
    }
}


struct vg_walk_ctx {
    struct vg_ctrl  *c;
    double           dt;
};

static void
remote_cb(int family, const uint8_t *addr,
    const struct host_counters *sum, void *arg)
{
    struct vg_walk_ctx *w = arg;

    policy_one_remote(w->c, family, addr, sum, w->dt);
}


static void
walk_remotes(struct vg_ctrl *c, double dt)
{
    struct vg_walk_ctx w = { .c = c, .dt = dt };
    uint32_t budget = c->cfg->remote_map_size;
    int complete;

    if (budget == 0) {
        budget = VG_REMOTE_MAP_MAX;
    }

    c->snap_gen++;

    if (c->snap_gen == 0) {
        snap_reset_pool(c);
        c->snap_gen = 1;
    }

    complete = vg_remote_foreach(c->maps, budget, remote_cb, &w);

    if (complete == 1) {
        snap_prune(c);
    }
}


static void
expire_drops(struct vg_ctrl *c)
{
    time_t now = time(NULL);
    int i = 0;

    while (i < c->drop_count) {
        if (c->drops[i].reason == VG_REASON_MANUAL) {
            i++;
            continue;
        }

        if (now - c->drops[i].inserted < c->cfg->ban_time) {
            i++;
            continue;
        }

        vg_ctrl_undrop(c, &c->drops[i].cidr);
    }
}


static double
tick_dt(struct vg_ctrl *c)
{
    struct timespec now;
    double dt;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (c->have_last_tick == 0) {
        c->last_tick = now;
        c->have_last_tick = 1;
        return 0;
    }

    dt = (double) (now.tv_sec - c->last_tick.tv_sec)
         + (double) (now.tv_nsec - c->last_tick.tv_nsec) / 1e9;
    c->last_tick = now;

    if (dt < 0) {
        dt = 0;
    }

    return dt;
}


int
vg_ctrl_tick(struct vg_ctrl *c)
{
    struct vg_metrics m;
    double dt = tick_dt(c);

    if (vg_metrics_read(c->maps, &m) < 0) {
        return -1;
    }

    if (c->have_last_m && dt > 0) {
        uint64_t dp = m.rx_pkts >= c->last_m.rx_pkts
                      ? m.rx_pkts - c->last_m.rx_pkts : 0;
        uint64_t db = m.rx_bytes >= c->last_m.rx_bytes
                      ? m.rx_bytes - c->last_m.rx_bytes : 0;

        c->rx_pps = (double) dp / dt;
        c->rx_bps = (double) db * 8.0 / dt;
    }

    c->last_m = m;
    c->have_last_m = 1;

    if (dt <= 0) {
        return 0;
    }

    if (c->state == VG_IDLE) {
        if (c->rx_pps > (double) c->cfg->wake_pps
            || c->rx_bps > (double) c->cfg->wake_mbps * 1000000.0)
        {
            vg_ctrl_arm(c, "wake threshold");
        }

        return 0;
    }

    walk_remotes(c, dt);
    expire_drops(c);

    if (c->rx_pps < (double) c->cfg->wake_pps
        && c->rx_bps < (double) c->cfg->wake_mbps * 1000000.0)
    {
        if (c->quiet_since == 0) {
            c->quiet_since = time(NULL);
        }

        if (c->drop_count == 0
            && time(NULL) - c->quiet_since >= c->cfg->clear_seconds)
        {
            vg_ctrl_disarm(c, "attack cleared");
        }

    } else {
        c->quiet_since = 0;
    }

    return 0;
}


void
vg_ctrl_status(struct vg_ctrl *c, char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "state=%s armed=%d rx_pps=%.0f rx_bps=%.0f drops=%d iface=%s\n",
             c->state == VG_ACTIVE ? "active" : "idle",
             c->state == VG_ACTIVE, c->rx_pps, c->rx_bps, c->drop_count,
             c->cfg->interface);
}


void
vg_ctrl_stats(struct vg_ctrl *c, char *buf, size_t buflen)
{
    struct vg_metrics m;

    if (vg_metrics_read(c->maps, &m) < 0) {
        snprintf(buf, buflen, "error reading metrics\n");
        return;
    }

    snprintf(buf, buflen,
             "rx_pkts=%llu rx_bytes=%llu passed=%llu dropped=%llu "
             "non_ip=%llu map_full=%llu parse_err=%llu\n"
             "rx_pps=%.0f rx_bps=%.0f state=%s drops=%d\n",
             (unsigned long long)m.rx_pkts,
             (unsigned long long)m.rx_bytes,
             (unsigned long long)m.passed,
             (unsigned long long)m.dropped,
             (unsigned long long)m.non_ip,
             (unsigned long long)m.map_full,
             (unsigned long long)m.parse_err, c->rx_pps, c->rx_bps,
             c->state == VG_ACTIVE ? "active" : "idle", c->drop_count);
}


void
vg_ctrl_list_drops(struct vg_ctrl *c, char *buf, size_t buflen)
{
    size_t used = 0;
    int i;

    if (c->drop_count == 0) {
        snprintf(buf, buflen, "(none)\n");
        return;
    }

    buf[0] = 0;

    for (i = 0; i < c->drop_count && used + 80 < buflen; i++) {
        char p[80];
        int n;

        vg_cidr_to_str(&c->drops[i].cidr, p, sizeof(p));
        n = snprintf(buf + used, buflen - used,
                     "%s reason=%u age=%ld\n", p, c->drops[i].reason,
                     (long) (time(NULL) - c->drops[i].inserted));

        if (n > 0) {
            used += (size_t) n;
        }
    }
}


void
vg_ctrl_prometheus(struct vg_ctrl *c, char *buf, size_t buflen)
{
    struct vg_metrics m;

    memset(&m, 0, sizeof(m));
    vg_metrics_read(c->maps, &m);
    snprintf(buf, buflen,
             "# TYPE voidgate_armed gauge\n"
             "voidgate_armed %d\n"
             "# TYPE voidgate_rx_packets_total counter\n"
             "voidgate_rx_packets_total %llu\n"
             "# TYPE voidgate_rx_bytes_total counter\n"
             "voidgate_rx_bytes_total %llu\n"
             "# TYPE voidgate_dropped_packets_total counter\n"
             "voidgate_dropped_packets_total %llu\n"
             "# TYPE voidgate_map_full_total counter\n"
             "voidgate_map_full_total %llu\n"
             "# TYPE voidgate_drop_prefixes gauge\n"
             "voidgate_drop_prefixes %d\n"
             "# TYPE voidgate_rx_pps gauge\n"
             "voidgate_rx_pps %.0f\n",
             c->state == VG_ACTIVE ? 1 : 0,
             (unsigned long long)m.rx_pkts,
             (unsigned long long)m.rx_bytes,
             (unsigned long long)m.dropped,
             (unsigned long long)m.map_full, c->drop_count, c->rx_pps);
}


#if (VG_CTRL_TEST)
unsigned
vg_ctrl_snap_count(const struct vg_ctrl *c)
{
    unsigned n = 0;
    int i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        const struct vg_snap_ent *e;

        for (e = c->snaps[i]; e != NULL; e = e->next) {
            n++;
        }
    }

    return n;
}
#endif
