/* SPDX-License-Identifier: Apache-2.0 */
#include "ctl_server.h"
#include "ipaddr.h"
#include "maps.h"
#include "policy.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


typedef void (*vg_ctl_handler_pt)(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);


typedef struct {
    const char         *name;
    int                 prefix;
    vg_ctl_handler_pt   handler;
} vg_ctl_command_t;


static void ctl_status(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_stats(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_drops(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_arm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_disarm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_drop(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_undrop(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_reload(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);


static const vg_ctl_command_t  vg_ctl_commands[] = {
    { "status",  0, ctl_status },
    { "stats",   0, ctl_stats },
    { "drops",   0, ctl_drops },
    { "arm",     0, ctl_arm },
    { "disarm",  0, ctl_disarm },
    { "drop ",   1, ctl_drop },
    { "undrop ", 1, ctl_undrop },
    { "reload",  0, ctl_reload }
};


static void
ctl_status(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    snprintf(reply, reply_size,
             "state=%s armed=%d rx_pps=%.0f rx_bps=%.0f "
             "prefixes=%d iface=%s\n",
             ctrl->state == VG_ACTIVE ? "active" : "idle",
             ctrl->state == VG_ACTIVE, ctrl->rx_pps, ctrl->rx_bps,
             ctrl->drop_count,
             ctrl->cfg->interface);
}


static void
ctl_stats(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    struct vg_metrics  m;

    if (vg_metrics_read(ctrl->maps, &m) < 0) {
        snprintf(reply, reply_size, "error reading metrics\n");
        return;
    }

    snprintf(reply, reply_size,
             "rx_pkts=%llu rx_bytes=%llu passed=%llu dropped=%llu "
             "non_ip=%llu map_full=%llu parse_err=%llu\n"
             "rx_pps=%.0f rx_bps=%.0f state=%s prefixes=%d\n",
             (unsigned long long) m.rx_pkts,
             (unsigned long long) m.rx_bytes,
             (unsigned long long) m.passed,
             (unsigned long long) m.dropped,
             (unsigned long long) m.non_ip,
             (unsigned long long) m.map_full,
             (unsigned long long) m.parse_err, ctrl->rx_pps, ctrl->rx_bps,
             ctrl->state == VG_ACTIVE ? "active" : "idle", ctrl->drop_count);
}


static void
ctl_drops(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    int     i;
    size_t  used = 0;

    if (ctrl->drop_count == 0) {
        snprintf(reply, reply_size, "(none)\n");
        return;
    }

    reply[0] = 0;

    for (i = 0; i < ctrl->drop_count && used + 80 < reply_size; i++) {
        int   n;
        char  p[80];

        vg_cidr_to_str(&ctrl->drops[i].cidr, p, sizeof(p));
        n = snprintf(reply + used, reply_size - used,
                     "%s reason=%u age=%ld\n", p, ctrl->drops[i].reason,
                     (long) (time(NULL) - ctrl->drops[i].inserted));

        if (n > 0) {
            used += (size_t) n;
        }
    }
}


static void
ctl_arm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_arm(ctrl, "ctl") < 0) {
        snprintf(reply, reply_size, "error: arm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_disarm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_disarm(ctrl, "ctl") < 0) {
        snprintf(reply, reply_size, "error: disarm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_drop(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    struct vg_cidr  p;

    if (vg_parse_cidr(args, &p) < 0) {
        snprintf(reply, reply_size, "error: bad cidr\n");

    } else if (vg_ctrl_drop(ctrl, &p, VG_REASON_MANUAL) < 0) {
        snprintf(reply, reply_size, "error: refused or map update failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_undrop(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    struct vg_cidr  p;

    if (vg_parse_cidr(args, &p) < 0) {
        snprintf(reply, reply_size, "error: bad cidr\n");

    } else {
        vg_ctrl_undrop(ctrl, &p);
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_reload(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_reload(ctrl) < 0) {
        snprintf(reply, reply_size, "error: reload failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


int
vg_ctl_server_listen(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    chmod(path, 0660);

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


void
vg_ctl_server_handle(struct vg_ctrl *ctrl, int cfd)
{
    char                    *nl;
    size_t                   i, len;
    ssize_t                  n;
    const vg_ctl_command_t  *cmd;
    char                     req[256], reply[8192];

    n = read(cfd, req, sizeof(req) - 1);

    if (n <= 0) {
        return;
    }

    req[n] = 0;
    nl = strchr(req, '\n');

    if (nl != NULL) {
        *nl = 0;
    }

    snprintf(reply, sizeof(reply), "error: unknown command\n");

    for (i = 0; i < sizeof(vg_ctl_commands) / sizeof(vg_ctl_commands[0]); i++) {
        cmd = &vg_ctl_commands[i];
        len = strlen(cmd->name);

        if (cmd->prefix ? strncmp(req, cmd->name, len) == 0
                        : strcmp(req, cmd->name) == 0)
        {
            reply[0] = 0;
            cmd->handler(ctrl, cmd->prefix ? req + len : NULL,
                         reply, sizeof(reply));
            break;
        }
    }

    if (reply[0]) {
        ssize_t wr = write(cfd, reply, strlen(reply));

        (void) wr;
    }
}
