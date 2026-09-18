/* SPDX-License-Identifier: Apache-2.0 */

#include "ctl_server.h"
#include "policy.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int interrupt_read, interrupt_send;
static size_t fragment;

ssize_t __real_read(int fd, void *buf, size_t size);
ssize_t __real_send(int fd, const void *buf, size_t size, int flags);

ssize_t
__wrap_read(int fd, void *buf, size_t size)
{
    if (interrupt_read) {
        interrupt_read = 0;
        errno = EINTR;
        return -1;
    }
    if (fragment && size > fragment) {
        size = fragment;
    }
    return __real_read(fd, buf, size);
}

ssize_t
__wrap_send(int fd, const void *buf, size_t size, int flags)
{
    if (interrupt_send) {
        interrupt_send = 0;
        errno = EINTR;
        return -1;
    }
    if (fragment && size > fragment) {
        size = fragment;
    }
    return __real_send(fd, buf, size, flags);
}

int
vg_metrics_read(struct vg_maps *maps, struct vg_metrics *out)
{
    memset(out, 0, sizeof(*out));
    out->rx_pkts = UINT64_MAX;
    return 0;
}

int
vg_ctrl_arm(struct vg_ctrl *ctrl, const char *why)
{
    ctrl->state = VG_ACTIVE;
    return 0;
}

int
vg_ctrl_disarm(struct vg_ctrl *ctrl, const char *why)
{
    ctrl->state = VG_IDLE;
    return 0;
}

int
vg_ctrl_drop(struct vg_ctrl *ctrl, const struct vg_cidr *cidr, uint32_t reason)
{
    ctrl->drops[0].cidr = *cidr;
    ctrl->drops[0].reason = reason;
    ctrl->drops[0].inserted = time(NULL);
    ctrl->drop_count = 1;
    return 0;
}

int
vg_ctrl_undrop(struct vg_ctrl *ctrl, const struct vg_cidr *cidr)
{
    ctrl->drop_count = 0;
    return 0;
}

int
vg_ctrl_reload(struct vg_ctrl *ctrl)
{
    return -1;
}

static void
check(struct vg_ctrl *ctrl, const void *request, size_t size, const char *expected)
{
    int fd[2];
    char reply[8192];
    size_t used = 0;
    ssize_t n;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    assert(write(fd[0], request, size) == (ssize_t) size);
    assert(shutdown(fd[0], SHUT_WR) == 0);
    interrupt_read = interrupt_send = 1;
    fragment = 2;
    vg_ctl_server_handle(ctrl, fd[1]);
    fragment = 0;
    interrupt_read = interrupt_send = 0;
    close(fd[1]);
    while ((n = read(fd[0], reply + used, sizeof(reply) - 1 - used)) > 0) {
        used += (size_t) n;
    }
    assert(n == 0);
    reply[used] = 0;
    assert(strcmp(reply, expected) == 0);
    close(fd[0]);
}

int
main(int argc, char **argv)
{
    struct vg_config_file cfg = {0};
    struct vg_drop_rec drop = {0};
    struct vg_ctrl ctrl = { .cfg = &cfg, .drops = &drop };
    char long_command[255];
    int fd[2];

    snprintf(cfg.interface, sizeof(cfg.interface), "test0");
    if (argc == 2) {
        struct timeval timeout = { .tv_sec = 1 };
        int listener = vg_ctl_server_listen(argv[1]);
        assert(listener >= 0);
        puts("ready");
        fflush(stdout);
        for (;;) {
            int client = accept(listener, NULL, NULL);
            assert(client >= 0);
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            fragment = 2;
            vg_ctl_server_handle(&ctrl, client);
            close(client);
        }
    }

    check(&ctrl, "arm\n", 4, "ok\n");
    assert(ctrl.state == VG_ACTIVE);
    check(&ctrl, "disarm", 6, "ok\n"); /* EOF framing remains supported. */
    assert(ctrl.state == VG_IDLE);
    check(&ctrl, "stat", 4, "error: unknown command\n");
    check(&ctrl, "arm\0\n", 5, "error: bad command\n");
    assert(ctrl.state == VG_IDLE);
    memset(long_command, 'x', sizeof(long_command));
    check(&ctrl, long_command, sizeof(long_command), "error: command too long\n");
    check(&ctrl, "", 0, "");

    /* A stalled, incomplete command must not execute. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    {
        struct timeval timeout = { .tv_usec = 10000 };
        assert(setsockopt(fd[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    assert(write(fd[0], "arm", 3) == 3);
    vg_ctl_server_handle(&ctrl, fd[1]);
    assert(ctrl.state == VG_IDLE);
    close(fd[0]);
    close(fd[1]);

    /* Replying to a disconnected peer must not raise SIGPIPE. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    assert(write(fd[0], "status\n", 7) == 7);
    close(fd[0]);
    vg_ctl_server_handle(&ctrl, fd[1]);
    close(fd[1]);
    puts("control protocol tests passed");
    return 0;
}
