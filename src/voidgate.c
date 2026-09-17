/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include "policy.h"
#include "ipaddr.h"
#include "log.h"
#include "maps.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


static void on_signal(int sig);
static void sock_timeout(int fd);
static int listen_unix(const char *path);
static int listen_http(int port);
static void handle_ctl(struct vg_ctrl *ctrl, int cfd);
static void handle_http(struct vg_ctrl *ctrl, int cfd);
static long elapsed_ms(const struct timespec *a, const struct timespec *b);
static void usage(const char *argv0);

static volatile sig_atomic_t g_stop;

static void
on_signal(int sig)
{
    (void) sig;
    g_stop = 1;
}


static void
sock_timeout(int fd)
{
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}


static int
listen_unix(const char *path)
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


static int
listen_http(int port)
{
    struct sockaddr_in addr;
    int fd, one = 1;

    if (port <= 0) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t) port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


static void
handle_ctl(struct vg_ctrl *ctrl, int cfd)
{
    char req[256], reply[8192];
    ssize_t n;
    char *nl;

    sock_timeout(cfd);
    n = read(cfd, req, sizeof(req) - 1);

    if (n <= 0) {
        return;
    }

    req[n] = 0;
    nl = strchr(req, '\n');

    if (nl != NULL) {
        *nl = 0;
    }

    reply[0] = 0;

    if (strcmp(req, "status") == 0) {
        vg_ctrl_status(ctrl, reply, sizeof(reply));

    } else if (strcmp(req, "stats") == 0) {
        vg_ctrl_stats(ctrl, reply, sizeof(reply));

    } else if (strcmp(req, "drops") == 0) {
        vg_ctrl_list_drops(ctrl, reply, sizeof(reply));

    } else if (strcmp(req, "arm") == 0) {
        if (vg_ctrl_arm(ctrl, "ctl") < 0) {
            snprintf(reply, sizeof(reply), "error: arm failed\n");

        } else {
            snprintf(reply, sizeof(reply), "ok\n");
        }

    } else if (strcmp(req, "disarm") == 0) {
        if (vg_ctrl_disarm(ctrl, "ctl") < 0) {
            snprintf(reply, sizeof(reply), "error: disarm failed\n");

        } else {
            snprintf(reply, sizeof(reply), "ok\n");
        }

    } else if (strncmp(req, "drop ", 5) == 0) {
        struct vg_cidr p;

        if (vg_parse_cidr(req + 5, &p) < 0) {
            snprintf(reply, sizeof(reply), "error: bad cidr\n");

        } else if (vg_ctrl_drop(ctrl, &p, VG_REASON_MANUAL) < 0) {
            snprintf(reply, sizeof(reply),
                     "error: refused or map update failed\n");

        } else {
            snprintf(reply, sizeof(reply), "ok\n");
        }

    } else if (strncmp(req, "undrop ", 7) == 0) {
        struct vg_cidr p;

        if (vg_parse_cidr(req + 7, &p) < 0) {
            snprintf(reply, sizeof(reply), "error: bad cidr\n");

        } else {
            vg_ctrl_undrop(ctrl, &p);
            snprintf(reply, sizeof(reply), "ok\n");
        }

    } else if (strcmp(req, "reload") == 0) {
        if (vg_ctrl_reload(ctrl) < 0) {
            snprintf(reply, sizeof(reply), "error: reload failed\n");

        } else {
            snprintf(reply, sizeof(reply), "ok\n");
        }

    } else {
        snprintf(reply, sizeof(reply), "error: unknown command\n");
    }

    if (reply[0]) {
        ssize_t wr = write(cfd, reply, strlen(reply));

        (void) wr;
    }
}


static void
handle_http(struct vg_ctrl *ctrl, int cfd)
{
    char req[512], body[4096], resp[4608];
    ssize_t n;

    sock_timeout(cfd);
    n = read(cfd, req, sizeof(req) - 1);

    if (n <= 0) {
        return;
    }

    req[n] = 0;

    if (strncmp(req, "GET ", 4) != 0 || strstr(req, "/metrics") == NULL) {
        const char *nf = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Length: 0\r\nConnection: close\r\n\r\n";
        ssize_t wr = write(cfd, nf, strlen(nf));

        (void) wr;
        return;
    }

    vg_ctrl_prometheus(ctrl, body, sizeof(body));
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/plain; version=0.0.4\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             strlen(body), body);
    {
        ssize_t wr = write(cfd, resp, strlen(resp));

        (void) wr;
    }
}


static long
elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec - b->tv_sec) * 1000L
           + (a->tv_nsec - b->tv_nsec) / 1000000L;
}


static void
usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-c config] [-i iface]\n", argv0);
}


int
main(int argc, char **argv)
{
    struct vg_config_file cfg;
    struct vg_maps maps;
    struct vg_ctrl ctrl;
    const char *cfg_path = "/etc/voidgate/voidgate.conf";
    const char *iface_ov = NULL;
    int opt, ctl_fd = -1, http_fd = -1;
    struct sigaction sa;
    struct timespec last_tick;

    while ((opt = getopt(argc, argv, "c:i:h")) != -1) {
        switch (opt) {
        case 'c':
            cfg_path = optarg;
            break;
        case 'i':
            iface_ov = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (vg_config_load(cfg_path, &cfg) < 0) {
        return 1;
    }

    if (iface_ov != NULL) {
        snprintf(cfg.interface, sizeof(cfg.interface), "%s", iface_ov);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (vg_maps_open(&maps, &cfg) < 0) {
        return 1;
    }

    if (vg_populate_allow(&maps, &cfg) < 0
        || vg_populate_local(&maps, &cfg) < 0)
    {
        vg_maps_close(&maps);
        return 1;
    }

    if (vg_cfg_commit(&maps, 0, &cfg) < 0) {
        vg_maps_close(&maps);
        return 1;
    }

    if (vg_xdp_attach(&maps, &cfg) < 0) {
        vg_maps_close(&maps);
        return 1;
    }

    if (vg_ctrl_init(&ctrl, &cfg, &maps, cfg_path, iface_ov) < 0) {
        vg_maps_close(&maps);
        return 1;
    }

    ctl_fd = listen_unix(VG_SOCK_PATH);

    if (ctl_fd < 0) {
        vg_log("ctl socket %s failed: %s (voidgatectl disabled)",
               VG_SOCK_PATH, strerror(errno));

    } else {
        vg_log("ctl socket %s", VG_SOCK_PATH);
    }

    http_fd = listen_http(cfg.metrics_port);

    if (http_fd >= 0) {
        vg_log("prometheus 127.0.0.1:%d/metrics", cfg.metrics_port);
    }

    vg_log("idle on %s, wake_pps=%llu wake_mbps=%llu", cfg.interface,
           (unsigned long long)cfg.wake_pps,
           (unsigned long long)cfg.wake_mbps);

    clock_gettime(CLOCK_MONOTONIC, &last_tick);
    while (!g_stop) {
        struct pollfd pfd[2];
        int nfds = 0, pr, wait_ms;
        struct timespec now;
        long elapsed;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = elapsed_ms(&now, &last_tick);
        wait_ms = cfg.idle_poll_ms - (int) elapsed;

        if (wait_ms < 0) {
            wait_ms = 0;
        }

        if (ctl_fd >= 0) {
            pfd[nfds].fd = ctl_fd;
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        if (http_fd >= 0) {
            pfd[nfds].fd = http_fd;
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        pr = poll(pfd, (nfds_t) nfds, wait_ms);

        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }

            break;
        }

        if (pr > 0) {
            int i;

            for (i = 0; i < nfds; i++) {
                int cfd;

                if (!(pfd[i].revents & POLLIN)) {
                    continue;
                }

                cfd = accept(pfd[i].fd, NULL, NULL);

                if (cfd < 0) {
                    continue;
                }

                if (pfd[i].fd == ctl_fd) {
                    handle_ctl(&ctrl, cfd);

                } else {
                    handle_http(&ctrl, cfd);
                }

                close(cfd);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (pr <= 0 || elapsed_ms(&now, &last_tick) >= cfg.idle_poll_ms) {
            vg_ctrl_tick(&ctrl);
            last_tick = now;
        }
    }

    vg_ctrl_disarm(&ctrl, "shutdown");
    vg_ctrl_free(&ctrl);
    vg_maps_close(&maps);

    if (ctl_fd >= 0) {
        close(ctl_fd);
        unlink(VG_SOCK_PATH);
    }

    if (http_fd >= 0) {
        close(http_fd);
    }

    vg_log("exit");
    return 0;
}
