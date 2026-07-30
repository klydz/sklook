// SPDX-License-Identifier: GPL-2.0-only
// sklook: BPF SK_LOOKUP program that intercepts TCP connections to
// TARGET_PORT and redirects them to a socket pre-loaded in sock_map.
//
// Attach with: bpftool net attach sk_lookup sk_redirect id <prog_id>
// Or via libbpf: bpf_program__attach_netns(prog, netns_fd)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TARGET_PORT     9999

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sock_map SEC(".maps");

SEC("sk_lookup")
int sk_redirect(struct bpf_sk_lookup *ctx) {
    if (ctx->local_port != TARGET_PORT)
        return SK_PASS;

    u32 key = 0;
    struct bpf_sock *sk = bpf_map_lookup_elem(&sock_map, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, (void *)sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
