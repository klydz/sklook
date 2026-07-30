# sklook

BPF SK_LOOKUP program that intercepts TCP connections to a target
port and redirects them to a backdoor socket. No packet mangling,
no iptables, no XDP/TC, just the kernel's socket lookup hook.

## how it works

A 28-line BPF program (sklook_kern.c) attaches to the network
namespace via BPF_PROG_TYPE_SK_LOOKUP. Every new TCP connection
to port 9999 is redirected to a listening socket on port 31337
by calling bpf_sk_assign().

The userspace loader (sklook_user.c) creates the backdoor socket,
registers it in a SOCKHASH map, loads the BPF object, and attaches
it to the current netns.

## requirements

- Linux 5.6+
- CONFIG_DEBUG_INFO_BTF=y (for vmlinux.h)
- root, or CAP_BPF + CAP_NET_ADMIN + CAP_NET_NS_ADMIN
- libbpf development headers
- clang, bpftool

## build

```
make
```

This generates vmlinux.h from BTF, compiles the BPF program, and
builds the userspace loader.

## run

```
sudo ./sklook
```

Connections to 127.0.0.1:9999 will be transparently redirected
to 127.0.0.1:31337.

## article

[(article)
](https://klydz.net/post.php?slug=bypassing-xdp-and-tc-stealthy-connection-interception-via-bpf-sklookup)
