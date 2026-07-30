CC      ?= gcc
CLANG   ?= clang
BPFTOOL ?= bpftool

all: vmlinux.h sklook_kern.o sklook

# Generate vmlinux.h from BTF.  This needs pahole and a kernel that
# exposes /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y).
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

sklook_kern.o: sklook_kern.c vmlinux.h
	$(CLANG) -target bpf -g -O2 -c sklook_kern.c -o sklook_kern.o

sklook: sklook_user.c
	$(CC) -g -O2 sklook_user.c -o sklook -lbpf -lpthread

clean:
	rm -f sklook_kern.o sklook

distclean: clean
	rm -f vmlinux.h

.PHONY: all clean distclean
