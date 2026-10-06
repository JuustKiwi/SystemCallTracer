CC = clang
CFLAGS = -g -O2 -Wall
ARCH = x86

.PHONY: all clean

all: loader

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tracer.bpf.o: tracer.bpf.c vmlinux.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c tracer.bpf.c -o tracer.bpf.o

tracer.skel.h: tracer.bpf.o
	bpftool gen skeleton tracer.bpf.o > tracer.skel.h

loader: loader.c tracer.skel.h
	$(CC) $(CFLAGS) loader.c -lbpf -o loader

clean:
	rm -f tracer.bpf.o tracer.skel.h loader vmlinux.h
