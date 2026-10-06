#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer.skel.h"

struct event_data {
    unsigned int pid;
    unsigned int syscall_id;
    char comm[ 16 ];
    char str_arg[ 128 ];
    unsigned long long start_time;
    unsigned long long duration_ns;
    long ret;
};

static volatile sig_atomic_t exiting = 0;

const char *syscall_names[ 500 ] = {
    [ 0 ] = "read",
    [ 1 ] = "write",
    [ 2 ] = "open",
    [ 3 ] = "close",
    [ 4 ] = "stat",
    [ 5 ] = "fstat",
    [ 9 ] = "mmap",
    [ 10 ] = "mprotect",
    [ 12 ] = "brk",
    [ 16 ] = "ioctl",
    [ 21 ] = "access",
    [ 157 ] = "prctl",
    [ 158 ] = "arch_prctl",
    [ 202 ] = "futex",
    [ 217 ] = "getdents64",
    [ 218 ] = "set_tid_address",
    [ 231 ] = "exit_group",
    [ 257 ] = "openat",
    [ 262 ] = "newfstatat",
    [ 273 ] = "set_robust_list",
    [ 302 ] = "prlimit64",
    [ 318 ] = "getrandom",
    [ 334 ] = "rseq"
};

const char *get_syscall_name( unsigned int id ){
    if( id < 500 && syscall_names[ id ] ){
        return syscall_names[ id ];
    }
    return "UNKNOWN";
}

void sig_handler( int sig ){
    exiting = 1;
}

int handle_event( void *ctx, void *data, size_t data_sz ){
    struct event_data *e = data;
    const char *sys_name = get_syscall_name( e->syscall_id );
    double duration_us = e->duration_ns / 1000.0;

    if( e->str_arg[ 0 ] != '\0' ){
        printf( "Comm: %-10s PID: %-6u Syscall: %-16s Time: %8.3f us  Ret: %-4ld  Arg: %s\n", 
                e->comm, e->pid, sys_name, duration_us, e->ret, e->str_arg );
    }else{
        printf( "Comm: %-10s PID: %-6u Syscall: %-16s Time: %8.3f us  Ret: %-4ld\n", 
                e->comm, e->pid, sys_name, duration_us, e->ret );
    }
    return 0;
}

int main( int argc, char **argv ){
    struct tracer_bpf *skel;
    struct ring_buffer *rb;
    int err;
    char target_comm[ 16 ] = { 0 };
    unsigned int key = 0;
    int map_fd;

    if( argc != 2 ){
        fprintf( stderr, "Usage: %s <command_name>\n", argv[ 0 ] );
        return 1;
    }

    strncpy( target_comm, argv[ 1 ], 15 );

    signal( SIGINT, sig_handler );
    signal( SIGTERM, sig_handler );

    skel = tracer_bpf__open();
    if( !skel ){
        fprintf( stderr, "Failed to open BPF skeleton\n" );
        return 1;
    }

    err = tracer_bpf__load( skel );
    if( err ){
        fprintf( stderr, "Failed to load BPF skeleton\n" );
        tracer_bpf__destroy( skel );
        return 1;
    }

    map_fd = bpf_map__fd( skel->maps.target_comm_map );
    err = bpf_map_update_elem( map_fd, &key, target_comm, BPF_ANY );
    if( err ){
        fprintf( stderr, "Failed to set target command\n" );
        tracer_bpf__destroy( skel );
        return 1;
    }

    err = tracer_bpf__attach( skel );
    if( err ){
        fprintf( stderr, "Failed to attach BPF skeleton\n" );
        tracer_bpf__destroy( skel );
        return 1;
    }

    rb = ring_buffer__new( bpf_map__fd( skel->maps.ringbuf ), handle_event, NULL, NULL );
    if( !rb ){
        fprintf( stderr, "Failed to create ring buffer\n" );
        tracer_bpf__destroy( skel );
        return 1;
    }

    printf( "Tracing command '%s'... Hit Ctrl-C to end.\n", target_comm );

    while( !exiting ){
        err = ring_buffer__poll( rb, 100 );
        if( err == -EINTR ){
            err = 0;
            break;
        }
        if( err < 0 ){
            break;
        }
    }

    ring_buffer__free( rb );
    tracer_bpf__destroy( skel );
    return -err;
}
