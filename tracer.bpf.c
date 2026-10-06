#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint( type, BPF_MAP_TYPE_ARRAY );
    __type( key, unsigned int );
    __type( value, char[ 16 ] );
    __uint( max_entries, 1 );
} target_comm_map SEC(".maps");

struct event_data {
    unsigned int pid;
    unsigned int syscall_id;
    char comm[ 16 ];
    char str_arg[ 128 ];
    unsigned long long start_time;
    unsigned long long duration_ns;
    long ret;
};

struct {
    __uint( type, BPF_MAP_TYPE_HASH );
    __type( key, unsigned long long );
    __type( value, struct event_data );
    __uint( max_entries, 10240 );
} active_syscalls SEC(".maps");

struct {
    __uint( type, BPF_MAP_TYPE_RINGBUF );
    __uint( max_entries, 256 * 1024 );
} ringbuf SEC(".maps");

static __always_inline int comm_equals( const char *a, const char *b ){
    for( int i = 0; i < 16; i++ ){
        if( a[ i ] != b[ i ] ){
            return 0;
        }
        if( a[ i ] == '\0' ){
            break;
        }
    }
    return 1;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter( struct trace_event_raw_sys_enter *ctx ){
    unsigned int key = 0;
    char *target_comm = bpf_map_lookup_elem( &target_comm_map, &key );
    if( !target_comm ){
        return 0;
    }

    char current_comm[ 16 ];
    bpf_get_current_comm( &current_comm, sizeof( current_comm ) );

    if( !comm_equals( current_comm, target_comm ) ){
        return 0;
    }

    unsigned long long tgid = bpf_get_current_pid_tgid();
    struct event_data event = { 0 };

    event.pid = tgid >> 32;
    event.syscall_id = ctx->id;
    event.start_time = bpf_ktime_get_ns();
    
    for( int i = 0; i < 16; i++ ){
        event.comm[ i ] = current_comm[ i ];
    }

    unsigned long arg0 = ctx->args[ 0 ];
    unsigned long arg1 = ctx->args[ 1 ];

    if( ctx->id == 257 || ctx->id == 262 ){
        bpf_probe_read_user_str( event.str_arg, sizeof( event.str_arg ), (void *)arg1 );
    }else if( ctx->id == 2 || ctx->id == 4 || ctx->id == 21 ){
        bpf_probe_read_user_str( event.str_arg, sizeof( event.str_arg ), (void *)arg0 );
    }

    bpf_map_update_elem( &active_syscalls, &tgid, &event, BPF_ANY );
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit( struct trace_event_raw_sys_exit *ctx ){
    unsigned long long tgid = bpf_get_current_pid_tgid();
    
    struct event_data *saved_event = bpf_map_lookup_elem( &active_syscalls, &tgid );
    if( !saved_event ){
        return 0;
    }

    struct event_data *event = bpf_ringbuf_reserve( &ringbuf, sizeof( struct event_data ), 0 );
    if( !event ){
        bpf_map_delete_elem( &active_syscalls, &tgid );
        return 0;
    }

    *event = *saved_event;
    event->duration_ns = bpf_ktime_get_ns() - saved_event->start_time;
    event->ret = ctx->ret;

    bpf_ringbuf_submit( event, 0 );
    bpf_map_delete_elem( &active_syscalls, &tgid );

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
