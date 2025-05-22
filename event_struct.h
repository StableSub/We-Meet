#ifndef __EVENT_STRUCT_H__
#define __EVENT_STRUCT_H__

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <stdint.h>
#include <linux/types.h>
#endif

enum event_type {
    PROCESS_CREATE,
    PROCESS_TERMINATE,
    FILE_OPEN,
    TCP_CONNECT
};

#define EVENT_TCP_CONNECT TCP_CONNECT

struct base_struct {
    enum event_type type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp_ns;
    char comm[256];
};

struct process_event {
    struct base_struct base;
};

struct file_open_event {
    struct base_struct base;
    char filename[256];
};

struct tcp_connect_event {
    struct base_struct base;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
};

struct sock_info_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

#endif
