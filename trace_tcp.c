#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "event_struct.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct sock_info_t);
    __uint(max_entries, 1024);
} sock_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_events SEC(".maps");

SEC("kprobe/tcp_connect")
int handle_tcp_connect_kprobe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock_info_t info = {};

    bpf_core_read(&info.saddr, sizeof(info.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&info.daddr, sizeof(info.daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&info.sport, sizeof(info.sport), &sk->__sk_common.skc_num);
    bpf_core_read(&info.dport, sizeof(info.dport), &sk->__sk_common.skc_dport);

    bpf_map_update_elem(&sock_info_map, &pid, &info, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_connect")
int handle_tcp_connect_kretprobe(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct sock_info_t *info = bpf_map_lookup_elem(&sock_info_map, &pid);
    if (!info)
        return 0;

    struct tcp_connect_event *e;
    e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->base.type = EVENT_TCP_CONNECT;
    e->base.pid = pid;
    e->base.tid = pid_tgid & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&e->base.ppid, sizeof(e->base.ppid), &parent->tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->base.uid = uid_gid >> 32;
    e->base.gid = uid_gid & 0xFFFFFFFF;
    bpf_get_current_comm(&e->base.comm, sizeof(e->base.comm));
    e->base.timestamp_ns = bpf_ktime_get_ns();

    e->saddr = info->saddr;
    e->daddr = info->daddr;
    e->sport = info->sport;
    e->dport = bpf_ntohs(info->dport);
    e->protocol = IPPROTO_TCP;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&sock_info_map, &pid);
    return 0;
}