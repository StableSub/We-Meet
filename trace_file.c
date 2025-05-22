#include "vmlinux.h"
#include "event_struct.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_open(struct trace_event_raw_sys_enter *ctx) {
    struct file_open_event *e;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = (u32)bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->base.type = FILE_OPEN;
    e->base.pid = pid;
    e->base.ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->base.uid = uid;
    bpf_get_current_comm(e->base.comm, sizeof(e->base.comm));

    const char *filename = (const char*) ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}