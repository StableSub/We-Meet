#include "build/trace_process.skel.h"
#include "build/trace_file.skel.h"
#include "build/trace_tcp.skel.h"
#include "event_struct.h"

#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static int handle_event(void *ctx, void *data, size_t len) {
    struct base_struct *base = data;

    switch (base->type) {
        case PROCESS_CREATE: {
            struct process_event *e = data;
            printf("[PROCESS] {\n"
                "  event_type : process create\n"
                "  pid        : %u\n"
                "  ppid       : %u\n"
                "  uid        : %u\n"
                "  comm       : %s\n"
                "}\n\n",
                e->base.pid, e->base.ppid, e->base.uid, e->base.comm);
            break;
        }
        case PROCESS_TERMINATE: {
            struct process_event *e = data;
            printf("[PROCESS] {\n"
                "  event_type : process terminate\n"
                "  pid        : %u\n"
                "  ppid       : %u\n"
                "  uid        : %u\n"
                "  comm       : %s\n"
                "}\n\n",
                e->base.pid, e->base.ppid, e->base.uid, e->base.comm);
            break;
        }
        case FILE_OPEN: {
            struct file_open_event *e = data;
            printf("[FILE] {\n"
                "  pid      : %u\n"
                "  ppid     : %u\n"
                "  uid      : %u\n"
                "  comm     : %s\n"
                "  filename : %s\n"
                "}\n\n",
                e->base.pid, e->base.ppid, e->base.uid, e->base.comm, e->filename);
            break;
        }
        case TCP_CONNECT: {
            struct tcp_connect_event *e = data;
            printf("[TCP] {\n"
                    "  pid         : %u\n"
                    "  comm        : %s\n"
                    "  sport       : %u\n"
                    "  dport       : %u\n"
                    "  saddr       : 0x%x\n"
                    "  daddr       : 0x%x\n"
                    "}\n\n",
                    e->base.pid, e->base.comm,
                    e->sport, e->dport,
                    e->saddr, e->daddr);
            break;
        }
        default:
    }

    return 0;
}

struct trace_process *init_trace_process(struct ring_buffer **rb) {
    struct trace_process *skel = trace_process__open();
    if (!skel || trace_process__load(skel) || trace_process__attach(skel)) {
        fprintf(stderr, "trace_process attach 실패\n");
        return NULL;
    }
    *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    return skel;
}

struct trace_file *init_trace_file(struct ring_buffer **rb) {
    struct trace_file *skel = trace_file__open();
    if (!skel || trace_file__load(skel) || trace_file__attach(skel)) {
        fprintf(stderr, "trace_file attach 실패\n");
        return NULL;
    }
    *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    return skel;
}

struct trace_tcp *init_trace_tcp(struct ring_buffer **rb) {
    struct trace_tcp *skel = trace_tcp__open();
    if (!skel || trace_tcp__load(skel) || trace_tcp__attach(skel)) {
        fprintf(stderr, "trace_tcp attach 실패\n");
        return NULL;
    }
    *rb = ring_buffer__new(bpf_map__fd(skel->maps.tcp_events), handle_event, NULL, NULL);
    return skel;
}

int main() {
    struct ring_buffer *rb_proc = NULL, *rb_file = NULL, *rb_tcp = NULL;
    struct trace_process *p_skel = init_trace_process(&rb_proc);
    struct trace_file *f_skel = init_trace_file(&rb_file);
    struct trace_tcp *t_skel = init_trace_tcp(&rb_tcp);

    if (!p_skel || !f_skel || !t_skel || !rb_proc || !rb_file || !rb_tcp)
        return 1;

    printf("✅ ringbuf attach 완료! 로그 수집 중...\n");

    while (1) {
        ring_buffer__poll(rb_proc, 100);
        ring_buffer__poll(rb_file, 100);
        ring_buffer__poll(rb_tcp, 100);
    }

    ring_buffer__free(rb_proc);
    ring_buffer__free(rb_file);
    ring_buffer__free(rb_tcp);
    trace_process__destroy(p_skel);
    trace_file__destroy(f_skel);
    trace_tcp__destroy(t_skel);
    return 0;
}