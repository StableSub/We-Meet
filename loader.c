#include "event.skel.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>  

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    bool event_type;
    char comm[256];
}

static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    int file = open("event.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
    dup2(file, STDOUT_FILENO);
    printf("{\n"
        "   type_of_event : %s,\n"
        "   pid : %d,\n"
        "   ppid : %d,\n"
        "   uid : %d,\n"
        "   comm : %s\n"
        "}\n", (e->event_type == 0 ? "execve" : "exit"), e->pid, e->ppid, e->uid, e->comm);
    return 0;
}

int main() {
    struct ring_buffer *rb = NULL;
    struct event_process *skel;

    skel = event__open();
    if (!skel) {
        fprintf(stderr, "open 실패\n");
        return 1;
    }

    if (event__load(skel)) {
        fprintf(stderr, "load 실패\n");
        return 1;
    }

    if (event__attach(skel)) {
        fprintf(stderr, "attach 실패\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new 실패\n");
        return 1;
    }

    printf("✅ ringbuf attach 완료! execve 기다리는 중...\n");
    while (1) 
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    event_process__destroy(skel);
    return 0;
}