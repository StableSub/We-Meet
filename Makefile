KERNEL_SRC ?= $(HOME)/linux-6.14.6
BUILD_DIR := build

BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -Wall -target bpf -D__TARGET_ARCH_arm64
BPF_INCLUDES = \
  -I . \
  -I /home/stablesub/ \
  -I $(KERNEL_SRC)/tools/lib/bpf \
  -I $(KERNEL_SRC)/tools/bpf/resolve_btfids/libbpf/include/bpf \

BPF_SRCS := trace_process.c trace_file.c trace_tcp.c
BPF_OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(BPF_SRCS))
BPF_SKELS := $(patsubst %.c, $(BUILD_DIR)/%.skel.h, $(BPF_SRCS))

LOADER := loader

all: $(BUILD_DIR) $(BPF_OBJS) $(BPF_SKELS) $(LOADER)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	bpftool gen skeleton $< > $@

$(LOADER): loader.c $(BPF_SKELS)
	clang -g -O2 -Wall -I$(BUILD_DIR) -I. -o $@ loader.c -lbpf -lelf -lz

clean:
	rm -rf $(BUILD_DIR) $(LOADER)