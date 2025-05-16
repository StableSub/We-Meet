# Makefile
KERNEL_SRC ?= $(HOME)/linux-6.14.6

BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -Wall -target bpf -D__TARGET_ARCH=arm64
BPF_INCLUDES = \
  -I . \
  -I /home/stablesub/ \
  -I $(KERNEL_SRC)/tools/lib/bpf \
  -I $(KERNEL_SRC)/tools/bpf/resolve_btfids/libbpf/include/bpf \
  -I $(HOME)/libbpf-latest/include \
  -I $(HOME)/libbpf-latest/include/bpf

SRC = event.c
OUT = event.o
SKEL = event.skel.h
LOADER = loader

all: $(OUT) $(SKEL) $(LOADER)

$(OUT): $(SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(SKEL): $(OUT)
	bpftool gen skeleton $< > $@

$(LOADER): main.c $(SKEL)
	clang -g -O2 -Wall -I. -o $@ main.c -lbpf -lelf -lz

clean:
	rm -f $(OUT) $(SKEL) $(LOADER)