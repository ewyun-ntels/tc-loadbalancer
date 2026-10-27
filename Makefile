CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MULTIARCH  := $(shell gcc -print-multiarch 2>/dev/null)

BPF_SRC    := bpf/lb_kern.c
BPF_OBJ    := bpf/lb_kern.o

# 맵은 LIBBPF_PIN_BY_NAME 이라 bpffs 루트에 이름 그대로 핀된다.
PIN_MAPS   := /sys/fs/bpf/lb_assign /sys/fs/bpf/lb_stats
PIN_PROG   := /sys/fs/bpf/lbtest

BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -Wall -Werror \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -I bpf

ifneq ($(MULTIARCH),)
BPF_CFLAGS += -I/usr/include/$(MULTIARCH)
endif

.PHONY: all clean bpffs verify unpin dump

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/lb_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpffs:
	@mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
	@mountpoint -q /sys/fs/bpf && echo "bpffs mounted"

# 부착하지 않고 verifier 만 통과시켜 본다.
# SEC("tc") 는 libbpf 가 자동 인식하므로 type 인자를 주면 안 된다
# (주면 섹션명이 'sched_cls/' 로 바뀌어 인식 실패).
verify: $(BPF_OBJ) bpffs unpin
	sudo $(BPFTOOL) prog loadall $(BPF_OBJ) $(PIN_PROG)
	@echo "--- program ---"
	sudo $(BPFTOOL) prog show pinned $(PIN_PROG)/lb_ingress
	@echo "--- maps ---"
	@for m in $(PIN_MAPS); do sudo $(BPFTOOL) map show pinned $$m; done
	@echo "--- verifier OK ---"
	@$(MAKE) --no-print-directory unpin

unpin:
	@sudo rm -rf $(PIN_PROG) $(PIN_MAPS)

dump: $(BPF_OBJ)
	$(BPFTOOL) prog dump xlated file $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)
