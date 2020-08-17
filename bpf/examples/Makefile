MPTCP := ${PWD}/../../../mptcp_net-next

CFLAGS := -I${MPTCP}/usr/include
CFLAGS += -I${MPTCP}/tools/lib
CFLAGS += -I${MPTCP}/tools/include
CFLAGS += -I${MPTCP}/tools/perf

LOADER_FLAGS := -lelf -lbpf
LOADER_FLAGS += -DHAVE_ATTR_TEST=0

BPF_FLAGS := -O2 -target bpf -g

all: loader mptcp_set_mark_kern.o

loader:
	@clang $(CFLAGS) $(LOADER_FLAGS) -o loader loader.c

mptcp_set_mark_kern.o:
	@clang $(BPF_FLAGS) -c mptcp_set_mark_kern.c \
		$(CFLAGS) -o mptcp_set_mark_kern.o

clean:
	@rm *_kern.o loader
