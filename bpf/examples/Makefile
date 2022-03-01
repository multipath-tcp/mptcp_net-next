MPTCP := ${PWD}/../../../mptcp_net-next

CFLAGS := -I${MPTCP}/usr/include
CFLAGS += -I${MPTCP}/tools/perf/libbpf/include

LOADER_FLAGS := -lelf -lz ${MPTCP}/tools/perf/libbpf/libbpf.a
LOADER_FLAGS += -DHAVE_ATTR_TEST=0

BPF_FLAGS := -O2 -target bpf -g

all: loader mptcp_set_sf_sockopt_kern.o

loader: loader.c
	clang $(CFLAGS) -o $@ $< $(LOADER_FLAGS)

%.o: %.c
	clang $(BPF_FLAGS) -c $< $(CFLAGS) -o $@

clean:
	rm -f *_kern.o loader
