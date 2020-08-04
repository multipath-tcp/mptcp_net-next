MPTCP := ${PWD}/../../../mptcp_net-next

CFLAGS := -I${MPTCP}/usr/include
CFLAGS += -I${MPTCP}/tools/lib
CFLAGS += -I${MPTCP}/tools/include
CFLAGS += -I${MPTCP}/tools/perf

LOADER_FLAGS := -lelf -lbpf
LOADER_FLAGS += -DHAVE_ATTR_TEST=0

BPF_FLAGS := -O2 -target bpf -g

all: mptcp_set_mark_user

mptcp_set_mark_kern.o:
	@clang $(BPF_FLAGS) -c mptcp_set_mark_kern.c \
		$(CFLAGS) -o mptcp_set_mark_kern.o

mptcp_set_mark_user: mptcp_set_mark_kern.o
	@clang  $(CFLAGS) $(LOADER_FLAGS) \
		-o mptcp_set_mark_user mptcp_set_mark_user.c
clean:
	@rm mptcp_set_mark_user mptcp_set_mark_kern.o
