#
## Makefile for MultiPath TCP support code.
#
#

obj-$(CONFIG_MPTCP) += mptcp.o

mptcp-y := mptcp_ctrl.o mptcp_ipv4.o mptcp_pm.o \
	   mptcp_output.o mptcp_input.o mptcp_sched.o

obj-$(CONFIG_MPTCP_FULLMESH) += mptcp_fullmesh.o

mptcp-$(subst m,y,$(CONFIG_IPV6)) += mptcp_ipv6.o

