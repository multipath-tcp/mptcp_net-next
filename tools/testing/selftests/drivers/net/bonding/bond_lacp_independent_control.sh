#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# +-------------------------+ +-------------------------+
# | H1 (vrf)                | | H2 (vrf)                |
# |  + bond1 (802.3ad)      | |  + bond2 (802.3ad)      |
# |  | coupled_control off  | |  |                      |
# |  | 192.0.2.1/28         | |  | 192.0.2.2/28         |
# |  |                      | |  |                      |
# |  + $h1                  | |  + $h2                  |
# +--|----------------------+ +--|----------------------+
#    |                           |
#    +---------------------------+

# shellcheck disable=SC2034,SC2329
ALL_TESTS="
	collecting
	distributing
"
NUM_NETIFS=2
REQUIRE_MZ=no
lib_dir=$(dirname "$0")
# shellcheck disable=SC1091
source "$lib_dir"/../../../net/forwarding/lib.sh

lacp_state_get()
{
	local dev=$1; shift

	ip -d -j link show dev "$dev" | \
		jq '.[].linkinfo.info_slave_data.ad_actor_oper_port_state'
}

# The actor state of a port in ATTACHED state is 0x0f: Activity (0x01),
# Timeout (0x02), Aggregation (0x04) and Synchronization (0x08). The
# Collecting (0x10) bit is added in COLLECTING state (0x1f) and the
# Distributing (0x20) bit in DISTRIBUTING state (0x3f).
lacp_state_wait()
{
	local dev=$1; shift
	local state=$1; shift

	slowwait "$WAIT_TIMEOUT" until_counter_is "== $state" \
		lacp_state_get "$dev" > /dev/null
}

partner_state_clear()
{
	local bits=$1; shift

	tc filter replace dev "$h1" ingress pref 1 handle 101 protocol 0x8809 \
		flower skip_hw action pedit munge offset 18 u8 set 0 \
		retain "$bits"
}

h1_create()
{
	adf_ip_link_add bond1 type bond mode 802.3ad lacp_rate fast \
		coupled_control off
	adf_ip_link_set_master "$h1" bond1
	adf_simple_if_init bond1 192.0.2.1/28

	tc qdisc add dev "$h1" clsact
	defer tc qdisc del dev "$h1" clsact

	tc qdisc add dev bond1 clsact
	defer tc qdisc del dev bond1 clsact

	tc filter add dev bond1 ingress pref 1 handle 101 proto ip \
		flower skip_hw src_ip 192.0.2.2 dst_ip 192.0.2.1 \
		ip_proto icmp type 8 action pass
	defer tc filter del dev bond1 ingress pref 1 handle 101 flower
}

h2_create()
{
	adf_ip_link_add bond2 type bond mode 802.3ad lacp_rate fast
	adf_ip_link_set_master "$h2" bond2
	adf_simple_if_init bond2 192.0.2.2/28
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	h2=${NETIFS[p2]}

	adf_vrf_prepare

	h1_create
	h2_create
}

collecting()
{
	local pkts

	RET=0

	# Clear the Synchronization (0x08) and Collecting (0x10) bits in the
	# partner's state to move $h1 to ATTACHED state and then only clear
	# the Collecting bit to move it to COLLECTING state.
	partner_state_clear 0x18
	defer tc filter del dev "$h1" ingress pref 1 handle 101 flower
	lacp_state_wait "$h1" 0x0f
	check_err $? "Port did not reach ATTACHED state"

	partner_state_clear 0x10
	lacp_state_wait "$h1" 0x1f
	check_err $? "Port did not reach COLLECTING state"

	# $h1 cannot reply to ARP requests in COLLECTING state.
	ip neigh add 192.0.2.1 lladdr "$(mac_get bond1)" dev bond2 \
		nud permanent
	defer ip neigh del 192.0.2.1 dev bond2

	ping_do bond2 192.0.2.1
	pkts=$(tc_rule_handle_stats_get "dev bond1 ingress" 101)
	((pkts >= PING_COUNT))
	check_err $? "Packets not received in COLLECTING state"

	log_test "Receive in COLLECTING state"
}

distributing()
{
	RET=0

	lacp_state_wait "$h1" 0x3f
	check_err $? "Port did not reach DISTRIBUTING state"

	ping_do bond2 192.0.2.1
	check_err $? "Ping failed"

	log_test "Ping in DISTRIBUTING state"
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit "$EXIT_STATUS"
