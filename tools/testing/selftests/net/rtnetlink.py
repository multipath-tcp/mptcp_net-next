#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import socket
import struct
import time
from lib.py import bkg, ip, ksft_exit, ksft_run, ksft_eq, ksft_ge, ksft_true, KsftSkipEx
from lib.py import CmdExitFailure, NetNS, NetNSEnter, RtnlAddrFamily

IPV4_ALL_HOSTS_MULTICAST = b'\xe0\x00\x00\x01'
IPV4_TEST_MULTICAST = b'\xef\x01\x01\x01'
IPV6_TEST_MULTICAST = bytes.fromhex('ff020000000000000000000000000123')


def _users_for(rtnl: RtnlAddrFamily, family: int, grp: bytes, ifindex: int):
    """Return mc-users for grp on ifindex, or 0 if absent."""

    addrs = rtnl.getmulticast({"ifa-family": family}, dump=True)
    matches = [addr for addr in addrs
               if addr['multicast'] == grp and addr['ifa-index'] == ifindex]
    if not matches:
        return 0
    if 'mc-users' not in matches[0]:
        return None

    return matches[0]['mc-users']


def dump_mcaddr_check() -> None:
    """
    Verify IPv4 multicast addresses and their user counts in RTM_GETMULTICAST.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ip("link set lo up")
            rtnl = RtnlAddrFamily()
            lo_idx = socket.if_nametoindex('lo')
            addresses = rtnl.getmulticast({"ifa-family": socket.AF_INET}, dump=True)

            all_host_multicasts = [
                addr for addr in addresses
                if addr['multicast'] == IPV4_ALL_HOSTS_MULTICAST
            ]

            ksft_ge(len(all_host_multicasts), 1,
                    "No interface found with the IPv4 all-hosts multicast address")

            mreq = IPV4_TEST_MULTICAST + socket.inet_aton('127.0.0.1')
            before = _users_for(rtnl, socket.AF_INET, IPV4_TEST_MULTICAST, lo_idx)
            if before is None:
                raise KsftSkipEx("kernel does not expose IFA_MC_USERS")

            s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s1.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                s2.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                after_join = _users_for(rtnl, socket.AF_INET,
                                        IPV4_TEST_MULTICAST, lo_idx)
                if after_join is None:
                    raise KsftSkipEx("kernel does not expose IFA_MC_USERS")
                ksft_eq(after_join - before, 2,
                        f"users delta != 2 after two joins "
                        f"(before={before}, after={after_join})")
            finally:
                s1.close()
                s2.close()


def dump_mcaddr6_check() -> None:
    """
    Verify IPv6 multicast addresses and their user counts in RTM_GETMULTICAST.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ip("link set lo up")
            rtnl = RtnlAddrFamily()
            lo_idx = socket.if_nametoindex('lo')
            before = _users_for(rtnl, socket.AF_INET6,
                                IPV6_TEST_MULTICAST, lo_idx)
            if before is None:
                raise KsftSkipEx("kernel does not expose IFA_MC_USERS for IPv6")

            mreq = IPV6_TEST_MULTICAST + struct.pack('=I', lo_idx)
            s1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s1.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                s2.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

                after_join = _users_for(rtnl, socket.AF_INET6,
                                        IPV6_TEST_MULTICAST, lo_idx)
                if after_join is None:
                    raise KsftSkipEx("kernel does not expose IFA_MC_USERS for IPv6")
                ksft_eq(after_join - before, 2,
                        f"IPv6 users delta != 2 after two joins "
                        f"(before={before}, after={after_join})")
            finally:
                s1.close()
                s2.close()


def ipv4_devconf_notify() -> None:
    """
    Configure an interface and set ipv4-devconf values through netlink
    to verify that the appropriate netlink notifications are being sent.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ifname = "dummy1"
            ip(f"link add name {ifname} type dummy", ns=str(ns))

            with bkg("ip monitor", ns=str(ns)) as cmd_obj:
                time.sleep(1)
                try:
                    ip(f"link set dev {ifname} inet forwarding on")
                    ip(f"link set dev {ifname} inet proxy_arp on")
                    ip(f"link set dev {ifname} inet rp_filter 1")
                    ip(f"link set dev {ifname} inet ignore_routes_with_linkdown on")
                except CmdExitFailure:
                    raise KsftSkipEx("iproute2 does not support IPv4 devconf attributes")
                time.sleep(1)

    ksft_true(f"inet {ifname} ignore_routes_with_linkdown on" in cmd_obj.stdout,
              f"No 'ignore_routes_with_linkdown on' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} rp_filter strict" in cmd_obj.stdout,
              f"No 'rp_filter strict' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} proxy_neigh on" in cmd_obj.stdout,
              f"No 'proxy_neigh on' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} forwarding on" in cmd_obj.stdout,
              f"No 'forwarding on' notificiation found for interface {ifname}")

def main() -> None:
    ksft_run([dump_mcaddr_check, dump_mcaddr6_check, ipv4_devconf_notify])
    ksft_exit()

if __name__ == "__main__":
    main()
