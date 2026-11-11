#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Measure TCP throughput with iperf3."""

from lib.py import Iperf3Runner, NetDrvEpEnv, ksft_exit, ksft_metric, ksft_run


def tcp(cfg):
    """Measure TCP throughput."""
    result = Iperf3Runner(cfg).measure()
    ksft_metric("throughput", result.throughput, goal="higher")


def main():
    """Run the iperf performance test."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        ksft_run([tcp], args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
