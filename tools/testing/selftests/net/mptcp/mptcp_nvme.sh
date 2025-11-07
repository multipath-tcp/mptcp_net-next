#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

trtype="${1:-mptcp}"
traddr="${2:-127.0.0.1}"
ns=1
port=1234
trsvcid=4420
nqn=nqn.2014-08.org.nvmexpress.${trtype}dev

dd if=/dev/zero of=/tmp/test.raw bs=1M count=0 seek=512
losetup /dev/loop100 /tmp/test.raw
cd /sys/kernel/config/nvmet/subsystems
mkdir ${nqn}
cd ${nqn}
echo 1 > attr_allow_any_host
cd namespaces
mkdir ${ns}
cd ${ns}
echo /dev/loop100 > device_path
echo 1 > enable
cd /sys/kernel/config/nvmet/ports
mkdir ${port}
cd ${port}
echo ${trtype} > addr_trtype
echo ipv4 > addr_adrfam
echo ${traddr} > addr_traddr
echo ${trsvcid} > addr_trsvcid
cd subsystems
ln -s ../../../subsystems/${nqn} ${trtype}subsys

echo "nvme discover"
nvme discover -t ${trtype} -a ${traddr} -s ${trsvcid}

echo "nvme connect"
devname=$(nvme connect -t ${trtype} -a ${traddr} -s ${trsvcid} -n ${nqn} | awk '{print $4}')

sleep 0.5
echo "nvme list"
nvme list

fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randread --numjobs=4 --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread --filename=/dev/${devname}n1

fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randwrite --numjobs=4 --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread --filename=/dev/${devname}n1

sleep 0.5
echo "nvme disconnect"
nvme disconnect -n ${nqn}

rm -rf /sys/kernel/config/nvmet/ports/${port}/subsystems/${trtype}subsys
rmdir /sys/kernel/config/nvmet/ports/${port}
echo 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/enable
echo -n 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/device_path
rmdir /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}
rmdir /sys/kernel/config/nvmet/subsystems/${nqn}
losetup -d /dev/loop100
rm -rf /tmp/test.raw
