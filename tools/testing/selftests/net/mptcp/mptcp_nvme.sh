#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

trtype="${1:-mptcp}"
traddr="${2:-127.0.0.1}"
ns=1
port=1234
trsvcid=4420
nqn=nqn.2014-08.org.nvmexpress.${trtype}dev
final_ret=0

#ip mptcp monitor &

cleanup()
{
	rm -rf /sys/kernel/config/nvmet/ports/${port}/subsystems/${trtype}subsys
	rmdir /sys/kernel/config/nvmet/ports/${port}
	echo 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/enable
	echo -n 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/device_path
	rmdir /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}
	rmdir /sys/kernel/config/nvmet/subsystems/${nqn}
	losetup -d /dev/loop100
	rm -rf /tmp/test.raw
}

check_error()
{
	if dmesg | grep -E -q "starting error recovery|Buffer I/O error"; then
		cleanup
		exit 1
	fi
}

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

echo
echo "nvme discover"
echo
nvme discover -t ${trtype} -a ${traddr} -s ${trsvcid}

echo
echo "nvme connect"
echo
devname=$(nvme connect -t ${trtype} -a ${traddr} -s ${trsvcid} -n ${nqn} | awk '{print $4}')
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error

sleep 0.5
echo
echo "nvme list"
echo
nvme list
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error

echo
echo "fio randread"
echo
fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randread --numjobs=4 \
    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread \
    --filename=/dev/${devname}n1
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error

echo
echo "fio randwrite"
echo
fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randwrite --numjobs=4 \
    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randwrite \
    --filename=/dev/${devname}n1
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error

sleep 0.5
echo
echo "nvme disconnect"
echo
nvme disconnect -n ${nqn}
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error

cleanup
echo "final_ret=${final_ret}"
exit ${final_ret}
