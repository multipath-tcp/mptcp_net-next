.. SPDX-License-Identifier: GPL-2.0-only

=====================
PSP Security Protocol
=====================

Protocol
========

PSP Security Protocol (PSP) was defined at Google and published in:

https://raw.githubusercontent.com/google/psp/main/doc/PSP_Arch_Spec.pdf

This section briefly covers protocol aspects crucial for understanding
the kernel API. Refer to the protocol specification for further details.

Note that the kernel implementation and documentation uses the term
"device key" in place of "master key", it is both less confusing
to an average developer and is less likely to run afoul any naming
guidelines.

Derived Rx keys
---------------

PSP borrows some terms and mechanisms from IPsec. PSP was designed
with HW offloads in mind. The key feature of PSP is that Rx keys for every
connection do not have to be stored by the receiver but can be derived
from device key and information present in packet headers.
This makes it possible to implement receivers which require a constant
amount of memory regardless of the number of connections (``O(1)`` scaling).

Tx keys have to be stored like with any other protocol, but Tx is much
less latency sensitive than Rx, and delays in fetching keys from slow
memory is less likely to cause packet drops. Preferably, the Tx keys
should be provided with the packet (e.g. as part of the descriptors).

Key rotation
------------

The device key known only to the receiver is fundamental to the design.
Per specification this state cannot be directly accessible (it must be
impossible to read it out of the hardware of the receiver NIC).
Moreover, it has to be "rotated" periodically (usually daily). Rotation
means that new device key gets generated (by a random number generator
of the device), and used for all new connections. To avoid disrupting
old connections the old device key remains in the NIC. A phase bit
carried in the packet headers indicates which generation of device key
the packet has been encrypted with.

User facing API
===============

PSP is designed primarily for hardware offloads. There is currently
no software fallback for systems which do not have PSP capable NICs.
There is also no standard (or otherwise defined) way of establishing
a PSP-secured connection or exchanging the symmetric keys.

The expectation is that higher layer protocols will take care of
protocol and key negotiation. For example one may use TLS key exchange,
announce the PSP capability, and switch to PSP if both endpoints
are PSP-capable.

All configuration of PSP is performed via the PSP netlink family.

Device discovery
----------------

The PSP netlink family defines operations to retrieve information
about the PSP devices available on the system, configure them and
access PSP related statistics.

Securing a connection
---------------------

PSP encryption is currently only supported for TCP connections.
Rx and Tx keys are allocated separately. First the ``rx-assoc``
Netlink command needs to be issued, specifying a target TCP socket.
Kernel will allocate a new PSP Rx key from the NIC and associate it
with given socket. At this stage socket will accept both PSP-secured
and plain text TCP packets.

Tx keys are installed using the ``tx-assoc`` Netlink command.
Once the Tx keys are installed, all data read from the socket will
be PSP-secured. In other words act of installing Tx keys has a secondary
effect on the Rx direction.

There is an intermediate period after ``tx-assoc`` successfully
returns and before the TCP socket encounters it's first PSP
authenticated packet, where the TCP stack will allow certain nondata
packets, i.e. ACKs, FINs, and RSTs, to enter TCP receive processing
even if not PSP authenticated. During the ``tx-assoc`` call, the TCP
socket's ``rcv_nxt`` field is recorded. At this point, ACKs and RSTs
will be accepted with any sequence number, while FINs will only be
accepted at the latched value of ``rcv_nxt``. Once the TCP stack
encounters the first TCP packet containing PSP authenticated data, the
other end of the connection must have executed the ``tx-assoc``
command, so any TCP packet, including those without data, will be
dropped before receive processing if it is not successfully
authenticated. This is summarized in the table below. The
aforementioned state of rejecting all non-PSP packets is labeled "PSP
Full".

+----------------+------------+------------+-------------+-------------+
| Event          | Normal TCP | Rx PSP     | Tx PSP      | PSP Full    |
+================+============+============+=============+=============+
| Rx plain       | accept     | accept     | drop        | drop        |
| (data)         |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Rx plain       | accept     | accept     | accept      | drop        |
| (ACK|FIN|RST)  |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Rx PSP (good)  | drop       | accept     | accept      | accept      |
+----------------+------------+------------+-------------+-------------+
| Rx PSP (bad    | drop       | drop       | drop        | drop        |
| crypt, !=SPI)  |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Tx             | plain text | plain text | encrypted   | encrypted   |
|                |            |            | (excl. rtx) | (excl. rtx) |
+----------------+------------+------------+-------------+-------------+

To ensure that any data read from the socket after the ``tx-assoc``
call returns success has been authenticated, the kernel will scan the
receive and ofo queues of the socket at ``tx-assoc`` time. If any
enqueued packet was received in clear text, the Tx association will
fail, and the application should retry installing the Tx key after
draining the socket (this should not be necessary if both endpoints
are well behaved).

Because TCP sequence numbers are not integrity protected prior to
upgrading to PSP, it is possible that a MITM could offset sequence
numbers in a way that deletes a prefix of the PSP protected part of
the TCP stream. If userspace cares to mitigate this type of attack, a
special "start of PSP" message should be exchanged after ``tx-assoc``.

Upgrade to PSP must be done on established TCP connections.
``rx-assoc`` and ``tx-assoc`` will return ``-ENOTCONN`` if
``sk_state`` is not ``TCP_ESTABLISHED``.

The PSP assoc state of a socket is not reset when the connection is
torn down. ``connect()`` on a socket that has PSP assoc state will
return ``-EINVAL``.

Rekeying
--------

A connection which has completed the exchange described above and is
in the "PSP Full" state can be rekeyed in place without being torn
down. The Tx and Rx directions are rekeyed separately using the same
netlink calls as in connection setup.

``rx-assoc`` allocates a new Rx key and SPI, which should be passed
to the peer exactly as during the initial exchange. The SPI which was
in use before the rekey remains acceptable on the socket until the
next Rx rekey, or until the device key it was derived from has been
rotated out, so packets the peer sent before it learned the new SPI
are still received.

``tx-assoc`` installs a new Tx key, which takes effect immediately.

A rekey is rejected with ``-EINVAL`` if it would change the PSP device
or the PSP version of the association. It is rejected with ``-EBUSY``
if the socket has not completed its initial exchange in both
directions.

Rotation notifications
----------------------

The rotations of device key happen asynchronously and are usually
performed by management daemons, not under application control.
The PSP netlink family will generate a notification whenever keys
are rotated. Applications are expected to rekey their connections,
as described above, before device keys are rotated again.

Kernel implementation
=====================

Driver notes
------------

Drivers are expected to start with no PSP enabled (``psp-versions-ena``
in ``dev-get`` set to ``0``) whenever possible. The user space should
not depend on this behavior, as future extension may necessitate creation
of devices with PSP already enabled, nonetheless drivers should not enable
PSP by default. Enabling PSP should be the responsibility of the system
component which also takes care of key rotation.

Note that ``psp-versions-ena`` is expected to be used only for enabling
receive processing. The device is not expected to reject transmit requests
after ``psp-versions-ena`` has been disabled. User may also disable
``psp-versions-ena`` while there are active associations, which will
break all PSP Rx processing.

Drivers are expected to ensure that a device key is usable and secure
upon init, without explicit key rotation by the user space. It must be
possible to allocate working keys, and that no duplicate keys must be
generated. If the device allows the host to request the key for an
arbitrary SPI - driver should discard both device keys (rotate the
device key twice), to avoid potentially using a SPI+key which previous
OS instance already had access to.

Drivers must use ``psp_skb_get_assoc_rcu()`` to check if PSP Tx offload
was requested for given skb. On Rx drivers should allocate and populate
the ``SKB_EXT_PSP`` skb extension, and set the skb->decrypted bit to 1.

Deferred Tx key deletion
~~~~~~~~~~~~~~~~~~~~~~~~

Drivers which implement ``tx_key_add`` and ``tx_key_del`` may hold key
references in their Tx rings, so PSP core waits until descriptors
containing these references are completed before removing the key from
the underlying device. PSP core uses accounting based on Byte Queue Limits
(BQL) to wait for a suitable grace period before asking the driver to
remove the key.

Drivers which implement the Tx key callbacks must meet the following
requirements:

* The driver must be "ops locked"
  (see Documentation/networking/netdevices.rst).
* A PSP skb accepted by ``ndo_start_xmit()`` must remain socket-owned until
  every Tx descriptor referencing its PSP key has been completed or otherwise
  made incapable of using the key. The driver must not orphan the skb before
  that point. Otherwise, the socket destructor may free the Tx key while key
  references remain in the Tx ring.
* Every PSP packet accepted by ``ndo_start_xmit()`` must be included in BQL
  queued bytecount before the function returns.
* Completion bytecounts must exactly match enqueue bytecounts and preserve
  queue order. A later packet must not be reported as completed while an earlier
  packet can still reference its key.
* Before calling ``dql_reset()`` on a queue, the driver must ensure that all
  outstanding descriptors containing key references have been completed or
  discarded. If called under the netdev instance lock, then descriptors can
  remain outstanding after the reset as long as they are completed or
  discarded before the instance lock is released.
* When decreasing ``real_num_tx_queues``, the driver must ensure that every
  outstanding descriptor on the queues at or above the new Tx queue count
  has been completed or otherwise made incapable of using its PSP key
  before the netdev instance lock is released.
* The BQL state of a queue below ``real_num_tx_queues`` must reflect all
  bytes completed or be reset after the queue has been quiesced. Failure to
  do so will stall the grace period algorithm.
* Before calling ``psp_dev_unregister()``, the driver must ensure that all
  outstanding Tx descriptors containing key references have been completed
  or discarded. PSP core deletes all remaining Tx keys during
  unregistration without waiting for a grace period.

Kernel implementation notes
---------------------------

PSP implementation follows the TLS offload more closely than the IPsec
offload, with per-socket state, and the use of skb->decrypted to prevent
clear text leaks.

PSP device is separate from netdev, to make it possible to "delegate"
PSP offload capabilities to software devices (e.g. ``veth``).
