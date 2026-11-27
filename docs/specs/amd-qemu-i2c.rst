.. SPDX-License-Identifier: GPL-2.0-or-later

Generic I2C controller for emulation (amd-qemu-i2c)
===================================================

``amd-qemu-i2c`` is an I2C controller made for emulation rather than copied
from a real part.  It is a bus controller and a target at the same time, and
it models the behaviour firmware has to handle: address and data NACKs,
clock stretching, timeouts, lost arbitration and a stuck bus.  The Zephyr
driver is ``i2c_amd_qemu.c`` in ainic-suc (compatible ``amd,qemu-i2c``).

Buses
-----

Every controller has a ``bus-name``.  Controllers with the same name in one
QEMU are on one bus, together with any QEMU I2C devices (``at24c-eeprom``,
``tmp105``, PMBus devices, ...) attached to their ``i2c-bus`` (named after
the bus).  ``amd-qemu-i2c-link`` extends a bus to another QEMU over a
chardev; addresses with no target in this QEMU go to the peer, which NACKs
them if it has none either.

On ``vul_suc`` there are three controllers:

====== ============ ===== =================
Name   Base         IRQ   Machine property
====== ============ ===== =================
i2c0   0x40002000   9     ``i2c0-bus``
i2c1   0x40021000   37    ``i2c1-bus``
i2c2   0x50002000   38    ``i2c2-bus``
====== ============ ===== =================

Each is on its own bus unless the machine properties give two the same
name.  Examples::

  # i2c0 and i2c1 on one bus, an EEPROM on it
  -machine vul_suc,i2c1-bus=i2c0 -device at24c-eeprom,bus=i2c0,address=0x50

  # this QEMU's i2c0 bus continues in another QEMU
  -chardev socket,id=l0,host=127.0.0.1,port=4000,server=on,wait=off
  -device amd-qemu-i2c-link,chardev=l0,bus-name=i2c0

  # ... which connects with
  -chardev socket,id=l0,host=127.0.0.1,port=4000,reconnect-ms=200
  -device amd-qemu-i2c-link,chardev=l0,bus-name=i2c1

A bus is held by one controller from START to STOP.  A controller that
starts while another holds the bus loses arbitration.  When controllers on
both sides of a link start at once, the side with ``arb-priority=on`` wins.

Registers
---------

32-bit registers, 0x100 bytes.  The FIFOs hold 256 bytes; there are two
target address slots.  Unlisted offsets are reserved.

=====  ============  ===  ======================================================
Off    Name          Acc  Description
=====  ============  ===  ======================================================
0x00   ID            RO   0x51433249 ("I2CQ")
0x0c   CTRL          RW   [0] ENABLE, [1] TARGET_EN, [6:4] SPEED (Zephyr
                          ``I2C_SPEED_*``; recorded, does not change timing)
0x10   STATUS        RO   [9:8] T_SLOT: the address slot of the latest
                          T_WRITE_REQ or T_READ_REQ
0x14   INT_STATUS    W1C  see below
0x18   INT_ENABLE    RW   see below; the IRQ is (INT_STATUS & INT_ENABLE) != 0
0x20   C_ADDR        RW   [9:0] target address, [15] 10-bit
0x24   C_LEN         RW   bytes in the next command (0..FIFO depth)
0x28   C_CMD         WO   starts a command: [0] START (or repeated START),
                          [1] READ, [2] STOP after it, [3] LAST (NACK the last
                          byte read), [8] RECOVER (ends any running command
                          and recovers the bus; other bits ignored)
0x30   C_TIMEOUT     RW   how long (us) a target may stretch before the
                          command ends with TIMEOUT; 0 disables
0x34   C_DATA        RW   write: push to the TX FIFO; read: pop the RX FIFO
0x3c   C_FIFO_CLR    WO   [0] clear TX, [1] clear RX
0x40   T_ADDR0       RW   [9:0] address, [15] 10-bit, [31] VALID
0x44   T_ADDR1       RW   as T_ADDR0
0x48   T_DATA        RW   read: byte received; write: byte to send
0x4c   T_RESP        WO   [0] ACK (1) or NACK (0): answers the pending target
                          event and releases the bus
=====  ============  ===  ======================================================

Interrupts (INT_STATUS, INT_ENABLE):

==== ============= ========================================================
Bit  Name          Set when
==== ============= ========================================================
0    C_DONE        a command finished, with or without an error below
1    C_NACK_ADDR   no target acknowledged the address
2    C_NACK_DATA   the target NACKed a written byte
3    C_ARB_LOST    the bus was held by another controller
4    C_TIMEOUT     the target stretched longer than C_TIMEOUT
5    C_BUS_ERR     bad command (including one that would overflow a FIFO),
                   stuck bus, or link lost mid-transfer
8    T_WRITE_REQ   addressed for a write; answer with T_RESP
9    T_READ_REQ    addressed for a read; write T_DATA, then T_RESP
10   T_RX          a byte was written to us (T_DATA); answer with T_RESP
11   T_TX_REQ      the controller wants the next byte: write T_DATA, then
                   T_RESP
12   T_STOP        STOP, or the controller ended the transfer; no answer
==== ============= ========================================================

Controller commands
-------------------

A transfer is one or more commands.  START sends the address (a repeated
START if the bus is already held); a command without START continues the
current message, so messages longer than the FIFO are split into commands.
For a write, C_LEN bytes must be in the TX FIFO.  A read puts C_LEN bytes in
the RX FIFO and ACKs each byte except the last one if LAST is set; a read
with C_LEN 0 is a bad command.  STOP releases the bus.  On any error the
controller sends STOP itself.  RECOVER is accepted while a command runs: it
ends the command and its transfer, and C_DONE is raised once.

Target events
-------------

Each event except T_STOP holds the bus (clock stretching) until firmware
writes T_RESP; the controller's C_TIMEOUT bounds how long.  Firmware must
clear the event in INT_STATUS before writing T_RESP, because T_RESP lets the
controller go on and may raise the next event at once.  NACKing T_WRITE_REQ
or T_READ_REQ NACKs the address; NACKing T_RX NACKs that byte.  A STOP that
is still pending when the next transfer starts belongs to the previous one,
and T_SLOT then already names the new transfer's slot, so firmware should
record the slot at T_WRITE_REQ or T_READ_REQ.

Fault injection
---------------

QOM properties, settable at run time with ``qom-set`` (for example
``/machine/i2c0``):

==================== ======= ================================================
Property             Side    Effect
==================== ======= ================================================
fault-nack-addr      ctrl    NACK every START to this address (0: off)
fault-nack-byte      ctrl    NACK the n-th data byte of each message (0: off)
fault-arb-lost       ctrl    the next START loses arbitration (clears itself)
fault-sda-stuck      ctrl    every START fails (C_BUS_ERR) until RECOVER
fault-stretch-us     target  stretch each answer by this long
fault-hang           target  never answer; the controller times out
==================== ======= ================================================

Link
----

``amd-qemu-i2c-link`` (properties ``chardev``, ``bus-name``,
``arb-priority``) sends 8-byte frames: magic 0x5a, type, sequence (le16),
address (le16, bit 15 = 10-bit), byte, flags or status.

==== ======== =========================================================
Type Name     Meaning
==== ======== =========================================================
0x01 START    address, flags bit 0 = read; answered with RESULT (and the
              first byte, for a read)
0x02 WRITE    one byte; answered with RESULT
0x03 NEXT     read the next byte; answered with RESULT
0x04 RNACK    the controller NACKed the last byte read
0x05 STOP     end of transfer
0x06 ABORT    the controller gave up (timeout, error)
0x81 RESULT   status 0 ACK, 1 NACK, 2 arbitration lost, 3 bus error;
              byte = data read
==== ======== =========================================================

While the peer is not connected, addresses not found locally are NACKed.
If the link drops during a transfer, the transfer ends with C_BUS_ERR.
