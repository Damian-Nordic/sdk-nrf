.. _802154_sniffer:

IEEE 802.15.4 Sniffer
#####################

.. contents::
   :local:
   :depth: 2

The IEEE 802.15.4 Sniffer listens to a selected IEEE 802.15.4 channel (2.4GHz O-QPSK with DSSS) and integrates with the nRF 802.15.4 sniffer extcap for Wireshark.

Requirements
************

The sample supports the following development kits:

.. table-from-sample-yaml::

The application can be used with the `nRF Sniffer for 802.15.4`_ extcap utility for the `Wireshark`_ network protocol analyzer.

Overview
********

The application presents the user with a command-line interface.

See the :ref:`802154_sniffer_commands` for the list of the available commands.

LED 1:
   When the capture is stopped the LED blinks with a period of 2 seconds with 50% duty cycle.
   When the capture is ongoing the LED blinks with a period of 0.5 seconds with 50% duty cycle.

LED 4:
   When the sniffer captures a packet the LED is toggled on and off.

.. _802154_sniffer_commands:

Serial commands list
********************

This section lists the serial commands that are supported by the sample.

channel - Change the radio channel
==================================

The command changes the IEEE 802.15.4 radio channel to listen on.

   .. parsed-literal::
      :class: highlight

      channel *<channel>*

The ``<channel>`` argument is an integer in the range between 11 and 26.

For example:

   .. parsed-literal::
      :class: highlight

      channel *23*

phy - Change the radio PHY
==========================

The command selects the physical layer used for reception.

   .. parsed-literal::
      :class: highlight

      phy *<phy>*

The ``<phy>`` argument is either ``250k`` for the 2.4 GHz O-QPSK with DSSS PHY, or ``2m`` for the 2 Mbps GFSK PHY.

For example:

   .. parsed-literal::
      :class: highlight

      phy *250k*

.. note::
   Set the PHY before the channel, because changing the PHY can reset the channel setting.

receive - start capturing packets
=================================

The ``receive`` command makes the sniffer enter the RX state and start capturing packets.

   .. parsed-literal::
      :class: highlight

      receive

The received packets will be printed to the command-line with the following format:

   .. parsed-literal::
      :class: highlight

      received: *<data>* power: *<power>* lqi: *<lqi>* time: *<timestamp>*

* The ``<data>`` is a hexidecimal string representation of the received packet.
* The ``<power>`` value is the signal power in dBm.
* The ``<lqi>`` value is the IEEE 802.15.4 Link Quality Indicator.
* The ``<timestamp>`` value is the absolute time of the received packet since the sniffer booted.

sleep - stop capturing packets
==============================

The ``sleep`` command disables the radio and ends the receive process.

   .. parsed-literal::
      :class: highlight

      sleep

Hardware time sync (multi-sniffer)
===================================

When ``CONFIG_IEEE802154_SNIFFER_TIME_SYNC`` is enabled and the ``sniffer_sync`` devicetree node is present, the sample can emit hardware-timestamped sync pulses on a GPIO pin.

Master (generates pulses and reports ``sync role=master seq=<n> t=<us>``):

   .. parsed-literal::
      :class: highlight

      sync master start
      sync master start *<interval_ms>*

Slave (captures pulses and reports ``sync role=slave id=<id> edge=<n> t=<us>``):

   .. parsed-literal::
      :class: highlight

      sync slave
      sync slave *<id>*

Stop sync:

   .. parsed-literal::
      :class: highlight

      sync stop

Wiring (connect **SYNC** pin on each board, plus common GND). Role is set in software only
(``sync master start`` / ``sync slave``); either board can be master or slave.

* nRF54LM20 dongle **SYNC = P0.03** (header port **P0**, pin **3**)
* nRF52840 dongle **SYNC = P0.02** (header port **P0**, pin **02**)
* nRF52840 DK **SYNC = P0.03** (header **A1**)

Example cable between two dongles:

.. code-block:: text

   nRF54LM20  P0.03 (SYNC)  ──►  nRF52840  P0.02 (SYNC)
   GND                     ──►  GND

.. note::
   Use a **P0** header pin on nRF54LM20 (default **P0.03**, GPIOTE30). **P2.xx** is outside
   the GPIOTE-capable domain on this SoC and must not be used for sync.

Expansion header GPIO available on the dongles (other pins may be in use by LEDs/USB):

* nRF54LM20 dongle: **P1** 0–9 and 17–20, **P0** 3–9, **P2** 0–5
* nRF52840 dongle: **P0** 02, 09, 10, 13, 15, 17, 20, 22, 24, 29, 31; **P1** 00, 10, 13, 15

To use a different sync pin, change ``sync-gpios`` in the board overlay
(``boards/nrf54lm20dongle_nrf54lm20b_cpuapp.overlay``, ``boards/nrf52840dongle_nrf52840.overlay``,
or ``boards/nrf52840dk_nrf52840.overlay``).

.. note::
   When adding an overlay for a new board, keep ``hw-flow-control`` on the CDC ACM UART node.
   Without it, the USB CDC driver silently discards characters once its TX FIFO is full,
   which truncates capture lines in the middle during traffic bursts.

Wireshark extcap (multi-sniffer, one interface)
------------------------------------------------

``scripts/nrf802154_sniffer.py`` is a single extcap that auto-detects every connected
sniffer CDC port (MCUmgr/DFU ports are skipped). With one port connected it behaves like a
plain single-dongle sniffer; with two or more it also drives hardware time sync, using the
first detected port as sync master and the rest as slaves.

Install the extcap::

   mkdir -p ~/.local/lib/wireshark/extcap
   cp scripts/nrf802154_sniffer.py ~/.local/lib/wireshark/extcap/
   chmod +x ~/.local/lib/wireshark/extcap/nrf802154_sniffer.py

Requires ``pyserial`` (``pip install pyserial``).

In Wireshark, choose **nRF Sniffer for 802.15.4**, set the channel(s) and PHY per port, and
start capture. For two or more ports, use the **Master Port** and **Sync Interval [ms]**
options to pick which port sends ``sync master start <interval_ms>`` (the rest get
``sync slave <n>``); by default the first detected port is master.

Packets from the individual devices do not reach the host in timestamp order, because each
device buffers its output independently. The extcap therefore holds packets back briefly
(``REORDER_HOLD_S``, 0.25 s by default) and writes them sorted by their hardware
synchronized timestamp, so frames appear in Wireshark with a matching short delay.

bootloader - reboot the device to the bootloader
================================================

The ``bootloader`` command reboots the device in bootloader mode.

   .. parsed-literal::
      :class: highlight

      bootloader

The device reboots into bootloader mode, and the red LED starts pulsing.

.. note::
   The ``bootloader`` command is available only for the ``nrf52840dongle/nrf52840`` board.

Configuration
*************

|config|

Building and running
********************

.. |sample path| replace:: :file:`samples/peripheral/802154_sniffer`

.. include:: /includes/build_and_run.txt

.. _802154_sniffer_testing:

Testing the sample
==================

After programming the sample to your development kit, complete the following steps to test it:

1. Connect the development kit to the computer using a USB cable.
   Use the development kit's nRF USB port (**J3**).
   The kits are assigned serial ports.
   |serial_port_number_list|
#. |connect_terminal|
#. Switch to a radio channel with an ongoing radio traffic:

   .. parsed-literal::
      :class: highlight

      channel *23*

#. Start the capture process:

   .. parsed-literal::
      :class: highlight

      receive

   The **LED 1** will start blinking with shorter intervals.

#. If there is radio traffic on the selected channel, the sniffer should print the captured packets:

   .. parsed-literal::
      :class: highlight

      received: 49a85d41a5fffff4110f10270000369756e65619d09428a04b301951821db234460aa5ec4ff506631ef8adb22674683700 power: -39 lqi: 220 time: 15822687

   The **LED 4** will toggle its state when a frame is received.

#. Disable the capture:

   .. parsed-literal::
      :class: highlight

      sleep

   The **LED 1** will start blinking with longer intervals.

Dependencies
************

This sample uses the following `sdk-nrfxlib`_ libraries:

* :ref:`nrfxlib:mpsl`
* :ref:`nrfxlib:nrf_802154`

This sample uses the following |NCS| libraries:

* :ref:`dk_buttons_and_leds_readme`

This sample uses the following Zephyr libraries:

* :ref:`zephyr:kernel_api`:

  * :file:`include/zephyr/kernel.h`
  * :file:`include/zephyr/sys/util.h`

* :ref:`zephyr:ieee802154_interface`:

  * :file:`include/zephyr/net/ieee802154_radio.h`

* :ref:`zephyr:shell_api`:

  * :file:`include/zephyr/shell/shell.h`
  * :file:`include/zephyr/shell/shell_uart.h`
