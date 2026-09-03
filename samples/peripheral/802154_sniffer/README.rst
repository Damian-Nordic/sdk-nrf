.. _802154_sniffer:

IEEE 802.15.4 Sniffer
#####################

.. contents::
   :local:
   :depth: 2

The IEEE 802.15.4 Sniffer listens to a selected IEEE 802.15.4 channel, using either the 2.4 GHz O-QPSK with DSSS PHY or the 2 Mbps GFSK PHY, and integrates with the nRF 802.15.4 sniffer extcap for Wireshark.

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

      r *<data>* *<power>* *<lqi>* *<timestamp>*

* The ``<data>`` is a Base64 string representation of the received packet, without the FCS field.
* The ``<power>`` value is the signal power in dBm.
* The ``<lqi>`` value is the IEEE 802.15.4 Link Quality Indicator.
* The ``<timestamp>`` value is the absolute time of the received packet since the sniffer booted.

.. note::
   Earlier versions of the sample used a longer, hexadecimal format
   (``received: <data> power: <power> lqi: <lqi> time: <timestamp>``).
   The Wireshark script still accepts the old format, so it works with sniffers that run older
   firmware (but without multi-sniffer support).

sleep - stop capturing packets
==============================

The ``sleep`` command disables the radio and ends the receive process.

   .. parsed-literal::
      :class: highlight

      sleep

sync - synchronize several sniffers
===================================

When ``CONFIG_IEEE802154_SNIFFER_TIME_SYNC`` is enabled and the ``sniffer_sync`` devicetree node is present, the sample can emit hardware-timestamped sync pulses on a GPIO pin.

The primary device generates the pulses and reports ``sync role=primary seq=<n> t=<us>``:

   .. parsed-literal::
      :class: highlight

      sync primary start
      sync primary start *<interval_ms>*

The ``<interval_ms>`` argument is an integer in the range between 10 and 60000.
The lower bound leaves room for the pulse to be cleared before the next one is due.

A secondary device captures the pulses and reports ``sync role=secondary id=<id> edge=<n> t=<us>``:

   .. parsed-literal::
      :class: highlight

      sync secondary
      sync secondary *<id>*

The following command stops the synchronization:

   .. parsed-literal::
      :class: highlight

      sync stop

Connect the sync pin of every board together, plus a common ground.
The role is selected in software (``sync primary start`` or ``sync secondary``), so any of the connected boards can be the primary one.
The pin is defined by the ``sync-gpios`` property in the board overlay in the :file:`boards` directory:

* ``nrf54lm20dongle/nrf54lm20b/cpuapp`` - **P0.03**
* ``nrf52840dongle/nrf52840`` - **P0.02**
* ``nrf52840dk/nrf52840`` - **P0.03**

.. note::
   On the nRF54LM20, select the replacement pin from **P0** or **P1**, because a secondary device needs a GPIOTE channel to timestamp the pulse.
   The **P2** port has no ``gpiote-instance`` assigned in the devicetree and cannot capture the pulse.

.. note::
   When adding an overlay for a new board, include the ``hw-flow-control`` and ``tx-fifo-size`` properties from :file:`boards/cdc-acm-common.dtsi` on the CDC ACM UART node.
   The flow control flag only affects the polling write path, where the USB CDC driver otherwise discards characters once its TX FIFO fills.
   The FIFO is kept small on purpose, because it is drained in order and every queued byte delays the next sync report.

bootloader - reboot the device to the bootloader
================================================

The ``bootloader`` command reboots the device in bootloader mode.

   .. parsed-literal::
      :class: highlight

      bootloader

The device reboots into bootloader mode, and the red LED starts pulsing.

.. note::
   The ``bootloader`` command is available only for the ``nrf52840dongle/nrf52840`` board.

Capturing in Wireshark
**********************

The :file:`scripts/nrf802154_sniffer.py` script is a single extcap that auto-detects every connected sniffer CDC port and skips the MCUmgr, DFU, and bootloader interfaces exposed by the same device.
With one port connected it behaves like a plain single-device sniffer.
With two or more it also drives the hardware time synchronization, with one port acting as the sync primary and the rest as secondary ones.

Install the script like the `nRF Sniffer for 802.15.4`_ extcap.
It requires Python 3.8 or later and the ``pyserial`` package, which must be available to the Python interpreter that Wireshark uses to run the script:

.. code-block:: console

   pip install pyserial

In Wireshark, choose **nRF Sniffer for 802.15.4**, set the channel and the PHY for each port, and start the capture.
For two or more ports, use the **Primary Port** and **Sync Interval [ms]** options to pick which port receives ``sync primary start <interval_ms>``, while the remaining ports receive ``sync secondary <n>``.

Packets from the individual devices do not reach the host in timestamp order, because each device buffers its output independently.
The script therefore holds packets back briefly, 0.25 seconds by default, and writes them sorted by their synchronized timestamp, so frames appear in Wireshark with a matching short delay.

Showing the channel and the PHY of each frame
=============================================

With the **Out-Of-Band meta-data** option set to **IEEE 802.15.4 TAP**, the script tags every frame with the channel and the bit rate of the port that captured it.
The bit rate identifies the PHY, and is 250000 for the O-QPSK with DSSS PHY and 2000000 for the 2 Mbps GFSK PHY.
Both values are shown in the :guilabel:`IEEE 802.15.4 TAP` branch of the packet details pane, which makes it possible to tell apart the frames of ports configured differently, for example when the ports of a multi-device capture watch different channels.

Wireshark shows this information in the packet list only after you add a column for it.
Go to :guilabel:`Edit` > :guilabel:`Preferences` > :guilabel:`Appearance` > :guilabel:`Columns`, add an entry of the :guilabel:`Custom` type for each of the following fields, and confirm with :guilabel:`OK`:

* ``wpan-tap.ch_num`` - IEEE 802.15.4 channel.
* ``wpan-tap.bit_rate`` - PHY bit rate, in bits per second.

Both fields are also available as display filters, so ``wpan-tap.ch_num == 11`` limits the packet list to the frames captured on channel 11.

Configuration
*************

|config|

The following sample-specific Kconfig options are used in this sample (located in :file:`samples/peripheral/802154_sniffer/Kconfig`) :

.. options-from-kconfig::
   :show-type:

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

      r SahdQaX///QRDxAnAAA2l1bmVhnQlCigSzAZUYIdsjRGCqXsT/UGYx74rbImdGg= -39 220 15822687

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

* :ref:`zephyr:ring_buffers_v2`:

  * :file:`include/zephyr/sys/ring_buffer.h`

* :ref:`zephyr:ieee802154_interface`:

  * :file:`include/zephyr/net/ieee802154_radio.h`

* :ref:`zephyr:uart_api`:

  * :file:`include/zephyr/drivers/uart.h`

* :ref:`zephyr:shell_api`:

  * :file:`include/zephyr/shell/shell.h`
  * :file:`include/zephyr/shell/shell_uart.h`
