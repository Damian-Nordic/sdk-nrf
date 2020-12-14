.. _connectedhomeip_lock_sample

Connected Home over IP: Lock
############################

.. contents::
   :local:
   :depth: 2

The Connected Home over IP Lock sample demonstrates the usage of 
`CHIP <https://www.connectedhomeip.com/>`_ to build a door lock device with one
basic bolt. It works as a CHIP accessory, that is a device that can be paired
and controlled remotely over a CHIP network built on top of a low-power,
802.15.4 Thread network.

The sample uses buttons to test changing the lock and device states and LEDs to
show the state of these changes. You can use this example as a reference for
creating your own application.

Overview
********

The CHIP device that runs the lock application is controlled by the CHIP
controller device over the Thread protocol. By default, the CHIP device has
Thread disabled, and it should be paired with the CHIP controller over Bluetooth
LE and get configuration from it. Some actions required before establishing full
communication are described below.

The example also comes with a test mode, which allows to start Thread with the
default settings by pressing a button manually. However, this mode is not
CHIP-compliant and it does not guarantee that the device will be able to
communicate with the CHIP controller and other devices.

Bluetooth LE advertising
========================

To commission the device onto a CHIP network, the device must be discoverable
over Bluetooth LE. For security reasons, you must start Bluetooth LE advertising
manually after powering up the device by pressing **Button 4**.

Device commissioning information
================================

To start the commissioning procedure, the controller must get the commissioning
information from the CHIP device. The data payload, which includes the device
discriminator and setup PIN code, is encoded within a QR code, printed to the 
UART console, and shared using an NFC tag.

.. _chip_lock_sample_rendezvous:

Bluetooth LE rendezvous
=======================

In CHIP, the commissioning procedure (called rendezvous) is done over Bluetooth
LE between a CHIP device and the CHIP controller, where the controller has the
commissioner role. When the procedure is finished the device should be equipped
with all information needed to securely operate in the CHIP network.

Thread provisioning
-------------------

Last part of the rendezvous procedure, the provisioning operation, involves
sending the Thread network credentials from the CHIP controller to the CHIP
device. As a result, the device is able to join the Thread network and
communicate with other Thread devices in the network.

Requirements
************

The sample supports the following development kits:

.. table-from-rows:: /includes/sample_board_rows.txt
   :header: heading
   :rows: nrf52840dk_nrf52840

User Interface
**************

This section lists the User Interface elements that you can use to control and
monitor the state of the device. 

**LED 1**:
    shows the overall state of the device and its connectivity. The following
    states are possible:

    * *Short Flash On (50 ms on/950 ms off)* - The device is in the
      unprovisioned (unpaired) state and is waiting for a commissioning
      application to connect.
    * *Rapid Even Flashing (100 ms on/100 ms off)* - The device is in the
      unprovisioned state and a commissioning application is connected through
      Bluetooth LE.
    * *Short Flash Off (950ms on/50ms off)* - The device is fully
      provisioned, but does not yet have full Thread network or service
      connectivity.
    * *Solid On* - The device is fully provisioned and has full Thread
      network and service connectivity.

**LED 2**:
    simulates the lock bolt and shows the state of the lock. The following 
    states are possible:

    * *Solid On* - The bolt is extended and the door is locked.
    * *Off* - The bolt is retracted and the door is unlocked.
    * *Rapid Even Flashing (50 ms on/50 ms off during 2 s)* - The simulated
      bolt is in motion from one position to another.

**Button 1**:
    Pressing the button once initiates the factory reset of the device.

**Button 2**:
    Pressing the button once changes the lock state to the opposite one.

**Button 3**:
    Pressing the button once starts the Thread networking in the test mode
    using the default configuration.

**Button 4**:
    Pressing the button once starts the Bluetooth LE advertising for the
    predefined period of time.

**SEGGER J-Link USB port**:
    can be used to get logs from the device or communicate with it using the
    command-line interface.

**NFC port with antenna attached**:
    can be used to start the :ref:`rendezvous<chip_lock_sample_rendezvous>`
    by providing the commissioning information from the CHIP device in a data
    payload shared using NFC.

Building and running
********************

.. |sample path| replace:: :file:`samples/connectedhomeip/lock`

.. include:: /includes/build_and_run.txt

Testing the example
===================

Testing lock state changes
--------------------------

After building the sample and programming it to your development kit, test its
basic features by performing the following steps:

#. Observe that initially, **LED 2** is lit which means that the door is closed.
#. Press **Button 2** to unlock the door. **LED 2** is blinking while the door
   is opening. After approximately 2 seconds, **LED 2** gets turned off
   permanently.
#. Press **Button 2** once more to lock the door again.
#. Press **Button 1** to initiate factory reset of the device. The device is 
   rebooted after having all its settings erased.

Commissioning and remote control
--------------------------------

You can use
`Android CHIPTool <https://github.com/project-chip/connectedhomeip/tree/master/src/android/CHIPTool>`_
as the CHIP controller to commission and control the lock device. Read
`Commissioning nRF Connect Accessory using Android CHIPTool <https://github.com/project-chip/connectedhomeip/blob/master/docs/guides/nrfconnect_android_commissioning.md>`_
tutorial to learn how to set up testing environment and remotely control the sample over a CHIP network.

Sample output
=============

The sample logging output can be observed through a serial port.
For more details, see :ref:`putty`.

Dependencies
============

This sample uses Connected Home over IP library which includes |NCS| platform
integration layer:

* `Connected Home over IP <https://github.com/project-chip/connectedhomeip>`_

In addition, the sample uses the following |NCS| components:

* :ref:`dk_buttons_and_leds_readme`
* :ref:`nfc_uri`
* :ref:`lib_nfc_t2t`

The sample depends on the following Zephyr libraries:

* :ref:`zephyr:logging_api`
* :ref:`zephyr:kernel_api`
