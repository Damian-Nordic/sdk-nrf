#!/usr/bin/env python3
#
# Copyright (c) 2019 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

"""Wireshark extcap presenting several synchronized nRF 802.15.4 sniffers as a
single interface with one merged timeline.

Based on the extcap script of the nRF Sniffer for 802.15.4.
"""

import ctypes
import os
import sys
import re
import signal
import struct
import time
import uuid
from queue import Empty
from argparse import ArgumentParser
from enum import IntEnum
from binascii import a2b_hex
from base64 import b64decode
from serial import Serial, SerialException
from serial.tools.list_ports import comports
from multiprocessing import Event, Queue, Process, freeze_support, parent_process
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple, Union

NORDICSEMI_VID = 0x1915
SNIFFER_802154_PID = 0x154B

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

QUEUE_MAXSIZE = 4096
SERIAL_LINE_MAX = 512
SERIAL_BUFFER_MAX = 65536

# Windows frees a port some time after the process holding it is killed, so every
# open is retried until one of these deadlines.
PORT_OPEN_TIMEOUT_S = 3.0
PORT_STOP_TIMEOUT_S = 1.5

# Interval between the liveness checks the extcap and its readers make.
LIVENESS_POLL_S = 0.5

# Deadline for every reader to open its port. The pulse train starts only then,
# so that the first pulse reaches all of them.
READERS_READY_TIMEOUT_S = 8.0

# Packets from the individual readers arrive out of timestamp order, so they are
# held back this long and then written out sorted.
REORDER_HOLD_S = 0.25
REORDER_MAX_PACKETS = 4096

# Bursts push the sync reports behind the capture data already queued in the USB
# pipe, so reports arrive late or go missing. The offset in use then goes stale
# and drifts until the next reported edge re-locks it, so the capture repairs
# itself and only a prolonged silence is worth aborting on. That delay is bounded
# by the buffer sizes rather than by the pulse interval, hence a constant slack.
SYNC_TIMEOUT_INTERVALS = 3
SYNC_TIMEOUT_SLACK_S = 5.0

# Range the firmware accepts for "sync primary start".
SYNC_INTERVAL_MIN_MS = 10
SYNC_INTERVAL_MAX_MS = 60000

SYNC_PRIMARY_REGEX = r"sync role=primary seq=(\d+) t=(\d+)"
SYNC_SECONDARY_REGEX = r"sync role=secondary id=\d+ edge=(\d+) t=(\d+)"


class _DEVPROPKEY(ctypes.Structure):
    """Device property key, the one SetupAPI structure pyserial does not declare."""

    _fields_ = [("fmtid", ctypes.c_ubyte * 16), ("pid", ctypes.c_ulong)]


class _JOB_BASIC_LIMITS(ctypes.Structure):
    _fields_ = [("per_process_user_time", ctypes.c_int64),
                ("per_job_user_time", ctypes.c_int64),
                ("limit_flags", ctypes.c_ulong),
                ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t),
                ("active_process_limit", ctypes.c_ulong),
                ("affinity", ctypes.c_size_t),
                ("priority_class", ctypes.c_ulong),
                ("scheduling_class", ctypes.c_ulong)]


class _JOB_EXTENDED_LIMITS(ctypes.Structure):
    """Extended limits, the only form in which the kill-on-close flag is accepted."""

    _fields_ = [("basic_limits", _JOB_BASIC_LIMITS), ("io_counters", ctypes.c_uint64 * 6),
                ("process_memory_limit", ctypes.c_size_t),
                ("job_memory_limit", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t),
                ("peak_job_memory", ctypes.c_size_t)]


# Serial port device class, and the property Device Manager shows as "Bus reported
# device description". For a composite device it holds the USB interface string,
# which pyserial reports as ListPortInfo.interface on Linux only. Its registry
# copy needs administrator rights, so it is read through the PnP service.
GUID_DEVCLASS_PORTS = "4d36e978-e325-11ce-bfc1-08002be10318"
DEVPKEY_BUS_REPORTED_DESC = "540b947e-8b40-45bc-a8a2-6a0b894cbda2", 4
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
FRIENDLY_NAME_PORT_REGEX = re.compile(r"\((COM\d+)\)")


class Win32Support:
    """Windows-only helpers, each a no-op on other platforms.

    Windows reports no USB interface label through pyserial, does not signal a
    stopped capture, and leaves the children of a terminated process running.
    """

    _ports = None
    _kernel32 = None
    _winapi = None
    _ports_guid = None
    _bus_desc_key = None
    _job = None
    _loaded = False

    @classmethod
    def _load(cls) -> bool:
        if not cls._loaded:
            cls._loaded = True
            if IS_WINDOWS:
                try:
                    cls._bind()
                except Exception:
                    cls._ports = cls._kernel32 = cls._winapi = None
        return cls._kernel32 is not None

    @classmethod
    def _bind(cls) -> None:
        # pyserial's Windows backend declares the SetupAPI structures and
        # functions used below.
        import _winapi

        from serial.tools import list_ports_windows as ports

        handle, dword = ctypes.c_void_p, ctypes.c_ulong
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Declare the handles: the default marshalling truncates them to a C int.
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = handle
        kernel32.SetInformationJobObject.argtypes = [handle, dword, ctypes.c_void_p, dword]
        kernel32.AssignProcessToJobObject.argtypes = [handle, handle]
        ports.setupapi.SetupDiGetDevicePropertyW.argtypes = [
            ports.HDEVINFO, ports.PSP_DEVINFO_DATA, ctypes.POINTER(_DEVPROPKEY),
            ctypes.POINTER(dword), ctypes.c_void_p, dword, ctypes.POINTER(dword), dword]

        key_guid, key_pid = DEVPKEY_BUS_REPORTED_DESC
        cls._bus_desc_key = _DEVPROPKEY(
            (ctypes.c_ubyte * 16)(*uuid.UUID(key_guid).bytes_le), key_pid)
        cls._ports_guid = ports.GUID.from_buffer_copy(
            uuid.UUID(GUID_DEVCLASS_PORTS).bytes_le)
        cls._ports, cls._kernel32, cls._winapi = ports, kernel32, _winapi

    @classmethod
    def port_labels(cls) -> dict:
        """Map each present COM port onto the label Device Manager shows for it."""
        if not cls._load():
            return {}

        ports = cls._ports
        try:
            # pyserial's binding raises rather than returning an invalid handle.
            devices = ports.SetupDiGetClassDevs(ctypes.byref(cls._ports_guid), None, None,
                                                ports.DIGCF_PRESENT)
        except OSError:
            return {}

        labels: dict = {}
        name = ctypes.create_unicode_buffer(512)
        description = ctypes.create_unicode_buffer(512)
        description_type = ctypes.c_ulong()
        devinfo = ports.SP_DEVINFO_DATA()
        devinfo.cbSize = ctypes.sizeof(devinfo)
        index = 0

        try:
            while ports.SetupDiEnumDeviceInfo(devices, index, ctypes.byref(devinfo)):
                index += 1
                # The friendly name is localized, the "(COMx)" it ends with is not.
                if not ports.SetupDiGetDeviceRegistryProperty(
                        devices, ctypes.byref(devinfo), ports.SPDRP_FRIENDLYNAME, None,
                        ctypes.byref(name), ctypes.sizeof(name), None):
                    continue
                match = FRIENDLY_NAME_PORT_REGEX.search(name.value)
                if match and ports.setupapi.SetupDiGetDevicePropertyW(
                        devices, ctypes.byref(devinfo), ctypes.byref(cls._bus_desc_key),
                        ctypes.byref(description_type), ctypes.byref(description),
                        ctypes.sizeof(description), None, 0):
                    labels[match.group(1)] = description.value
        finally:
            ports.SetupDiDestroyDeviceInfoList(devices)

        return labels

    @classmethod
    def tie_child_to_extcap(cls, pid: Optional[int]) -> None:
        """Put a reader in a job object that the OS destroys with this process.

        A terminated extcap would otherwise leave its readers holding the ports.
        """
        if pid is None or not cls._load():
            return

        if cls._job is None:
            limits = _JOB_EXTENDED_LIMITS()
            limits.basic_limits.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            job = cls._kernel32.CreateJobObjectW(None, None)
            if not job or not cls._kernel32.SetInformationJobObject(
                    job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits),
                    ctypes.sizeof(limits)):
                return
            # Keep the handle: the kill happens when the last one is closed.
            cls._job = job

        try:
            child = cls._winapi.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        except OSError:
            return
        try:
            cls._kernel32.AssignProcessToJobObject(cls._job, child)
        finally:
            cls._winapi.CloseHandle(child)

    @classmethod
    def open_launcher(cls):
        """Open a handle to the process that started this extcap, or return None.

        Taken up front, so that a recycled pid cannot make it look alive later.
        """
        if not cls._load():
            return None
        try:
            return cls._winapi.OpenProcess(cls._winapi.SYNCHRONIZE, False, os.getppid())
        except OSError:
            return None

    @classmethod
    def has_exited(cls, process_handle) -> bool:
        if process_handle is None:
            return False
        return cls._winapi.WaitForSingleObject(process_handle, 0) != cls._winapi.WAIT_TIMEOUT


class MacOSSupport:
    """macOS-only helpers, each a no-op on other platforms.

    A composite device names its USB functions, not the interfaces each function
    groups. A CDC ACM function is named on its communication interface, while
    the serial port belongs to the data interface next to it. pyserial reports
    neither name, so both are read from IOKit here.
    """

    # IOKit classes these services as IOUSBInterface but matches them by the
    # IOUSBHostInterface name. Without a match no port gets a label, and every
    # device falls back to its first port.
    INTERFACE_SERVICE_TYPE = "IOUSBHostInterface"

    _ports = None
    _loaded = False

    @classmethod
    def _load(cls) -> bool:
        if not cls._loaded:
            cls._loaded = True
            if IS_MACOS:
                try:
                    # pyserial's macOS backend declares the IOKit bindings used below.
                    from serial.tools import list_ports_osx as ports

                    cls._ports = ports
                except Exception:
                    cls._ports = None
        return cls._ports is not None

    @classmethod
    def _int_property(cls, service, name):
        return cls._ports.get_int_property(service, name, cls._ports.kCFNumberSInt32Type)

    @classmethod
    def _interface_names(cls) -> dict:
        """Map each named USB interface onto its name.

        The key is the device location ID and the interface number, the pair a
        serial port is traced back to.
        """
        names: dict = {}

        for service in cls._ports.GetIOServicesByType(cls.INTERFACE_SERVICE_TYPE):
            location = cls._int_property(service, "locationID")
            number = cls._int_property(service, "bInterfaceNumber")
            name = cls._ports.get_string_property(service, "USB Interface Name")
            if name and location is not None and number is not None:
                names[(location, number)] = name

        return names

    @classmethod
    def port_labels(cls) -> dict:
        """Map each present serial port onto the name of its USB function."""
        if not cls._load():
            return {}

        ports = cls._ports
        labels: dict = {}

        try:
            names = cls._interface_names()

            for service in ports.GetIOServicesByType("IOSerialBSDClient"):
                device = ports.get_string_property(service, "IOCalloutDevice")
                interface = ports.GetParentDeviceByType(service, "IOUSBInterface")
                if not device or not interface:
                    continue
                location = cls._int_property(interface, "locationID")
                number = cls._int_property(interface, "bInterfaceNumber")
                if number is None:
                    continue
                # A CDC ACM function is named on the communication interface that
                # precedes the data interface the port belongs to.
                name = names.get((location, number)) or names.get((location, number - 1))
                if name:
                    labels[device] = name
        except Exception:
            return {}

        return labels


@dataclass
class SnifferPacket:
    port_id: str
    content: bytes
    timestamp: int
    lqi: int
    rssi: int


@dataclass
class SyncPrimaryEvent:
    seq: int
    t: int


@dataclass
class SyncSecondaryEvent:
    port_id: str
    edge: int
    t: int


@dataclass
class ReaderReady:
    port_id: str


@dataclass
class ExitEvent:
    pass


@dataclass
class SnifferPortConfig:
    port: str
    channel: int
    phy: str
    role: str


class DLT(IntEnum):
    DLT_IEEE802_15_4_NOFCS = 230
    DLT_IEEE802_15_4_TAP = 283


def _frame_from_compact(match: "re.Match", port_id: str) -> SnifferPacket:
    return SnifferPacket(
        port_id=port_id,
        content=b64decode(match.group(1)),
        rssi=int(match.group(2)),
        lqi=int(match.group(3)),
        timestamp=int(match.group(4)),
    )


def _frame_from_verbose(match: "re.Match", port_id: str) -> SnifferPacket:
    hex_psdu = match.group(1)
    if len(hex_psdu) < 4:
        raise ValueError("frame too short")
    return SnifferPacket(
        port_id=port_id,
        content=a2b_hex(hex_psdu[:-4]),
        rssi=int(match.group(2)),
        lqi=int(match.group(3)),
        timestamp=int(match.group(4)),
    )


# Newest format first. The older entry lets this script drive a sniffer whose
# firmware has not been updated yet.
FrameBuilder = Callable[["re.Match", str], SnifferPacket]
FRAME_FORMATS: Tuple[Tuple["re.Pattern", FrameBuilder], ...] = (
    (re.compile(r"\Ar ([A-Za-z0-9+/]+={0,2}) (-?\d+) (\d+) (\d+)"), _frame_from_compact),
    (
        re.compile(
            r"received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(-?\d+)"
        ),
        _frame_from_verbose,
    ),
)


class TimeSyncHub:
    """Turns the reported sync edges into a per-port offset to the primary clock."""

    PENDING_MAX = 256

    def __init__(self, primary_port: str):
        self.primary_port = primary_port
        self.offsets = {primary_port: 0}
        self.pending_primary: dict = {}
        self.pending_secondary: dict = {}
        self.first_local_us: Optional[int] = None
        self.first_global_us = 0
        self.anchor_error: Optional[str] = None
        self.first_seq: Optional[int] = None
        self.first_edges: dict = {}

    @classmethod
    def _bounded_insert(cls, store: dict, key: int, value: int) -> None:
        store[key] = value
        if len(store) > cls.PENDING_MAX:
            del store[min(store)]

    def _check_anchor(self, port_id: str) -> None:
        """Refuse a capture in which the devices disagree on the first pulse.

        A device that also counted a pulse of an earlier train pairs with a pulse
        of that number just as constantly, only whole intervals out.
        """
        if self.anchor_error is not None or self.first_seq is None:
            return

        first_edge = self.first_edges[port_id]
        if first_edge == self.first_seq:
            return

        self.anchor_error = (
            f"{port_id} counted pulse {first_edge} first while {self.primary_port} "
            f"counted pulse {self.first_seq} first, so the devices do not agree on which "
            f"pulse is the first one: every timestamp of {port_id} would be "
            f"{abs(first_edge - self.first_seq)} pulse intervals away from the others. "
            "Either something else is driving the sync line, or the first report of a "
            "device was lost. Restart the capture."
        )

    def handle_primary(self, seq: int, t_primary: int) -> None:
        if self.first_seq is None:
            self.first_seq = seq
            for port_id in self.first_edges:
                self._check_anchor(port_id)

        self._bounded_insert(self.pending_primary, seq, t_primary)

        for port_id, edges in self.pending_secondary.items():
            t_secondary = edges.pop(seq, None)
            if t_secondary is not None:
                self.offsets[port_id] = t_primary - t_secondary

    def handle_secondary(self, port_id: str, edge: int, t_secondary: int) -> None:
        if port_id not in self.first_edges:
            self.first_edges[port_id] = edge
            self._check_anchor(port_id)

        t_primary = self.pending_primary.get(edge)
        if t_primary is not None:
            self.offsets[port_id] = t_primary - t_secondary
            return

        # The readers are separate processes, so a secondary edge can overtake
        # the matching primary line. Buffer it instead of dropping it.
        self._bounded_insert(self.pending_secondary.setdefault(port_id, {}), edge, t_secondary)

    def capture_timestamp(self, port_id: str, t_local: int) -> Optional[int]:
        """Map a device timestamp onto wall clock time, or None before the lock."""
        if port_id not in self.offsets:
            return None

        t_global = t_local + self.offsets[port_id]
        if self.first_local_us is None:
            self.first_local_us = int(time.time() * 10**6)
            self.first_global_us = t_global

        return self.first_local_us + (t_global - self.first_global_us)


class PcapFormatter:
    @staticmethod
    def pcap_header(dlt: DLT) -> bytes:
        return struct.pack("<LHHIILL", 0xA1B2C3D4, 2, 4, 0, 0, 0x000000FF, dlt)

    @staticmethod
    def pcap_packet(frame: bytes, dlt: DLT, channel: int, rssi: int, lqi: int,
                    timestamp: int) -> bytes:
        tap = dlt == DLT.DLT_IEEE802_15_4_TAP
        caplength = len(frame) + (28 if tap else 0)

        pcap = bytearray()
        pcap += struct.pack("<II", (timestamp // 1000000) & 0xFFFFFFFF,
                            (timestamp % 1000000) & 0xFFFFFFFF)
        pcap += struct.pack("<LL", caplength, caplength)

        if tap:
            pcap += struct.pack("<HH", 0, 28)
            pcap += struct.pack("<HHf", 1, 4, rssi)
            pcap += struct.pack("<HHHH", 3, 3, channel, 0)
            pcap += struct.pack("<HHI", 10, 1, lqi)

        pcap += frame
        return bytes(pcap)


class SerialPortScanner:
    @staticmethod
    def is_sniffer_port(port, extra_label: str) -> bool:
        if port.vid != NORDICSEMI_VID or port.pid != SNIFFER_802154_PID:
            return False

        # Reject the interfaces known not to be a sniffer, rather than require the
        # sniffer label: a device with no recognizable label stays usable.
        label = " ".join(
            filter(None, [port.interface, port.description, port.product, port.manufacturer,
                          extra_label])
        ).lower()
        return not any(token in label for token in ("mcumgr", "dfu", "bootloader"))

    @staticmethod
    def device_key(port) -> str:
        """Identify the physical device a serial port belongs to.

        The USB topology path is shared by every interface of a device and is
        unique per device, which a serial number is only as long as no two boards
        were flashed with the same one.
        """
        if port.location:
            # On Linux the location ends with the interface it describes.
            return port.location.split(":")[0]

        return port.serial_number or port.device

    @staticmethod
    def list_ports() -> List[str]:
        # pyserial fills in ListPortInfo.interface on Linux only, hence the labels
        # read separately on Windows and macOS. Sorting the port objects rather
        # than their names orders COM10 after COM9, puts the capture interface
        # ahead of the extra ones, and the position in this list addresses the
        # port everywhere else.
        labels = Win32Support.port_labels() or MacOSSupport.port_labels()
        ports: List[str] = []
        devices = set()

        for port in sorted(comports()):
            if not SerialPortScanner.is_sniffer_port(port, labels.get(port.device, "")):
                continue
            # A device exposing an extra interface that carries no recognizable
            # label would otherwise show up as several capture interfaces.
            key = SerialPortScanner.device_key(port)
            if key in devices:
                continue
            devices.add(key)
            ports.append(port.device)

        return ports


class PacketParser:
    @staticmethod
    def parse_line(value: Union[bytes, bytearray], port_id: str = ""):
        text = value.decode("utf-8", errors="ignore")

        for pattern, build_frame in FRAME_FORMATS:
            m = pattern.search(text)
            if m:
                packet = build_frame(m, port_id)
                if not packet.content:
                    raise ValueError("empty frame")
                return packet

        m = re.search(SYNC_PRIMARY_REGEX, text)
        if m:
            return SyncPrimaryEvent(seq=int(m.group(1)), t=int(m.group(2)))

        m = re.search(SYNC_SECONDARY_REGEX, text)
        if m:
            return SyncSecondaryEvent(port_id=port_id, edge=int(m.group(1)), t=int(m.group(2)))

        raise ValueError("unrecognized serial line")


class SnifferProcess:
    @staticmethod
    def _enqueue(queue: Queue, item) -> None:
        """Queue an item, never at the cost of a sync or exit event."""
        try:
            queue.put_nowait(item)
            return
        except Exception:
            pass

        if isinstance(item, SnifferPacket):
            return

        try:
            queue.get_nowait()
        except Exception:
            pass
        try:
            queue.put_nowait(item)
        except Exception:
            pass

    @staticmethod
    def _extcap_alive() -> bool:
        """Tell whether the extcap that started this reader is still there.

        Nothing else stops a reader, so a terminated extcap would leave it running
        with the serial port open.
        """
        launcher = parent_process()
        return launcher is None or launcher.is_alive()

    @staticmethod
    def serial_reader(serial_port: str, queue: Queue, port_id: str, start_gate,
                      start_command: Optional[bytes] = None) -> None:
        reader_port = port_id or serial_port
        next_liveness_poll = 0.0
        announced = False

        while SnifferProcess._extcap_alive():
            try:
                serial = SnifferConfig.open_port(serial_port)
            except (SerialException, OSError):
                continue

            if not announced:
                announced = True
                SnifferProcess._enqueue(queue, ReaderReady(reader_port))

                # Start the train from here, on the first open only: restarting it
                # after a reconnect would renumber the primary pulses while the
                # edge counters of the secondary devices keep running.
                if start_command is not None:
                    while not start_gate.wait(LIVENESS_POLL_S):
                        if not SnifferProcess._extcap_alive():
                            serial.close()
                            return
                    try:
                        serial.write(start_command + b"\r\n")
                        serial.flush()
                    except Exception:
                        pass

            buffer = bytearray()

            while True:
                try:
                    now = time.monotonic()
                    if now >= next_liveness_poll:
                        next_liveness_poll = now + LIVENESS_POLL_S
                        if not SnifferProcess._extcap_alive():
                            break

                    # Serial.readline() issues one read() syscall per byte, which
                    # cannot keep up with the 2 Mbit/s PHY.
                    chunk = serial.read(max(1, serial.in_waiting))
                    if not chunk:
                        continue

                    buffer.extend(chunk)
                    if b"\n" not in chunk:
                        if len(buffer) > SERIAL_BUFFER_MAX:
                            del buffer[:-SERIAL_LINE_MAX]
                        continue

                    lines = buffer.split(b"\n")
                    buffer = bytearray(lines.pop())

                    for line in lines:
                        try:
                            item = PacketParser.parse_line(line, reader_port)
                        except ValueError:
                            continue

                        SnifferProcess._enqueue(queue, item)
                except Exception:
                    break

            try:
                serial.close()
            except Exception:
                pass

    @staticmethod
    def control_reader(control_in: str, queue: Queue) -> None:
        with open(control_in, "rb", 0) as control_in_fifo:
            try:
                while control_in_fifo.read(1):
                    pass
            except Exception:
                pass
            SnifferProcess._enqueue(queue, ExitEvent())


class SnifferConfig:
    @staticmethod
    def open_port(port: str, timeout_s: float = PORT_OPEN_TIMEOUT_S,
                  exclusive: bool = True) -> Serial:
        """Open a port, retrying until a holder on its way out has released it.

        A reader killed with the previous capture keeps the port claimed until its
        process is fully torn down.
        """
        # Windows has no shared serial port, and pyserial rejects exclusive=False
        # there rather than ignoring it.
        claim = None if IS_WINDOWS else exclusive
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                return Serial(port, exclusive=claim, timeout=0.05)
            except (SerialException, OSError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    @staticmethod
    def send_best_effort(port: str, *commands: bytes) -> None:
        """Send commands to a device, ignoring one that is gone or busy."""
        try:
            with SnifferConfig.open_port(port, PORT_STOP_TIMEOUT_S, exclusive=False) as serial:
                SnifferConfig._send(serial, b"", *commands)
        except (SerialException, OSError):
            pass

    @staticmethod
    def _drain(serial: Serial, limit: int = 65536, max_seconds: float = 0.25) -> None:
        """Drain pending data, bounded by time as well as by size."""
        drained = 0
        deadline = time.monotonic() + max_seconds
        while drained < limit and time.monotonic() < deadline:
            chunk = serial.read(min(4096, limit - drained))
            if not chunk:
                break
            drained += len(chunk)

    @staticmethod
    def _send(serial: Serial, *commands: bytes, settle: float = 0.0) -> None:
        for command in commands:
            serial.write(command + b"\r\n")
            serial.flush()
            if settle:
                time.sleep(settle)
            SnifferConfig._drain(serial)

    @staticmethod
    def configure_sniffer(port: str, channel: int, phy: str = "250k",
                          extra_commands: Optional[List[bytes]] = None):
        with SnifferConfig.open_port(port) as serial:
            serial.reset_input_buffer()
            # "sync stop" is repeated because the first one can drown in the
            # pulse reports of a primary device left running by a previous capture.
            SnifferConfig._send(serial, b"", b"sync stop", b"sleep",
                                b"shell echo off", b"sync stop")

            for command in extra_commands or []:
                SnifferConfig._send(serial, command)

            # The PHY goes first because changing it can reset the channel.
            SnifferConfig._send(serial, b"phy " + (phy or "250k").encode(), settle=0.05)
            SnifferConfig._send(serial, b"channel " + str(channel).encode(), settle=0.05)
            SnifferConfig._send(serial, b"receive")


class MultiSnifferEngine:
    def __init__(self):
        self.queue = Queue(maxsize=QUEUE_MAXSIZE)
        self.processes: List[Process] = []
        self.ports_config: List[SnifferPortConfig] = []
        self.config_by_port: dict = {}
        # Assigned by start_capture(), before any of the readers can produce.
        self.sync: TimeSyncHub
        self.dlt = DLT.DLT_IEEE802_15_4_TAP
        self._fatal_error: Optional[str] = None
        self._sync_fatal_s = 0.0
        self._last_sync_seen: dict = {}
        self._sync_seen: set = set()
        self._last_pcap_ts_us = 0
        self._pending: List[tuple] = []
        self._stopped = False
        self._launcher = None
        self._next_liveness_poll = 0.0
        # Assigned by start_capture(), before any reader can wait on it.
        self._sync_gate = None

    def _pcap_timestamp_us(self, ts_us: int) -> int:
        """Guard against equal or out-of-order timestamps left after reordering."""
        ts_us = max(0, int(ts_us))
        if ts_us <= self._last_pcap_ts_us:
            ts_us = self._last_pcap_ts_us + 1
        self._last_pcap_ts_us = ts_us
        return ts_us

    def _flush_pending(self, fifo_out, force: bool = False) -> None:
        """Write out the packets older than the hold-back window."""
        if not self._pending:
            return

        count = len(self._pending)
        idx = count
        if not force:
            cutoff = time.monotonic() - REORDER_HOLD_S
            idx = 0
            while idx < count and self._pending[idx][1] <= cutoff:
                idx += 1
            idx = max(idx, count - REORDER_MAX_PACKETS)

        if idx <= 0:
            return

        ready = self._pending[:idx]
        del self._pending[:idx]
        ready.sort(key=lambda item: item[0])

        for ts_us, _arrival, channel, content, rssi, lqi in ready:
            fifo_out.write(PcapFormatter.pcap_packet(content, self.dlt, channel, rssi, lqi,
                                                     self._pcap_timestamp_us(ts_us)))

    def _handle_packet(self, packet: SnifferPacket) -> None:
        config = self.config_by_port.get(packet.port_id)
        if config is None:
            return

        ts_us = self.sync.capture_timestamp(packet.port_id, packet.timestamp)
        if ts_us is None:
            return

        self._pending.append((ts_us, time.monotonic(), config.channel, packet.content,
                              packet.rssi, packet.lqi))

    def _stop(self):
        # Reached from the capture loop, from a signal handler and from the exit
        # path of start_capture, in any order.
        if self._stopped:
            return
        self._stopped = True

        for process in self.processes:
            process.kill()
        for process in self.processes:
            # Reap every reader before reopening the devices below: a signalled
            # reader still holds its port.
            process.join(timeout=2.0)
        self.processes = []

        # The primary device first, so the pulse train stops before the
        # secondary devices are released.
        for config in sorted(self.ports_config, key=lambda c: c.role != "primary"):
            SnifferConfig.send_best_effort(config.port, b"sync stop", b"sleep",
                                          b"shell echo on")

    def _start_sync_watchdog(self, sync_interval_ms: int) -> None:
        interval_s = max(sync_interval_ms, 1) / 1000.0
        self._sync_fatal_s = interval_s * SYNC_TIMEOUT_INTERVALS + SYNC_TIMEOUT_SLACK_S
        now = time.monotonic()
        self._last_sync_seen = {cfg.port: now for cfg in self.ports_config}
        self._sync_seen.clear()

    def _note_sync(self, port_id: str) -> None:
        if port_id in self._last_sync_seen:
            self._last_sync_seen[port_id] = time.monotonic()
            self._sync_seen.add(port_id)

    def _check_sync_watchdog(self) -> None:
        if self._fatal_error is not None or self._sync_fatal_s <= 0:
            return

        now = time.monotonic()
        for port_id, last_seen in self._last_sync_seen.items():
            silent_s = now - last_seen
            if silent_s <= self._sync_fatal_s:
                continue

            if port_id in self._sync_seen:
                cause = "The sync line is broken or the device stopped responding"
            else:
                cause = ("The device never reported one, so its firmware most likely "
                         "predates hardware time sync")
            self._fatal_error = (
                f"{port_id} reported no sync pulse for {silent_s:.1f} s "
                f"(limit {self._sync_fatal_s:.1f} s). {cause}, so the merged timeline "
                "can no longer be trusted. Check the firmware and the sync wiring, "
                "then restart the capture."
            )
            return

    def _abort_if_fatal(self, fifo_out) -> None:
        if self._fatal_error is None:
            return

        self._flush_pending(fifo_out, force=True)
        fifo_out.flush()
        # Wireshark surfaces anything written to stderr as a capture error.
        sys.stderr.write(f"nRF multi sniffer: {self._fatal_error}\n")
        sys.stderr.flush()
        self._stop()
        sys.exit(1)

    def stop_and_exit(self, *args, **kwargs):
        self._stop()
        sys.exit(0)

    def _capture_abandoned(self) -> bool:
        """Tell whether the process that started this extcap has exited.

        That launcher owns the read end of the fifo, and on Windows its exit is the
        only notice: no SIGTERM, and no control pipes without a toolbar.
        """
        if self._launcher is None:
            return False

        now = time.monotonic()
        if now < self._next_liveness_poll:
            return False
        self._next_liveness_poll = now + LIVENESS_POLL_S

        return Win32Support.has_exited(self._launcher)

    def _configure_ports(self) -> None:
        """Silence the sync line, then arm every secondary device.

        The primary is started later, from its own reader, once every reader is
        listening.
        """
        # A pulse train left over from an earlier capture would be counted by the
        # secondaries as they are armed, while the new primary numbers its pulses
        # from the start again, leaving the counters whole intervals apart. The
        # second "sync stop" can be needed because the first one drowns in the
        # pulse reports of a device that is still running.
        if len(self.ports_config) > 1:
            for cfg in self.ports_config:
                SnifferConfig.send_best_effort(cfg.port, b"sync stop", b"sync stop")

        for index, cfg in enumerate(self.ports_config):
            extra = [f"sync secondary {index}".encode()] if cfg.role == "secondary" else None
            SnifferConfig.configure_sniffer(cfg.port, cfg.channel, cfg.phy, extra)

    def _spawn_readers(self, control_in: Optional[str], sync_interval_ms: int) -> None:
        """Start one reader per port, plus the control pipe watcher.

        The primary reader is handed the command that starts the pulse train, to
        issue it on the port it already holds. A lone sniffer needs no train.
        """
        start_command = (b"sync primary start " + str(sync_interval_ms).encode()
                         if len(self.ports_config) > 1 else None)

        for cfg in self.ports_config:
            self.processes.append(Process(
                target=SnifferProcess.serial_reader,
                args=(cfg.port, self.queue, cfg.port, self._sync_gate,
                      start_command if cfg.role == "primary" else None),
                daemon=True))

        # The control pipe is the portable way to notice that Wireshark went
        # away; signal handling is unreliable on Windows.
        if control_in:
            self.processes.append(Process(target=SnifferProcess.control_reader,
                                          args=(control_in, self.queue), daemon=True))

        for process in self.processes:
            process.start()
            Win32Support.tie_child_to_extcap(process.pid)

    def _await_readers(self) -> bool:
        """Wait until every reader has its port open.

        A reader still starting up would miss the first pulse, leaving its device
        numbering shifted against the primary for the rest of the capture.
        """
        pending = {cfg.port for cfg in self.ports_config}
        deadline = time.monotonic() + READERS_READY_TIMEOUT_S

        while pending and time.monotonic() < deadline:
            if self._capture_abandoned():
                return False

            try:
                item = self.queue.get(timeout=0.2)
            except Empty:
                continue

            if isinstance(item, ReaderReady):
                pending.discard(item.port_id)
            elif isinstance(item, ExitEvent):
                return False
            # Anything else is capture data from before the first pulse, which has
            # no merged timeline to be placed on yet.

        if pending:
            self._fatal_error = (
                f"{', '.join(sorted(pending))} did not start reading within "
                f"{READERS_READY_TIMEOUT_S:.0f} s, so the first sync pulse cannot be "
                "shared by every device. Check that no other program is holding the port."
            )
        return not pending

    def start_capture(self, fifo: str, ports_config: List[SnifferPortConfig],
                      metadata: Optional[str] = None, control_in: Optional[str] = None,
                      sync_interval_ms: int = 100):
        primaries = [cfg for cfg in ports_config if cfg.role == "primary"]
        if len(primaries) != 1:
            sys.stderr.write(
                "nRF multi sniffer: expected exactly one primary port, "
                f"found {len(primaries)}\n")
            return

        paired = len(ports_config) > 1
        self.ports_config = ports_config
        self.config_by_port = {cfg.port: cfg for cfg in ports_config}
        self.sync = TimeSyncHub(primaries[0].port)
        self.dlt = (DLT.DLT_IEEE802_15_4_TAP if metadata == "ieee802154-tap"
                    else DLT.DLT_IEEE802_15_4_NOFCS)
        self._fatal_error = None
        self._last_pcap_ts_us = 0
        self._pending.clear()
        self._stopped = False
        self._next_liveness_poll = 0.0
        self._launcher = Win32Support.open_launcher()
        # Released once every reader is listening, to let the primary start.
        self._sync_gate = Event()

        try:
            with open(fifo, "wb", 0) as fifo_out:
                fifo_out.write(PcapFormatter.pcap_header(self.dlt))
                fifo_out.flush()

                try:
                    self._configure_ports()
                except (SerialException, OSError) as exc:
                    sys.stderr.write(f"nRF multi sniffer: failed to configure ports: {exc}\n")
                    self._stop()
                    return

                self._spawn_readers(control_in, sync_interval_ms)

                if paired:
                    if not self._await_readers():
                        # A fatal error is set on timeout, but not when the capture
                        # was stopped while the readers were starting.
                        self._abort_if_fatal(fifo_out)
                        self._stop()
                        return

                    self._sync_gate.set()
                    self._start_sync_watchdog(sync_interval_ms)

                self._capture_loop(fifo_out)
        except BrokenPipeError:
            pass
        finally:
            # Also covers leaving through an exception or through the sys.exit()
            # of a signal handler.
            self._stop()

    def _capture_loop(self, fifo_out) -> None:
        while True:
            if self._capture_abandoned():
                # The held-back packets have nowhere to go: the fifo reader is gone.
                self._stop()
                return

            try:
                item = self.queue.get(timeout=0.5)
            except Empty:
                self._flush_pending(fifo_out)
                self._check_sync_watchdog()
                self._abort_if_fatal(fifo_out)
                if self.processes and not any(p.is_alive() for p in self.processes):
                    sys.stderr.write("nRF multi sniffer: all reader processes exited\n")
                    self._flush_pending(fifo_out, force=True)
                    self._stop()
                    return
                continue

            # The queue never goes idle, because the primary device reports a sync
            # pulse several times a second. The Empty branch above would therefore
            # almost never run and the tail of a burst would sit in the reorder
            # buffer, so the flush has to happen on every item as well.
            self._flush_pending(fifo_out)

            if isinstance(item, SnifferPacket):
                self._handle_packet(item)
            elif isinstance(item, SyncPrimaryEvent):
                self._note_sync(self.sync.primary_port)
                self.sync.handle_primary(item.seq, item.t)
            elif isinstance(item, SyncSecondaryEvent):
                # The primary clock is the reference, so its offset stays zero and
                # only the secondary devices have one to resolve. Every timestamp is
                # converted with that offset, so accepting a secondary report from
                # the primary port would shift the whole merged timeline.
                if item.port_id in self.config_by_port and item.port_id != self.sync.primary_port:
                    self._note_sync(item.port_id)
                    self.sync.handle_secondary(item.port_id, item.edge, item.t)
            elif isinstance(item, ExitEvent):
                self._flush_pending(fifo_out, force=True)
                self._stop()
                return

            # The hub only reports a mismatched pairing; abort on it here, next to
            # the watchdog.
            self._fatal_error = self._fatal_error or self.sync.anchor_error

            self._check_sync_watchdog()
            self._abort_if_fatal(fifo_out)


class WiresharkExtcap:
    @staticmethod
    def extcap_interfaces():
        return (
            "extcap {version=1.0.0}"
            "{help=https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4}"
            "{display=nRF Sniffer for 802.15.4}\n"
            "interface {value=nrf802154-sniffer}{display=nRF Sniffer for 802.15.4}"
        )

    @staticmethod
    def extcap_dlts():
        return (
            "dlt {number=%d}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}\n"
            "dlt {number=%d}{name=IEEE802_15_4_NOFCS}{display=IEEE 802.15.4 without FCS}"
            % (DLT.DLT_IEEE802_15_4_TAP, DLT.DLT_IEEE802_15_4_NOFCS)
        )

    @staticmethod
    def extcap_config():
        """Build the options dialog for the currently detected ports."""
        ports = SerialPortScanner.list_ports()
        multi_device = len(ports) >= 2
        general = "{group=General}" if multi_device else ""

        entries = [
            ("--metadata", "Out-Of-Band meta-data", "Packet header with channel/RSSI/LQI",
             "selector", "{default=ieee802154-tap}" + general,
             [("ieee802154-tap", "IEEE 802.15.4 TAP", True), ("none", "None", False)]),
            ("--primary-index", "Primary Port",
             "Select which detected port should act as the sync primary",
             "selector", "{default=1}" + general,
             [(str(i), f"Port {i} {port}", i == 1) for i, port in enumerate(ports, start=1)]),
            ("--sync-interval", "Sync Interval [ms]", "Interval for 'sync primary start [ms]'",
             "integer",
             "{default=100}{range=%d,%d}" % (SYNC_INTERVAL_MIN_MS, SYNC_INTERVAL_MAX_MS) + general,
             []),
        ]

        for idx, port in enumerate(ports, start=1):
            # With several devices the tab already names the port.
            group = "{group=Port %d %s}" % (idx, port) if multi_device else ""
            prefix = "" if multi_device else f"{port} - "
            entries += [
                (f"--enabled{idx}", f"{prefix}Enabled",
                 "Uncheck to leave this sniffer out of the capture",
                 "boolean", "{default=true}" + group, []),
                (f"--channel{idx}", f"{prefix}Channel", "IEEE 802.15.4 channel 11-26",
                 "selector", "{default=11}" + group,
                 [(str(ch), str(ch), ch == 11) for ch in range(11, 27)]),
                (f"--phy{idx}", f"{prefix}PHY", "2m=GFSK, 250k=O-QPSK",
                 "selector", "{default=250k}" + group,
                 [("2m", "2M (GFSK)", False), ("250k", "250K (O-QPSK)", True)]),
            ]

        lines = [
            "arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % ((num,) + entry[:5])
            for num, entry in enumerate(entries)
        ]
        lines += [
            "value {arg=%d}{value=%s}{display=%s}{default=%s}"
            % (num, value, display, str(default).lower())
            for num, entry in enumerate(entries)
            for value, display, default in entry[5]
        ]
        return "\n".join(lines)


def parse_arguments():
    parser = ArgumentParser(
        description="Multi-sniffer extcap for nRF 802.15.4 (hardware time sync)")
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-interface")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-reload-option")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo")
    parser.add_argument("--extcap-control-in")
    parser.add_argument("--metadata")

    result, unknown = parser.parse_known_args()

    if result.capture and not result.extcap_interface:
        parser.error("--extcap-interface is required if --capture is present")

    return result, unknown


def parse_port_options(unknown: List[str]):
    """Pick the per-port options out of the dynamically generated arguments."""
    per_port: dict = {}
    primary_index = 1
    sync_interval_ms = 100
    i = 0

    while i < len(unknown):
        option = unknown[i]
        value = unknown[i + 1] if i + 1 < len(unknown) else None

        if value is None:
            break

        if option in ("--primary-index", "--sync-interval"):
            try:
                parsed = int(value)
            except (ValueError, TypeError):
                parsed = None
            if parsed is not None:
                if option == "--primary-index":
                    primary_index = parsed
                else:
                    sync_interval_ms = parsed
            i += 2
            continue

        m = re.match(r"--(channel|phy|enabled)(\d+)$", option)
        if m:
            per_port.setdefault(int(m.group(2)), {})[m.group(1)] = value
            i += 2
        else:
            i += 1

    return per_port, primary_index, sync_interval_ms


def build_ports_config(per_port: dict, primary_index: int) -> List[SnifferPortConfig]:
    detected_ports = SerialPortScanner.list_ports()
    if not detected_ports:
        sys.stderr.write("nRF multi sniffer: no sniffer ports found\n")
        sys.exit(1)

    enabled = [
        (idx, port)
        for idx, port in enumerate(detected_ports, start=1)
        if per_port.get(idx, {}).get("enabled", "true").lower() != "false"
    ]
    if not enabled:
        sys.stderr.write("nRF multi sniffer: all sniffer ports are disabled\n")
        sys.exit(1)

    if primary_index not in [idx for idx, _ in enabled]:
        primary_index = enabled[0][0]

    ports_config = []
    for idx, port in enabled:
        entry = per_port.get(idx, {})
        try:
            channel = int(entry.get("channel", 11))
        except (ValueError, TypeError):
            channel = 11
        ports_config.append(SnifferPortConfig(
            port=port,
            channel=channel,
            phy=entry.get("phy", "250k"),
            role="primary" if idx == primary_index else "secondary"))

    return ports_config


def main():
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    args, unknown = parse_arguments()

    if args.extcap_interfaces:
        print(WiresharkExtcap.extcap_interfaces())
        return

    if args.extcap_dlts:
        print(WiresharkExtcap.extcap_dlts())
        return

    if args.extcap_config:
        print(WiresharkExtcap.extcap_config())
        return

    if not (args.capture and args.fifo):
        return

    per_port, primary_index, sync_interval_ms = parse_port_options(unknown)
    sync_interval_ms = max(SYNC_INTERVAL_MIN_MS, min(sync_interval_ms, SYNC_INTERVAL_MAX_MS))

    engine = MultiSnifferEngine()
    signal.signal(signal.SIGINT, engine.stop_and_exit)
    signal.signal(signal.SIGTERM, engine.stop_and_exit)

    engine.start_capture(
        args.fifo,
        build_ports_config(per_port, primary_index),
        args.metadata,
        args.extcap_control_in,
        sync_interval_ms,
    )


if __name__ == "__main__":
    freeze_support()
    main()
