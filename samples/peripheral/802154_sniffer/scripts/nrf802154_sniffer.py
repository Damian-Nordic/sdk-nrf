#!/usr/bin/env python3

# Copyright (c) 2019, Nordic Semiconductor ASA
# Copyright (c) 2026 Nordic Semiconductor ASA (dual time-sync extcap)
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
# Wireshark extcap: one interface, two hardware-synced sniffers merged into one timeline.
# Streamlined for Wireshark integration only.

import sys
import re
import signal
import struct
import time
from queue import Empty
from argparse import ArgumentParser
from enum import IntEnum
from binascii import a2b_hex
from serial import Serial, SerialException
from serial.tools.list_ports import comports
from multiprocessing import Queue, Process, freeze_support
from dataclasses import dataclass
from typing import List, Optional

# CONSTANTS
NORDICSEMI_VID = 0x1915
SNIFFER_802154_PID = 0x154B
QUEUE_MAXSIZE = 512

# Packets are held back briefly and written out sorted by their hardware
# synchronized timestamp.
REORDER_HOLD_S = 0.25
REORDER_MAX_PACKETS = 4096

# Serial output parsing
RCV_REGEX = r"received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(-?\d+)"
SYNC_MASTER_REGEX = r"sync role=master seq=(\d+) t=(\d+)"
SYNC_SLAVE_REGEX = r"sync role=slave id=(\d+) edge=(\d+) t=(\d+)"


@dataclass
class SnifferPacket:
    content: bytes
    timestamp: int
    lqi: int
    rssi: int
    port_id: str = ""


@dataclass
class SyncMasterEvent:
    seq: int
    t: int


@dataclass
class SyncSlaveEvent:
    port_id: str
    sniffer_id: int
    edge: int
    t: int


@dataclass
class ExitEvent:
    reason: str = ""


@dataclass
class SnifferPortConfig:
    """Configuration for a single sniffer port."""
    port: str           # /dev/ttyACM0
    channel: int        # 11-26
    phy: str            # "2m" (GFSK) or "250k" (O-QPSK)
    role: str           # "master" or "slave"


@dataclass
class CaptureGroup:
    """Group of master + slaves synchronized on one hardware sync line."""
    master_port: str
    slave_ports: List[str]
    channel: int
    phy: str


class DLT(IntEnum):
    DLT_IEEE802_15_4_NOFCS = 230
    DLT_IEEE802_15_4_TAP = 283



class TimeSyncHub:
    """Correlates hardware sync UART lines into per-port time offsets.

    All timestamps reported by the firmware (packet capture time and sync
    master/slave edges) are 64-bit microsecond values, so no timer
    wraparound handling is required here.
    """

    def __init__(self):
        self.offsets: dict[str, int] = {}
        self.pending_master: dict[int, int] = {}
        self.pending_slave: dict[str, dict[int, int]] = {}
        self.first_local_timestamp = None
        self.first_global_timestamp = None
        self.master_port: Optional[str] = None

    def set_master_port(self, port_id: str) -> None:
        self.master_port = port_id
        self.offsets[port_id] = 0

    def handle_master(self, seq: int, t_master: int) -> None:
        """Store master edge timestamp and resolve any slave events that were
        received (from the other reader process) before this master line."""
        self.pending_master[seq] = t_master
        if len(self.pending_master) > 256:
            del self.pending_master[min(self.pending_master)]

        for port_id, edges in self.pending_slave.items():
            t_slave = edges.pop(seq, None)
            if t_slave is not None:
                self.offsets[port_id] = t_master - t_slave

    def handle_slave(self, port_id: str, edge: int, t_slave: int) -> Optional[int]:
        """Match slave edge to master edge and calculate offset. If the matching
        master line has not arrived yet (queue ordering race between the two
        reader processes), buffer the slave edge and resolve it later in
        handle_master() instead of dropping it."""
        t_master = self.pending_master.get(edge)
        if t_master is not None:
            offset = t_master - t_slave
            self.offsets[port_id] = offset
            return offset

        buf = self.pending_slave.setdefault(port_id, {})
        buf[edge] = t_slave
        if len(buf) > 256:
            del buf[min(buf)]
        return None

    def to_global(self, port_id: str, t_local: int) -> int:
        """Convert local port timestamp to global timeline."""
        if self.master_port is not None and port_id == self.master_port:
            offset = 0
        else:
            if port_id not in self.offsets:
                raise KeyError(port_id)
            offset = self.offsets[port_id]
        return t_local + offset

    def correct_time_multi(self, port_id: str, t_local: int) -> Optional[int]:
        """Convert hardware timestamp to human-readable microseconds."""
        # Drop slave packets before first sync lock
        if self.master_port is not None and port_id != self.master_port:
            if port_id not in self.offsets:
                return None

        t_global = self.to_global(port_id, t_local)
        if self.first_local_timestamp is None:
            self.first_local_timestamp = int(time.time() * (10**6))
            self.first_global_timestamp = t_global
            return self.first_local_timestamp
        if self.first_global_timestamp is None:
            return None
        return self.first_local_timestamp + (t_global - self.first_global_timestamp)


class PcapFormatter:
    """Builds PCAP headers and packets."""

    @staticmethod
    def pcap_header(dlt: DLT) -> bytes:
        header = bytearray()
        header += struct.pack("<L", int("a1b2c3d4", 16))
        header += struct.pack("<H", 2)
        header += struct.pack("<H", 4)
        header += struct.pack("<I", 0)
        header += struct.pack("<I", 0)
        header += struct.pack("<L", int("000000ff", 16))
        header += struct.pack("<L", dlt)
        return bytes(header)

    @staticmethod
    def pcap_packet(frame: bytes, dlt: DLT, channel: int, rssi: int, lqi: int, timestamp: int) -> bytes:
        """Build a single PCAP packet with IEEE 802.15.4 TAP header."""
        pcap = bytearray()
        caplength = len(frame)
        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            caplength += 28

        ts_sec = max(0, timestamp // 1000000)
        ts_usec = max(0, timestamp % 1000000)
        pcap += struct.pack("<I", ts_sec & 0xFFFFFFFF)
        pcap += struct.pack("<I", ts_usec & 0xFFFFFFFF)
        pcap += struct.pack("<L", caplength)
        pcap += struct.pack("<L", caplength)

        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            pcap += struct.pack("<HH", 0, 28)
            pcap += struct.pack("<HHf", 1, 4, rssi)
            pcap += struct.pack("<HHHH", 3, 3, channel, 0)
            pcap += struct.pack("<HHI", 10, 1, lqi)

        pcap += frame
        return bytes(pcap)


class SerialPortScanner:
    """Detects and identifies sniffer ports."""

    @staticmethod
    def is_sniffer_port(port) -> bool:
        """Check if port is an nRF 802.15.4 sniffer."""
        if port.vid != NORDICSEMI_VID:
            return False
        if port.pid != SNIFFER_802154_PID:
            return False
        label = " ".join(
            filter(None, [port.interface, port.description, port.product, port.manufacturer])
        ).lower()
        if any(token in label for token in ("mcumgr", "dfu", "bootloader")):
            return False
        return True

    @staticmethod
    def list_ports() -> List[str]:
        """Get sorted list of sniffer ports."""
        return sorted(port.device for port in comports() if SerialPortScanner.is_sniffer_port(port))


class PacketParser:
    """Parses serial output from sniffers."""

    @staticmethod
    def parse_line(value: bytes, port_id: str = ""):
        """Parse serial line as packet, sync, or ignore."""
        text = value.decode("utf-8", errors="ignore")

        # Check for received packet
        m = re.search(RCV_REGEX, text)
        if m:
            hex_psdu = m.group(1)
            if len(hex_psdu) < 4:
                raise ValueError("frame too short")
            content = a2b_hex(hex_psdu[:-4])
            if not content:
                raise ValueError("empty frame")
            return SnifferPacket(
                content=content,
                rssi=int(m.group(2)),
                lqi=int(m.group(3)),
                timestamp=int(m.group(4)),
                port_id=port_id,
            )

        # Check for sync master event
        m = re.search(SYNC_MASTER_REGEX, text)
        if m:
            return SyncMasterEvent(seq=int(m.group(1)), t=int(m.group(2)))

        # Check for sync slave event
        m = re.search(SYNC_SLAVE_REGEX, text)
        if m:
            return SyncSlaveEvent(
                port_id=port_id,
                sniffer_id=int(m.group(1)),
                edge=int(m.group(2)),
                t=int(m.group(3)),
            )

        raise ValueError("unrecognized serial line")

class SnifferProcess:
    """Worker process for reading serial ports."""

    @staticmethod
    def serial_reader(serial_port: str, queue: Queue, port_id: str = "") -> None:
        """Continuously read from serial port and parse output."""
        reader_port = port_id or serial_port

        while True:
            try:
                serial = Serial(serial_port, exclusive=True, timeout=0.05)
            except Exception:
                time.sleep(0.3)
                continue

            while True:
                try:
                    value = serial.readline()
                    if not value:
                        continue

                    try:
                        item = PacketParser.parse_line(value, reader_port)
                    except ValueError:
                        continue

                    # Graceful queue-full: drop oldest non-exit item
                    try:
                        queue.put_nowait(item)
                    except Exception:
                        try:
                            queue.get_nowait()
                        except Exception:
                            pass
                        try:
                            queue.put_nowait(item)
                        except Exception:
                            pass
                except Exception:
                    try:
                        serial.close()
                    except Exception:
                        pass
                    break

    @staticmethod
    def control_reader(control_in: str, queue: Queue) -> None:
        """Monitor Wireshark control pipe for disconnect."""
        with open(control_in, "rb", 0) as control_in_fifo:
            try:
                while True:
                    chunk = control_in_fifo.read(1)
                    if not chunk:
                        break
            except Exception:
                pass
            queue.put_nowait(ExitEvent("Wireshark connection lost."))


class SnifferConfig:
    """Configures sniffer hardware via serial commands."""

    @staticmethod
    def _drain_serial(serial: Serial, limit: int = 65536, max_seconds: float = 0.25) -> None:
        """Drain pending serial data, bounded by bytes and wall-clock time.

        The time bound avoids hanging on the master's continuous sync flood at
        short intervals, where reads keep returning data and never go empty.
        """
        drained = 0
        deadline = time.monotonic() + max_seconds
        while drained < limit and time.monotonic() < deadline:
            chunk = serial.read(min(4096, limit - drained))
            if not chunk:
                break
            drained += len(chunk)

    @staticmethod
    def configure_sniffer(port: str, channel: int, phy: str = "250k", extra_commands: Optional[List[bytes]] = None):
        """Initialize sniffer on port: stop sync, clear, set role, set channel, set PHY, start receive."""
        serial = Serial(port, exclusive=True, timeout=0.05)
        serial.reset_input_buffer()
        serial.write(b"\r\n")
        serial.write(b"sync stop\r\n")
        serial.write(b"sleep\r\n")
        serial.write(b"shell echo off\r\n")
        serial.write(b"sync stop\r\n")
        serial.flush()
        SnifferConfig._drain_serial(serial)

        if extra_commands:
            for command in extra_commands:
                serial.write(command)
                serial.flush()
                SnifferConfig._drain_serial(serial)

        # Set PHY before channel — some firmware resets channel state on PHY change.
        # Always send phy command so the device is in a known state regardless of firmware defaults.
        serial.write(b"phy " + (phy or "250k").encode() + b"\r\n")
        serial.flush()
        time.sleep(0.05)
        SnifferConfig._drain_serial(serial)

        serial.write(b"channel " + str(channel).encode() + b"\r\n")
        serial.flush()
        time.sleep(0.05)
        SnifferConfig._drain_serial(serial)

        serial.write(b"receive\r\n")
        serial.flush()
        SnifferConfig._drain_serial(serial)
        serial.close()


class MultiSnifferEngine:
    """Multi-sniffer capture engine with per-port configuration."""

    def __init__(self):
        self.queue = Queue(maxsize=QUEUE_MAXSIZE)
        self.processes: List[Process] = []
        self.ports_config: List[SnifferPortConfig] = []
        self.config_by_port: dict[str, SnifferPortConfig] = {}
        self.capture_groups: List[CaptureGroup] = []
        self.sync_hubs: dict[str, TimeSyncHub] = {}  # per master_port
        self._last_pcap_ts_us = 0
        self._pending: List[tuple] = []
        self.dlt = DLT.DLT_IEEE802_15_4_TAP

    def _pcap_timestamp_us(self, ts_us: int) -> int:
        """Last-resort guard against equal or out-of-order PCAP timestamps.

        After reordering this only nudges packets that share a timestamp, so it
        no longer flattens whole bursts onto consecutive microseconds.
        """
        ts_us = max(0, int(ts_us))
        if ts_us <= self._last_pcap_ts_us:
            ts_us = self._last_pcap_ts_us + 1
        self._last_pcap_ts_us = ts_us
        return ts_us

    def _queue_packet(self, port_id: str, content: bytes, channel: int, rssi: int, lqi: int,
                      ts_us: int) -> None:
        self._pending.append((ts_us, time.monotonic(), port_id, content, channel, rssi, lqi))

    def _flush_pending(self, fifo_out, force: bool = False) -> None:
        """Write out packets that are older than the hold-back window.

        Arrival times increase with insertion order, so the releasable packets
        are always a prefix of the buffer.
        """
        if not self._pending:
            return

        cutoff = time.monotonic() - REORDER_HOLD_S
        count = len(self._pending)
        idx = count if force else 0
        if not force:
            while idx < count and self._pending[idx][1] <= cutoff:
                idx += 1
            # Bound memory if a device backlog exceeds the hold-back window.
            idx = max(idx, count - REORDER_MAX_PACKETS)

        if idx <= 0:
            return

        ready = self._pending[:idx]
        del self._pending[:idx]
        ready.sort(key=lambda item: item[0])

        for ts_us, _arrival, port_id, content, channel, rssi, lqi in ready:
            pcap_ts = self._pcap_timestamp_us(ts_us)
            fifo_out.write(PcapFormatter.pcap_packet(content, self.dlt, channel, rssi, lqi,
                                                     pcap_ts))

    def _stop(self):
        """Stop all reader processes and clean up ports."""
        for process in self.processes:
            process.kill()
            process.join()
        self.processes = []

        # Stop sync on all ports (masters first). Retry non-exclusively: the
        # reader port release races with reopening it here.
        ordered = sorted(
            self.ports_config,
            key=lambda c: 0 if c.role == "master" else 1,
        )
        for port_config in ordered:
            self._send_stop(port_config)

    @staticmethod
    def _send_stop(port_config: SnifferPortConfig, attempts: int = 5) -> bool:
        """Best-effort deliver 'sync stop' to a single port, with retries."""
        for attempt in range(1, attempts + 1):
            try:
                serial = Serial(port_config.port, exclusive=False, timeout=0.05)
                serial.write(b"\r\n")
                serial.write(b"sync stop\r\n")
                serial.write(b"sleep\r\n")
                # Restore shell echo (turned off during capture).
                serial.write(b"shell echo on\r\n")
                serial.flush()
                serial.read(100000)
                serial.reset_input_buffer()
                serial.close()
                return True
            except (SerialException, OSError):
                time.sleep(0.1)
        return False

    def _stop_and_exit(self, *args, **kwargs):
        """Signal handler for clean shutdown."""
        self._stop()
        sys.exit(0)

    def _build_groups(self) -> List[CaptureGroup]:
        """Build the single capture group: one master plus all slaves."""
        masters = [cfg for cfg in self.ports_config if cfg.role == "master"]
        if len(masters) != 1:
            raise ValueError(
                f"Expected exactly one master port, found {len(masters)}"
            )

        master = masters[0]
        slaves = [cfg.port for cfg in self.ports_config if cfg.role == "slave"]

        return [CaptureGroup(
            master_port=master.port,
            slave_ports=slaves,
            channel=master.channel,
            phy=master.phy,
        )]

    def start_capture(self, fifo: str, ports_config: List[SnifferPortConfig], metadata: Optional[str] = None,
                       control_in: Optional[str] = None, sync_interval_ms: int = 100):
        """Main capture loop: read packets from queue and write to PCAP."""
        self.ports_config = ports_config
        self.config_by_port = {cfg.port: cfg for cfg in ports_config}

        try:
            self.capture_groups = self._build_groups()
        except ValueError as exc:
            sys.stderr.write(f"nRF multi sniffer: {exc}\n")
            return

        self._last_pcap_ts_us = 0
        self._pending.clear()

        if metadata == "ieee802154-tap":
            self.dlt = DLT.DLT_IEEE802_15_4_TAP
        else:
            self.dlt = DLT.DLT_IEEE802_15_4_NOFCS

        # Create time sync hub for each master
        for group in self.capture_groups:
            self.sync_hubs[group.master_port] = TimeSyncHub()
            self.sync_hubs[group.master_port].set_master_port(group.master_port)

        try:
            with open(fifo, "wb", 0) as fifo_out:
                # Write PCAP header
                fifo_out.write(PcapFormatter.pcap_header(self.dlt))
                fifo_out.flush()

                # Configure all sniffers. Arm every slave BEFORE starting the
                # master's pulse train so the slaves capture the master's very
                # first sync pulse. This keeps the firmware edge/seq counters
                # aligned (slave edge N == master seq N). If the master started
                # pulsing first (while a slave was still being configured), the
                # slave's edge=1 would map to some master seq=K>1, the edge==seq
                # matching would never lock, and every slave packet would be
                # dropped - Wireshark would then show only the master's stream.
                has_slaves = any(cfg.role == "slave" for cfg in self.ports_config)
                config_order = sorted(
                    self.ports_config,
                    key=lambda c: 0 if c.role == "slave" else 1,
                )
                try:
                    for cfg in config_order:
                        extra_cmd = None
                        if cfg.role == "master" and has_slaves:
                            extra_cmd = [f"sync master start {sync_interval_ms}\r\n".encode()]
                        elif cfg.role == "slave":
                            # Extract slave ID from config (simplified: use port index)
                            slave_id = self.ports_config.index(cfg)
                            extra_cmd = [f"sync slave {slave_id}\r\n".encode()]

                        SnifferConfig.configure_sniffer(cfg.port, cfg.channel, cfg.phy, extra_cmd)
                except (SerialException, OSError) as exc:
                    sys.stderr.write(f"nRF multi sniffer: failed to configure ports: {exc}\n")
                    self._stop()
                    return

                # Start reader processes
                for cfg in self.ports_config:
                    self.processes.append(Process(
                        target=SnifferProcess.serial_reader, 
                        args=(cfg.port, self.queue, cfg.port), 
                        daemon=True
                    ))

                # Start control-pipe watcher (portable disconnect detection,
                # notably needed on Windows where signal handling is unreliable).
                if control_in:
                    self.processes.append(Process(
                        target=SnifferProcess.control_reader,
                        args=(control_in, self.queue),
                        daemon=True
                    ))

                for process in self.processes:
                    process.start()

                # Main packet loop
                while True:
                    try:
                        packet = self.queue.get(timeout=0.5)
                    except Empty:
                        self._flush_pending(fifo_out)
                        if self.processes and not any(p.is_alive() for p in self.processes):
                            sys.stderr.write("nRF multi sniffer: all reader processes exited\n")
                            self._flush_pending(fifo_out, force=True)
                            self._stop()
                            break
                        continue

                    # Release aged packets on every iteration. Sync lines keep
                    # the queue busy, so relying on the idle branch alone would
                    # hold the tail of a burst until the next packet arrives.
                    self._flush_pending(fifo_out)

                    match packet:
                        case SnifferPacket(content, timestamp, lqi, rssi, port_id):
                            # Find which group this port belongs to
                            group = None
                            for g in self.capture_groups:
                                if port_id == g.master_port or port_id in g.slave_ports:
                                    group = g
                                    break

                            if group is None:
                                continue

                            time_sync = self.sync_hubs[group.master_port]
                            corrected_ts = time_sync.correct_time_multi(port_id, timestamp)

                            if corrected_ts is None:
                                continue

                            channel = self.config_by_port[port_id].channel
                            self._queue_packet(port_id, content, channel, rssi, lqi, corrected_ts)

                        case SyncMasterEvent(seq, t):
                            # Route to correct time sync hub
                            for group in self.capture_groups:
                                self.sync_hubs[group.master_port].handle_master(seq, t)

                        case SyncSlaveEvent(port_id, sniffer_id, edge, t):
                            # Find which group this slave belongs to
                            for group in self.capture_groups:
                                if port_id in group.slave_ports:
                                    self.sync_hubs[group.master_port].handle_slave(port_id, edge, t)
                                    break

                        case ExitEvent(reason):
                            self._flush_pending(fifo_out, force=True)
                            if reason:
                                sys.stderr.write(reason + "\n")
                            self._stop()
                            break

        except BrokenPipeError:
            self._stop()


class WiresharkExtcap:
    """Wireshark extcap protocol responses."""

    @staticmethod
    def extcap_interfaces():
        return (
            "extcap {version=0.8.0}"
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
    def extcap_config(reload_option: Optional[str] = None):
        """Generate dynamic interface configuration.
        
        Ports are auto-detected and fixed in sorted order.
        User configures channel and PHY per port.
        First port is always master, rest are slaves.
        """
        ports = SerialPortScanner.list_ports()

        # Base arguments
        args = [
            (0, "--metadata", "Out-Of-Band meta-data", "Packet header with channel/RSSI/LQI", "selector", "{default=ieee802154-tap}"),
        ]

        # Master selection and sync interval
        args.append((
            1,
            "--master-index",
            "Master Port",
            "Select which detected port should act as sync master",
            "selector",
            "{default=1}"
        ))
        args.append((
            2,
            "--sync-interval",
            "Sync Interval [ms]",
            "Interval for 'sync master start [ms]'",
            "integer",
            "{default=100}"
        ))

        # Channel and PHY selector per detected port (no role selector — order determines role)
        multi_device = len(ports) >= 2
        arg_num = 3
        for port_idx, port in enumerate(ports, start=1):
            if multi_device:
                port_label = f"Port {port_idx} {port}"
            else:
                port_label = f"{port}"
            args.append((
                arg_num,
                f"--channel{port_idx}",
                f"{port_label} — Channel",
                "IEEE 802.15.4 channel 11-26",
                "selector",
                "{default=11}"
            ))
            arg_num += 1

            args.append((
                arg_num,
                f"--phy{port_idx}",
                f"{port_label} — PHY",
                "2m=GFSK, 250k=O-QPSK",
                "selector",
                "{default=250k}"
            ))
            arg_num += 1

        res = []
        for arg in args:
            res.append("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

        # Option values
        values = []
        values.append((0, "ieee802154-tap", "IEEE 802.15.4 TAP", "true"))
        values.append((0, "none", "None", "false"))

        # Master selector options
        for port_idx, port in enumerate(ports, start=1):
            values.append((1, str(port_idx), f"Port {port_idx} {port}", "true" if port_idx == 1 else "false"))

        arg_num = 3
        for _port_idx, _port in enumerate(ports, start=1):
            # Channel values
            for ch in range(11, 27):
                values.append((arg_num, str(ch), str(ch), "true" if ch == 11 else "false"))
            arg_num += 1

            # PHY values
            values.append((arg_num, "2m", "2M (GFSK)", "false"))
            values.append((arg_num, "250k", "250K (O-QPSK)", "true"))
            arg_num += 1

        for value in values:
            res.append("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)

        return "\n".join(res)


def parse_arguments():
    """Parse Wireshark extcap command line arguments."""
    parser = ArgumentParser(description="Multi-sniffer extcap for nRF 802.15.4 (hardware time sync)")
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-interface")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-reload-option")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo")
    parser.add_argument("--extcap-control-in")
    parser.add_argument("--metadata")
    
    # Dynamic per-port arguments (will be parsed from sys.argv)
    # Format: --port1, --channel1, --phy1, --port2, --channel2, --phy2, etc.
    
    result, unknown = parser.parse_known_args()

    if result.capture and not result.extcap_interface:
        parser.error("--extcap-interface is required if --capture is present")

    return result, unknown


def main():
    """Main entry point for Wireshark extcap with multi-sniffer support."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    args, unknown = parse_arguments()
    extcap = WiresharkExtcap()

    if args.extcap_interfaces:
        print(extcap.extcap_interfaces())
        return

    if args.extcap_dlts:
        print(extcap.extcap_dlts())
        return

    if args.extcap_config:
        option = args.extcap_reload_option or ""
        print(extcap.extcap_config(option))
        return

    if args.capture and args.fifo:
        # Parse --master-index / --sync-interval and
        # --channel1/--phy1/--channel2/--phy2/... from unknown args.
        per_port: dict[int, dict] = {}
        master_index = 1
        sync_interval_ms = 100
        i = 0
        while i < len(unknown):
            if unknown[i] == "--master-index" and i + 1 < len(unknown):
                try:
                    master_index = int(unknown[i + 1])
                except (ValueError, TypeError):
                    master_index = 1
                i += 2
                continue

            if unknown[i] == "--sync-interval" and i + 1 < len(unknown):
                try:
                    sync_interval_ms = int(unknown[i + 1])
                except (ValueError, TypeError):
                    sync_interval_ms = 100
                i += 2
                continue

            m = re.match(r"--(channel|phy)(\d+)$", unknown[i])
            if m and i + 1 < len(unknown):
                per_port.setdefault(int(m.group(2)), {})[m.group(1)] = unknown[i + 1]
                i += 2
            else:
                i += 1

        detected_ports = SerialPortScanner.list_ports()
        if len(detected_ports) < 1:
            sys.stderr.write(
                "nRF multi sniffer: no sniffer ports found\n"
            )
            sys.exit(1)

        if not (1 <= master_index <= len(detected_ports)):
            master_index = 1

        # Keep interval in a sane range for firmware command.
        sync_interval_ms = max(1, min(sync_interval_ms, 60000))

        ports_config = []
        for port_idx, port in enumerate(detected_ports, start=1):
            entry = per_port.get(port_idx, {})
            try:
                channel = int(entry.get("channel", 11))
            except (ValueError, TypeError):
                channel = 11
            phy = entry.get("phy", "250k")
            role = "master" if port_idx == master_index else "slave"
            ports_config.append(SnifferPortConfig(port=port, channel=channel, phy=phy, role=role))

        engine = MultiSnifferEngine()
        signal.signal(signal.SIGINT, engine._stop_and_exit)
        signal.signal(signal.SIGTERM, engine._stop_and_exit)

        metadata = getattr(args, "metadata", None)
        engine.start_capture(
            args.fifo,
            ports_config,
            metadata,
            args.extcap_control_in,
            sync_interval_ms,
        )


if __name__ == "__main__":
    freeze_support()
    main()
