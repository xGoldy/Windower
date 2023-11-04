"""
Simple interface to read packets, either by live capture or from a file.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-09
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import scapy.utils
import scapy.sendrecv
import tqdm

from scapy.supersocket import L3RawSocket
from threading import Thread, Event


def determine_pcap_reader(filename: str):
    """Determines which Scapy PCAP reader to use according to the file extension.

    Parameters:
        filename Name of the PCAP file

    Returns:
        Scapy.PcapReader | Scapy.PcapNgReader based on the type of the file

    Raises:
        RuntimeError upon invalid file presention."""

    # Instantiate PCAP reader according to given extension
    if filename.endswith('.pcap') or filename.endswith('.pcap.gz'):
        return scapy.utils.PcapReader(filename)
    elif filename.endswith('.pcapng'):
        return scapy.utils.PcapNgReader(filename)
    else:
        raise RuntimeError("Only PCAP and PCAPNG files with the correct extension are supported ")


def read_file(filename: str, handler):
    """Reads the PCAP file, calling handler for each read packet.

    Parameters:
        filename PCAP file path
        handler  Function to process packets in"""

    reader = determine_pcap_reader(filename)   # Scapy PCAP reader instance

    for pkt in tqdm.tqdm(reader, unit='pkt'):
        handler(pkt)


def read_live(iface: str, handler):
    """Captures IPv4 or IPv6 packets from live interface and calls handler upon them.

    Parameters:
        iface   Interface to capture packets on
        handler Function to process packets in"""

    scapy.sendrecv.sniff(store=False, quiet=True, iface=iface, prn=handler, filter='ip or ip6')


class LiveThreadedSniffer(Thread):
    """Threaded implementation of the live packet sniffing with correct interrupt reaction.
    Idea of a threaded sniffer with correct resources deallocation retrieved from [1].
    [1]: https://blog.skyplabs.net/2018/03/01/python-sniffing-inside-a-thread-with-scapy/"""

    def  __init__(self, interface: str, handler) -> None:
        """Initializes a sniffer threaded instance.

        Parameters:
            interface Network interface name to sniff on
            handler   Packet handler function to use"""

        super().__init__()

        self._iface       = interface  # Interface to listen traffic on
        self._pkt_handler = handler    # Packet handler function
        self._stop_sniff  = Event()    # Thread execution stopping condition
        self._socket      = None       # Network socket corresponding this thread

        self.exc_event = Event()       # Event to signalize that exception has ocurred
        self.exc_type  = None          # Exception type that has ocurred
        self.daemon    = True          # Mark thread as daemon for proper exitting


    def run(self) -> None:
        """Sniffer thread execution routine.  Exception (such as for invalid interface is caught internally,
        whereas corresponding member variable self.exc_type and event self.exc_event is raised"""

        # Exception handling within a thread as a signalization to the caller
        try:
            self._socket = L3RawSocket(iface=self._iface, filter="ip or ip6")

            scapy.sendrecv.sniff(opened_socket=self._socket, store=False, quiet=True, iface=self._iface,
                prn=self._pkt_handler, stop_filter=self._should_stop, filter='ip or ip6')
        except Exception as exc:
            self.exc_type = exc
            self.exc_event.set()


    def join(self, timeout=None) -> None:
        """Joins the thread with the main process.

        Parameters:
            timetout Maximum timeout for thread joining."""

        self._stop_sniff.set()
        super().join(timeout)


    def close_socket(self) -> None:
        """Closes the underlying socket of the sniffer manually."""

        self._socket.close()


    def _should_stop(self, packet) -> bool:
        """Determines whether the packet sniffing should stop.

        Parameters:
            packet Last processed packet. Ignored in this case"""

        return self._stop_sniff.isSet()
