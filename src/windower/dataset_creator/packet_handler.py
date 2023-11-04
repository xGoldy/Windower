"""
Processes packets from a file in order to create a dataset, handles flow
control and windowing.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-07
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import io
import pandas as pd
import math
import numpy as np

from common.time import sec2nsec
from packetprocessing import extractor, logger, logtypes
from decimal import Decimal


class PacketHandler:
    """Packet handler class to process packets from file, simulate windowing, use external timestamps and maintain
    statistics usable for the dataset creation."""

    def __init__(self, logger: logger.Logger, window_interval: float, tstamps_src: io.FileIO = None,
        caida_like: bool = False) -> None:
        """Packet handler class for off-line processing and dataset creation. Performs windowing and saves logs
        obtained from the logger into internal structure, which can be, in turn, retrieved by a particular
        function.

        Parameters:
            logger           Logger instance to utilize for packet logging and statistics computation
            window_interval  Windowing interval in seconds to simulate
            tstamps_src      File handle for external packet timestamps source
            caida_like       Caida-like packet source with cut payloads and L2 headers"""

        self._caida_like        = caida_like        # CAIDA-like pkts with cut L4 payloads and L2 headers
        self._last_window_start = 0                 # Timestamp of the last window start
        self._logger            = logger            # Logger for packet processing
        self._pkt_counter       = 0                 # Packet counter for logging
        self._statistics        = None              # Window statistics (labels) from logger
        self._tstamps_src       = tstamps_src       # File for external timestamps source or None
        self._window_interval   = sec2nsec(window_interval)  # Windowing interval in nanoseconds

        # Initialize window statistics (labels)
        self._initialize_statistics()


    def clear(self) -> None:
        """Clears the packet handler module internal structures, keeping the current configuration intact."""

        self._last_window_start = 0

        self._initialize_statistics()
        self._logger.clear()


    def process(self, packet) -> None:
        """Packet handler function with windowing and logging statistics from logger into the internal structures.

        Parameters:
            packet Raw packet data to be processed"""

        pkt_features = None

        if not self._caida_like:
            pkt_features = extractor.extract_features(packet)
        else:
            tstamp = None

            if self._tstamps_src is not None:
                # Convert loaded timestamps to Decimal since Python's float are imprecise
                tstamp = Decimal(self._tstamps_src.readline())

            pkt_features = extractor.extract_features_caida(packet, tstamp)

        # Ignore packets which data could not be extracted (non IPv4/IPv6)
        if pkt_features is None:
            return

        # Perform windowing
        time_since_last_window = pkt_features.time - self._last_window_start

        # Always set the start of the window to the first processed packet
        if self._last_window_start == 0:
            self._last_window_start = pkt_features.time
        # Afterwards, start new window if specified window interval has elapsed
        elif time_since_last_window > self._window_interval:
            # Determine how many windows have elapsed if there is a gap bigger than 1 window interval
            windows_elapsed = math.floor(time_since_last_window / self._window_interval)

            self._last_window_start += windows_elapsed * self._window_interval
            self.end_logger_window()

        # Log the packet
        self._logger.log(pkt_features)


    def end_logger_window(self):
        """Ends logger window and logs obtained statistics to internal structures.  Called automatically in the
        packet processing function, but can be also called on demand after all input packets from the file are read.
        If the function is not called manually after file processing finishes, packets logged in the current
        (unfinished) window are not taken into account and their statistics are not exported by the object. Calling
        this function ensures statistics of these packets will be computed, but may provide a little skewed results
        since the window would probably be finished earlier than normally."""

        self._logger.end_window()

        # Find out candidates which statistics can be obtained
        ips_ready_for_processing = self._logger.find_candidates()

        # Obtain data for all ready IP addresses and add them to internal statistics structure
        for ip in ips_ready_for_processing:
            stats = self._logger.retrieve_statistics(ip, compute_interwindow_stats=True)

            self._statistics = pd.concat([self._statistics, stats], ignore_index=True)


    def get_labels(self) -> pd.DataFrame:
        """Getter for statistics collected by the packet handler from the logger."""

        return self._statistics


    def _initialize_statistics(self) -> None:
        """Initialize internal statistics header to provide semantics upon the logged data."""

        # Initialize empty dataframes with only structure specified based on numpy datatypes
        stats_summary = pd.DataFrame(np.zeros((0,), dtype=logtypes.NP_DTYPE_WINDOW_SUMMARY_STATS))
        stats_inters  = pd.DataFrame(np.zeros((0,), dtype=logtypes.NP_DTYPE_INTERWINDOW_STATS))

        # Merge the empty dataframes to create header structure
        self._statistics = stats_summary.merge(stats_inters, left_index=True, right_index=True)
