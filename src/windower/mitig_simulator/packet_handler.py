"""
Processes packets from online or offline and handles windowing for offline cases.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-20
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import common.time
import math
import numpy as np
import pandas as pd
import time

from typing import Callable
from cachetools import LRUCache

from common import defines
from common.time import sec2nsec
from mitig_simulator.model_wrapper import ModelWrapper
from packetprocessing import extractor
from packetprocessing.logger import Logger


# Numpy single IP statistics datatype
NP_DTYPE_IP_STATISTICS = np.dtype([
    ('detected_after', 'u4'),      # Time in seconds after the attacking IP has been detected
    ('detections_pos', 'u4'),      # Number of positive classifications
    ('detections_neg', 'u4'),      # Number of negative classifications
    ('pkts_allowed', 'u8'),        # Number of allowed packets
    ('pkts_denied', 'u8'),         # Number of denied packets
], align=True)


class PacketHandler:
    """Packet handler class for mitigation.  Handles windowing, statistics collection for performance
    estimation and mitigation process informational messages."""

    def __init__(self, model : ModelWrapper, logger: Logger, preproc_func: Callable | None,
        window_interval: float, *, model_treshold : float | None = None, denylist_size: int = 512000,
        verbose: bool = False) -> None:
        """Packet handler class for mitigation evaluation.  Performs windowing and collects statistics
        about the mitigation process.

        Parameters:
            model            Machine learning model to perfrom simulation with
            logger           Logger instance to utilize for packet logging
            preproc_func     func(pd.Dataframe) -> pd.DataFrame or None to transform the data
            window_interval  Windowing interval in seconds
            model_threshold  Threshold to use for decision about anomalous/non-anomalous behavior
            denylist_size    Size of the denylist for the mitigation process
            verbose          Packet processing verbose mode"""

        self._first_tstamp      = None              # Timestamp of the first received packet
        self._last_window_start = 0                 # Timestamp of the last window start
        self._logger            = logger            # Logger instance for packet processing
        self._model             = model             # Model instance for classification
        self._model_treshold    = model_treshold    # Threshold of the decision model, None for no threshold
        self._per_ip_losses     = {}                # The latest per-IP loss
        self._predictions_all   = []                # Lists all predictions for statistical purposes
        self._preprocessor      = preproc_func      # Data preprocessor instance before classification
        self._statistics        = {}                # Packet handler collected statistics of mitigation per IP
        self._verbose           = verbose           # Verbose output during for mitigation actions
        self._denylist          = LRUCache(denylist_size)   # Denylist (blacklist) for statistics computation
        self._window_interval   = sec2nsec(window_interval) # Windowing interval in nanoseconds


    def process(self, packet) -> None:
        """Packet handler function.
        Performs windowing by setting the right times within the function if desired. If external windowing system
        is used, more emphasis is put on the throughput, so windows have to be switched by a different thread outside
        of packet processing function.

        Parameters:
            packet Raw packet data to be processed"""

        pkt_features = extractor.extract_features(packet)

        # Ignore Non IPv4/IPv6 data
        if pkt_features is None:
            return

        # Log the IP address
        self._log_processing(pkt_features.src_ip)

        # Perform windowing
        time_since_last_window = pkt_features.time - self._last_window_start

        # Always set the start of the window to the first processed packet
        if self._last_window_start == 0:
            self._last_window_start = pkt_features.time
            self._first_tstamp      = pkt_features.time
        # Afterwards, start a new window if specified window interval has elapsed
        elif time_since_last_window > self._window_interval:
            # Determine how many windows have elapsed if there is a gap bigger than 1 window interval
            windows_elapsed = math.floor(time_since_last_window / self._window_interval)

            self._last_window_start += windows_elapsed * self._window_interval
            self.end_logger_window(pkt_features.time - self._first_tstamp)

        # Log the packet and obtain last IP loss
        self._logger.log(pkt_features)
        loss = self._per_ip_losses.get(pkt_features.src_ip, 0.0)

        return pkt_features.src_ip, loss


    def end_logger_window(self, elapsed: int = None) -> None:
        """Ends logger window and logs obtained statistics to internal structures.  Called automatically in the
        packet processing function, but can be also called on demand after all input packets from the file are read.
        If the function is not called manually after file processing finishes, packets logged in the current
        (unfinished) window are not taken into account and their statistics are not classified. Calling it ensures
        that statistics of these packets will be computed, but may provide a little skewed results since the window
        gets finished earlier than normally.

        Parameters:
            elapsed Nanoseconds elapsed since the analysis start (a.k.a delta timestamp)"""

        features_lst = []       # Features corresponding to ip_addresses
        features     = None     # Features corresponding to ip_addresses as a Matrix
        losses       = None     # Reconstruction errors
        final_preds  = None     # Final classification predictions

        self._logger.end_window()

        # Find out candidates which statistics can be obtained
        ips_ready_for_processing = self._logger.find_candidates()

        # Obtain data for all ready IP addresses and group them for batch processing
        for ip in ips_ready_for_processing:
            stats = self._logger.retrieve_statistics(ip, compute_interwindow_stats=True)

            features_lst.append(stats)

        # Preprocess statistics if some were extracted
        if len(features_lst) > 0:
            features     = pd.concat(features_lst, ignore_index=True)  # All statistics in single DataFrame
            ip_addresses = features[defines.DATA_SRC_IP_COLNAME]    # Corresponding IP addresses

            # Preprocess the features and evaluate them within the model
            if self._preprocessor is not None:
                features = self._preprocessor(features)

            losses = self._model(features.to_numpy())

            # Apply the threshold to determine anomalous behavior
            if self._model_treshold is not None:
                final_preds = np.where(losses < self._model_treshold, 0, 1)
            else:
                final_preds = losses
                losses = np.zeros(losses.shape[0])

            # Log results about predictions and losses into statistical structures
            self._predictions_all += list(zip(ip_addresses, losses.tolist()))

            for ip, prediction, loss in zip(ip_addresses, final_preds, losses):
                self._log_prediction(ip, prediction, elapsed, loss)


    def get_statistics(self) -> pd.DataFrame:
        """Returns gathered IP statistics as a Pandas Dataframe.

        Returns:
            pd.DataFrame Dataframe with the collected statistics, IPs being row indexes"""

        merged_stats = np.zeros((len(self._statistics),), dtype=NP_DTYPE_IP_STATISTICS)
        ip_addrs = list(self._statistics.keys())

        for idx in range(len(ip_addrs)):
            merged_stats[idx] = self._statistics[ip_addrs[idx]]

        return pd.DataFrame(merged_stats, index=self._statistics.keys())


    def get_predictions(self) -> list:
        """Returns a list of all per-IP predictions and their corresponding losses."""

        return self._predictions_all


    def _log_processing(self, ip: str) -> None:
        """Logs IP address during the processing phase.  If the IP was logged already, increases counters according
        to its presence in denylist. Otherwise creates a new entry for a given IP.

        Parameters:
            ip IP address to log"""

        # Create new statistics entry for a new IP
        if ip not in self._statistics:
            self._statistics[ip] = np.zeros(1, dtype=NP_DTYPE_IP_STATISTICS)

        # Determine whether the IP is in denylist and log accordingly
        if ip not in self._denylist:
            self._statistics[ip][0]['pkts_allowed'] += 1
        else:
            self._statistics[ip][0]['pkts_denied'] += 1


    def _log_prediction(self, ip: str, predicted_attack: bool, elapsed: int, loss: float) -> None:
        """Logs IP address prediction into internal statistics structures and updates denylist if needed.

        Parameters:
            ip               IP address to log
            predicted_attack Prediction of the ML model.  True for attack, False otherwise
            elapsed          Nanoseconds elapsed since the analysis start (a.k.a delta timestamp)
            loss             Loss score (e.g., reconstruction error) for the corresponding IP."""

        elapsed_s = common.time.nsec2seci(elapsed)      # Elapsed time in seconds

        self._per_ip_losses[ip] = loss

        if predicted_attack:
            # Attack detected - increment counters and print
            self._denylist[ip] = True
            self._statistics[ip][0]['detections_pos'] += 1

            if self._statistics[ip][0]['detected_after'] == 0:
                self._statistics[ip][0]['detected_after'] = elapsed_s

            if self._verbose:
                hhmmss = time.strftime("%H:%M:%S", time.gmtime(elapsed_s))

                print("{} - {} classified as attack".format(hhmmss, ip))

        else:
            # Legitimate traffic
            self._statistics[ip][0]['detections_neg'] += 1
