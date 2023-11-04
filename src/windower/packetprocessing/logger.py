"""
Module for logging and storing packet features.  Handles windowing and statistics computation.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-26
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import HLL
import math
import numpy as np
import pandas as pd

from common import defines
from common.time import sec2nsec, nsec2sec
from packetprocessing.logtypes import *
from packetprocessing.extractor import PacketFeatures, PROTO_L4_ICMP, PROTO_L4_TCP, PROTO_L4_UDP
from packetprocessing.streaming.sampling import ReservoirSampler
from packetprocessing.streaming.statistics import Average, Variance, Entropy
from dataclasses import dataclass
from cachetools import TTLCache, LRUCache


# Module configuration settings
MODULE_NAME = "logger"
MODULE_CONFIG = {
    defines.CONF_PARAMS_MANDATORY: ['window_length'],
    defines.CONF_PARAMS_DEFAULTS: {'history_min': 6, 'history_timeout': 120, 'packets_min': 15, 'samples_size': 40,
        'history_size': 0},
    defines.CONF_PARAMS_INTS: ['history_size', 'history_min', 'packets_min', 'samples_size'],
    defines.CONF_PARAMS_FLOATS: ['window_length', 'history_timeout'],
    defines.CONF_PARAMS_STRINGS: None,
    defines.CONF_PARAMS_BOOLS: None
}

# As memory of the computer is limited, "infinity" of history size was set to 25M entries by default.
# This corresponds to approximately 6GB of memory. Along with other memory requirements of other modules
# (such as packet handler statistics, this seems like a reasonable trade-off). Set the size manually if
# more is desired
HISTORY_SIZE_DEFAULT = 30000000

# On the real network, history traces should be cleared every few minutes. If "infinity" is desired,
# a resonable value might be 4 hours, allowing very large windows and still getting rid of old entries
# relatively often
HISTORY_TIMEOUT_DEFAULT = 14400

# Number of hyperloglog bits for registers to use
# Standard deviation of accuracy is computed as 1.04 / sqrt(2^bits), giving 4.60% standard error for value of 9
HYPERLOGLOG_BITS = 9


@dataclass
class IPWindow:
    """Window for packet statistical logging for a single IP address"""
    stats:           np.ndarray             # Statistics collected in the window
    aux:             np.ndarray             # Auxiliary data for statistics computation
    sport_samples:   list                   # Source port samples for entropy copmutation
    src_ports_hll:   HLL.HyperLogLog        # HyperLogLog for unique source ports
    connections_hll: HLL.HyperLogLog        # HyperLogLog for unique connections


class Logger:
    """Interface for packets logging, storing, and statistics computation."""

    def __init__(self, window_length: float, history_min: int = 6, history_size: int = 0, history_timeout: int = 0,
    packets_min: int = 20, samples_size: int = 40) -> None:
        """Initializes the logger object.

        Parameters:
            window_length   Size of the window in seconds. Informational value used for statistics computation.
                            Note that the actual window timing is independent of this value.
            history_min     Minimum number of historical logs to consider computing statistics for
            history_size    Maximum number of historical logs to be stored in the memory. Use 0 for unlimited
            history_timeout Maximum number of seconds to consider history logs valid.  Use 0 for no timeout
            packets_min     Minimum number of packets in a window to log it. Windows with lesser number of packets
                            are ignored
            samples_size    Number of samples to collect for various computations.
        """

        # Set history_size and history_timeout to very large numbers to simulate "infinity"
        history_size    = history_size if history_size > 0 else HISTORY_SIZE_DEFAULT
        history_timeout = history_timeout if history_timeout > 0 else HISTORY_TIMEOUT_DEFAULT

        self._history_timeout = sec2nsec(history_timeout)   # Maximum time to consider history
        self._history_min     = history_min                 # Minimum historical events for stats computation
        self._packets_min     = packets_min                 # Minimum number of packets in the time window
        self._samples_size    = samples_size                # Number of samples to store for entropy computation
        self._window_current  = {}                          # Current window statistics
        self._window_id       = 0                           # Window identifier
        self._window_length   = sec2nsec(window_length)     # Size of a single window in nanoseconds


        # Create a timeouting dictionary to store window statistics and mark IPs with enough collected data
        self._window_history  = TTLCache(maxsize=history_size, ttl=history_timeout, getsizeof=len)
        self._ready_ips = LRUCache(maxsize=int(history_size / history_min))


    def clear(self) -> None:
        """Clears the logger module internal structures, keeping the current configuration intact."""

        self._window_current = {}
        self._window_id = 0

        self._window_history.clear()
        self._ready_ips.clear()


    def log(self, features: PacketFeatures) -> None:
        """Logs features extracted from packet data into currently active window.

        Parameters:
            features Features extracted from the packet."""

        if features.src_ip in self._window_current:
            # Add to statistics in the current window
            self._log_existing_ip(features)
        else:
            # No record for the source IP in the current time window exist - create it
            self._window_current[features.src_ip] = IPWindow(
                np.zeros(1, dtype=NP_DTYPE_WINDOW_STATS),
                np.zeros(1, dtype=NP_DTYPE_WINDOW_AUXDATA),
                [0] * self._samples_size,
                HLL.HyperLogLog(HYPERLOGLOG_BITS),
                HLL.HyperLogLog(HYPERLOGLOG_BITS)
            )

            self._log_new_ip(features)

        # Log other statistics common for both types of IPs
        self._log_common(features)


    def end_window(self) -> None:
        """Ends currently active window."""

        # Save current window ID and increment it
        cur_window_id   = self._window_id
        self._window_id += 1

        # Iterate through all IP addresses in the window and log them in history if desired
        for ip, window_data in self._window_current.items():
            if window_data.stats[0]['pkts_total'] >= self._packets_min:
                # The window data for particular IP qualify for being processed
                # Set the window ID
                window_data.stats[0]['window_id'] = cur_window_id
                samples = window_data.sport_samples[:window_data.stats[0]['pkts_total']]

                # Compute standard deviation from auxiliary data
                window_data.stats[0]['pkt_arrivals_std'] = math.sqrt(Variance.var_stateless(
                    window_data.aux[0]['pkt_arrivals_std_aux'], window_data.stats[0]['pkts_total']))
                window_data.stats[0]['pkt_size_std'] = math.sqrt(Variance.var_stateless(
                    window_data.aux[0]['pkt_size_std_aux'], window_data.stats[0]['pkts_total']))

                # Retrieve approximation of unique number of ports and compute source port entropy
                window_data.stats[0]['port_src_unique'] = window_data.src_ports_hll.cardinality()
                window_data.stats[0]['port_src_entropy'] = Entropy.shannon_norm(samples)

                # Compute average number of packets per single connection
                window_data.stats[0]['conn_pkts_avg'] = \
                    float(window_data.stats[0]['pkts_total']) / window_data.connections_hll.cardinality()

                # Save the computed statistics into history
                if ip in self._window_history:
                    self._window_history[ip].append(window_data.stats)

                    if len(self._window_history[ip]) >= self._history_min:
                        # Determine if there are enough non-expired logs for the IP to be considered ready
                        approx_cur_time   = window_data.stats[0]['tstamp_end']
                        boundary_log_time = self._window_history[ip][-self._history_min][0]['tstamp_start']

                        if self._history_timeout > approx_cur_time - boundary_log_time:
                            # Boundary log is within time range - mark the IP address as ready
                            self._ready_ips[ip] = True
                        else:
                            # Boundary log has already expired - determine if to remove only it or multiple ones
                            if len(self._window_history[ip]) == self._history_min:
                                self._window_history[ip].pop(0)
                            else:
                                self._window_history[ip] = self._window_history[-self._history_min:]
                else:
                    self._window_history[ip] = [window_data.stats]

        # Empty the current widow
        self._window_current = {}


    def find_candidates(self) -> list:
        """Obtains IP addresses with sufficient number of history entries available for classification purposes."""

        return list(self._ready_ips.keys())


    def retrieve_statistics(self, ip: str, current_time: int = None, compute_interwindow_stats: bool = True,
        window_cnt: int = None, dump_windows: bool = False, delete_after: bool = True) -> pd.DataFrame:
        """Retrieve statistics of the particular IP address. Inter-window statistics are implicitly calculated, but
        can be specified otherwise.  The function averages statistics from the last window_cnt windows.  Contents of
        windows can also be dumped straightly without averaging for models that can utilize context information such as
        recurrent neural networks. All windows are deleted after this process implicitly (controlled by delete_after).

        Parameters:
            ip                        IP address to retrieve statistics for
            current_time              Current timestamp in nanoseconds to determine which window stats are outdated.
                                      If set to None, all stats are used.
            compute_interwindow_stats Whether the inter-window statistics should be calculated
            window_cnt                Number of windows to compute statistics from.  None takes all available
                                      non-expired ones
            dump_windows              Whether all windows should be dumped without their averaging.  If set to True, no
                                      inter-window statistics are computed
            delete_after              Whether windows for a particular IP address should be deleted after the process.

        Returns:
            pd.DataFrame Statistics as a single-row Pandas dataframe data.  If dump_windows is specified, multiple rows
                         in the dataframe are provided
            None         If the input IP address is invalid or no viable window data for it exists"""

        logs_to_keep  = 0       # How many longs have to be kept by slicing

        if ip not in self._window_history:
            return None

        # Retrieve list of the windows for a particular IP address
        window_stats = self._window_history[ip]

        # Delete the history statistics for a particular IP if desired and remove from ready dict
        if delete_after:
            del self._window_history[ip]

        self._ready_ips.pop(ip, None)

        # Determine how many windows to use for computation
        logs_to_keep = len(window_stats) if window_cnt is None else window_cnt

        if self._history_timeout != 0 and current_time is not None:
            logs_to_keep  = 0

            # Older logs can be timeouted, determine which of them are still valid
            for stat in reversed(window_stats):
                if current_time - stat[0]['tstamp_start'] < self._history_timeout:
                    logs_to_keep += 1
                else:
                    break

        # Make sure that minimum number of windows will always be met regardless of expiration time
        if logs_to_keep < self._history_min:
            logs_to_keep = self._history_min

        # Perform the slicing
        window_stats = window_stats[-logs_to_keep:]

        # Preallocate numpy array and merge statistics from all windows
        merged_stats = np.zeros((len(window_stats),), dtype=NP_DTYPE_WINDOW_STATS)

        for idx in range(len(window_stats)):
            merged_stats[idx] = window_stats[idx]

        # Dump windows statistics straightly if desired
        if dump_windows:
            return pd.DataFrame(merged_stats, columns=NP_DTYPE_WINDOW_STATS.names)

        # Summarize all viable windows
        result_stats = pd.DataFrame(self._summarize_windows(ip, merged_stats))

        # Compute interwindow statistics if desired
        if compute_interwindow_stats:
            interwind_stats = pd.DataFrame(self._compute_interwindows(merged_stats))
            result_stats = result_stats.merge(interwind_stats, left_index=True, right_index=True)

        return result_stats


    def set_window_length(self, new_size: float) -> None:
        """Sets the new informational value for logger's window size.  Note that this value is only informational
        and the actual windowing need to be performed externally by caling end_window() method.

        Parameters:
            new_size Used size of the window in seconds."""

        self._window_length = sec2nsec(new_size)


    @staticmethod
    def memory2history_elements(memory: int) -> int:
        """Computes number of history elements for Logger's constructor parameter history_size.

        Parameters:
            memory Memory available for the history elements in MB."""

        bytes_available = memory * 1024 * 1024

        return int(math.ceil(bytes_available / NP_WINDOW_STATS_ARRAY_SIZE))


    def _compute_interwindows(self, window_stats: np.ndarray) -> np.ndarray:
        """Computes interwindow statistics based on received window_stats by averaging

        Parameters:
            window_stats Numpy array shaped (N,) with dtype NP_DTYPE_WINDOW_STATS to compute interwindow stats for."""

        interwindows = np.zeros((1,), dtype=NP_DTYPE_INTERWINDOW_STATS)

        # Compute standard deviation of picked statistics of the windows.
        interwindows[0]['pkts_total_std']       = np.std(window_stats['pkts_total'])
        interwindows[0]['bytes_total_std']      = np.std(window_stats['bytes_total'])
        interwindows[0]['pkt_size_avg_std']     = np.std(window_stats['pkt_size_avg'])
        interwindows[0]['pkt_size_std_std']     = np.std(window_stats['pkt_size_std'])
        interwindows[0]['pkt_arrivals_avg_std'] = np.std(window_stats['pkt_arrivals_avg'])
        interwindows[0]['port_src_unique_std']  = np.std(window_stats['port_src_unique'])
        interwindows[0]['port_src_entropy_std'] = np.std(window_stats['port_src_entropy'])
        interwindows[0]['conn_pkts_avg_std']    = np.std(window_stats['conn_pkts_avg'])
        interwindows[0]['pkts_frag_share_std']  = np.std(window_stats['pkts_frag_count'] / window_stats['pkts_total'])
        interwindows[0]['hdrs_payload_ratio_avg_std'] = np.std(window_stats['hdrs_payload_ratio_avg'])

        # Determine the most dominant L4 protocol across windows
        total_tcp_pkts  = np.sum(window_stats['tcp_pkt_count'])
        total_udp_pkts  = np.sum(window_stats['udp_pkt_count'])
        total_icmp_pkts = np.sum(window_stats['icmp_pkt_count'])
        dominant_proto_ratios = None

        if max(total_tcp_pkts, total_udp_pkts, total_icmp_pkts) == total_tcp_pkts:
            # TCP is the most dominant
            dominant_proto_ratios = window_stats['tcp_pkt_count'] / window_stats['pkts_total']
        elif max(total_tcp_pkts, total_udp_pkts, total_icmp_pkts) == total_udp_pkts:
            # UDP is the most dominant
            dominant_proto_ratios = window_stats['udp_pkt_count'] / window_stats['pkts_total']
        else:
            # ICMP is the most dominant
            dominant_proto_ratios = window_stats['icmp_pkt_count'] / window_stats['pkts_total']

        # Compute standard deviation of the most dominant protocol ratios
        interwindows[0]['dominant_proto_ratio_std'] = np.std(dominant_proto_ratios)

        # Intra-window activity ratio as a time host was communicating within windows / captured time period
        total_time = window_stats.size * self._window_length
        total_activity = window_stats['tstamp_end'] - window_stats['tstamp_start']

        interwindows[0]['intrawindow_activity_ratio'] = np.sum(total_activity) / total_time

        # Inter-window activity ratio as a difference between the 1st and last processed window ID / processed windows
        interwindows[0]['interwindow_activity_ratio'] = window_stats.size / self._compute_window_span(window_stats)

        return interwindows


    @staticmethod
    def _summarize_windows(ip_addr: str, window_stats: np.ndarray) -> np.ndarray:
        """Computes summary statistics of multiple windows specified by window_stats.  Summaries are computed by
        averaging.

        Parameters
            ip_addr      IP address corresponding to windows being summarized
            window_stats Numpy array shaped (N,) with dtype NP_DTYPE_WINDOW_STATS to compute summary stats for."""

        summary_stats = np.zeros((1,), dtype=NP_DTYPE_WINDOW_SUMMARY_STATS)              # Summary stats to return
        proto_tcp_shares  = window_stats['tcp_pkt_count'] / window_stats['pkts_total']   # TCP ratios across windows
        proto_udp_shares  = window_stats['udp_pkt_count'] / window_stats['pkts_total']   # UDP ratios across windows
        proto_icmp_shares = window_stats['icmp_pkt_count'] / window_stats['pkts_total']  # ICMP ratios across windows
        pkts_frag_shares  = window_stats['pkts_frag_count'] / window_stats['pkts_total'] # Fragmented packets ratios

        # Set the number of totally summarized windows
        summary_stats[0]['window_count'] = window_stats.size
        summary_stats[0]['window_span']  = Logger._compute_window_span(window_stats)

        # Window span is the last window ID - first window ID with possible overflows taken into account
        first_window_id = window_stats[0]['window_id']
        last_window_id  = window_stats[window_stats.size - 1]['window_id']

        if last_window_id > first_window_id:
            summary_stats[0]['window_span'] = last_window_id - first_window_id + 1
        else:
            # Overflow would occur
            summary_stats[0]['window_span'] = last_window_id + 2**32 - first_window_id + 1

        # Set the IP address
        summary_stats[0][defines.DATA_SRC_IP_COLNAME] = ip_addr

        # Compute average values of windows values
        summary_stats[0]['pkts_total']       = np.average(window_stats['pkts_total'])
        summary_stats[0]['bytes_total']      = np.average(window_stats['bytes_total'])
        summary_stats[0]['pkt_arrivals_avg'] = np.average(window_stats['pkt_arrivals_avg'])
        summary_stats[0]['pkt_arrivals_std'] = np.average(window_stats['pkt_arrivals_std'])
        summary_stats[0]['pkt_size_avg']     = np.average(window_stats['pkt_size_avg'])
        summary_stats[0]['pkt_size_std']     = np.average(window_stats['pkt_size_std'])
        summary_stats[0]['proto_tcp_share']  = np.average(proto_tcp_shares)
        summary_stats[0]['proto_udp_share']  = np.average(proto_udp_shares)
        summary_stats[0]['proto_icmp_share'] = np.average(proto_icmp_shares)
        summary_stats[0]['port_src_unique']  = np.average(window_stats['port_src_unique'])
        summary_stats[0]['port_src_entropy'] = np.average(window_stats['port_src_entropy'])
        summary_stats[0]['conn_pkts_avg']    = np.average(window_stats['conn_pkts_avg'])
        summary_stats[0]['pkts_frag_share']  = np.average(pkts_frag_shares)
        summary_stats[0]['hdrs_payload_ratio_avg'] = np.average(window_stats['hdrs_payload_ratio_avg'])

        # Compute min-max summary statistics
        summary_stats[0]['pkt_size_min'] = np.amin(window_stats['pkt_size_min'])
        summary_stats[0]['pkt_size_max'] = np.amax(window_stats['pkt_size_max'])

        # Compute rates
        # If only 1 window with only 1 packet would be processed, this would be division by 0.  Let's suppose the
        # program will not be used that way, because additional IF-checking would be costly for no reason.
        # If you got an exception for these lines, you are probably using the ML extraction with wrong settings.
        summary_stats[0]['pkt_rate'] = np.sum(window_stats['pkts_total']) / nsec2sec(
            window_stats[window_stats.size - 1]['tstamp_end'] - window_stats[0]['tstamp_start'])
        summary_stats[0]['byte_rate'] = np.sum(window_stats['bytes_total']) / nsec2sec(
            window_stats[window_stats.size - 1]['tstamp_end'] - window_stats[0]['tstamp_start'])

        return summary_stats


    @staticmethod
    def _compute_window_span(window_stats: np.ndarray) -> int:
        window_span     = 0
        first_window_id = window_stats[0]['window_id']
        last_window_id  = window_stats[window_stats.size - 1]['window_id']

        if last_window_id > first_window_id:
            window_span = last_window_id - first_window_id + 1
        else:
            # Overflow would occur
            window_span = last_window_id + 2**32 - first_window_id + 1

        return window_span


    def _log_new_ip(self, features: PacketFeatures) -> None:
        """Logs packet features into the currently active logging window for IP addresses that have NOT been logged
        in the window before.

        Parameters:
            features Features extracted from the packet."""

        stats    = self._window_current[features.src_ip].stats      # Current window IP's corresponding stats
        pkt_size = features.len_headers + features.len_payload      # Total size of the packet

        # Always sample the first element source port
        self._window_current[features.src_ip].sport_samples[0] = features.src_port

        # Update window summary statistics
        stats[0]['pkts_total']  = 1
        stats[0]['bytes_total'] = pkt_size

        # Update time statistics
        stats[0]['tstamp_start'] = features.time
        stats[0]['tstamp_end']   = features.time

        # Update packet size statistics
        stats[0]['pkt_size_min'] = pkt_size
        stats[0]['pkt_size_max'] = pkt_size
        stats[0]['pkt_size_avg'] = pkt_size

        # Update headers & payloads statistics
        stats[0]['hdrs_payload_ratio_avg'] = float(features.len_headers) / pkt_size


    def _log_existing_ip(self, features: PacketFeatures) -> None:
        """Logs packet features into the currently active logging window for IP addresses that have already been logged
        in the window.

        Parameters:
            features Features extracted from the packet."""

        auxdata       = self._window_current[features.src_ip].aux          # Current window IP's corresponding auxdata
        stats         = self._window_current[features.src_ip].stats        # Current window IP's corresponding stats
        pkt_size      = features.len_headers + features.len_payload        # Total size of the packet
        pkt_hdr_ratio = float(features.len_headers) / pkt_size             # Header to whole packet size ratio
        pkt_arrival_delay = features.time - auxdata[0]['last_pkt_arrival'] # Delay between this and the previous packet
        prev_pkt_arrivals_avg = stats[0]['pkt_arrivals_avg']               # Previously computed packet arrivals delay
        prev_pkt_size_avg     = stats[0]['pkt_size_avg']                   # Previously computed packet sizes average

        # Sample the source port using reservoir sampling
        ReservoirSampler.sample_stateless(features.src_port, self._window_current[features.src_ip].sport_samples,
            self._samples_size, stats[0]['pkts_total'])

        # Update window summary statistics
        stats[0]['pkts_total']  += 1
        stats[0]['bytes_total'] += pkt_size

        # Update time statistics
        stats[0]['tstamp_end'] = features.time
        stats[0]['pkt_arrivals_avg'] = Average.avg_stateless(pkt_arrival_delay, prev_pkt_arrivals_avg,
            stats[0]['pkts_total'])

        # Update packet size statistics
        stats[0]['pkt_size_min'] = stats[0]['pkt_size_min'] if pkt_size > stats[0]['pkt_size_min'] else pkt_size
        stats[0]['pkt_size_max'] = stats[0]['pkt_size_max'] if pkt_size < stats[0]['pkt_size_max'] else pkt_size
        stats[0]['pkt_size_avg'] = Average.avg_stateless(pkt_size, prev_pkt_size_avg, stats[0]['pkts_total'])

        # Update headers & payloads statistics
        stats[0]['hdrs_payload_ratio_avg'] = Average.avg_stateless(pkt_hdr_ratio, stats[0]['hdrs_payload_ratio_avg'],
            stats[0]['pkts_total'])

        # Update auxiliary data
        auxdata[0]['pkt_arrivals_std_aux'] = Variance.var_aux_stateless(pkt_arrival_delay,
            auxdata[0]['pkt_arrivals_std_aux'], prev_pkt_arrivals_avg, stats[0]['pkt_arrivals_avg'])
        auxdata[0]['pkt_size_std_aux'] = Variance.var_aux_stateless(pkt_size, auxdata[0]['pkt_size_std_aux'],
            prev_pkt_size_avg, stats[0]['pkt_size_avg'])


    def _log_common(self, features: PacketFeatures) -> None:
        """Common logging function for both new and existing IPs and are independent of other logging operations and
        their order.

        Parameters:
            features Features extracted from the packet."""

        auxdata = self._window_current[features.src_ip].aux          # Current window IP's corresponding auxdata
        stats   = self._window_current[features.src_ip].stats        # Current window IP's corresponding stats

        # Update last packet arrival
        auxdata[0]['last_pkt_arrival'] = features.time

        # Log correct segment type
        if features.proto_l4 == PROTO_L4_TCP:
            stats[0]['tcp_pkt_count']  += 1
        elif features.proto_l4 == PROTO_L4_UDP:
            stats[0]['udp_pkt_count']  += 1
        elif features.proto_l4 == PROTO_L4_ICMP:
            stats[0]['icmp_pkt_count'] += 1

        # Increase fragmented packets counter upon fragment
        if features.fragmented:
            stats[0]['pkts_frag_count'] += 1

        # Log into probabilistic data structures
        self._window_current[features.src_ip].src_ports_hll.add(str(features.src_port))
        self._window_current[features.src_ip].connections_hll.add(str(features.src_port) + features.dst_ip +
            str(features.dst_port))
