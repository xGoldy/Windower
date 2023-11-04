
import csv
import logging
import weakref
import sys

import numpy as np

from netStat import netStat
import utils

logger = logging.getLogger(__name__)

class FeatureExtractor:

    @staticmethod
    def _close_file(file_handle):
        file_handle.close()

    def __init__(self, file_path, limit=sys.maxsize, lambdas=None):
        utils.check_file(file_path, ext="tsv")

        self._file_lines = utils.get_csv_lines_count(file_path)
        self._file_handle = open(file_path, 'rt', encoding="utf8")
        self._finalizer = weakref.finalize(self, FeatureExtractor._close_file, self._file_handle)

        self._file_reader = csv.reader(self._file_handle, delimiter='\t')
        next(self._file_reader) # move iterator past header

        self._index = 0
        self._limit = min(limit, self._file_lines-1)

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self._nstats = netStat(lambdas, maxHost, maxSess)

    def __iter__(self):
        return self

    def __len__(self):
        return self._limit

    def __next__(self):
        if self._index == self._limit:
            raise StopIteration

        row = self._file_reader.__next__()
        IPtype = np.nan
        timestamp = row[0]
        framelen = row[1]
        srcIP = ''
        dstIP = ''

        srcMAC = row[2]
        dstMAC = row[3]

        if row[4] != '':  # IPv4
            srcIP = row[4]
            dstIP = row[5]
            IPtype = 0
        elif row[17] != '':  # ipv6
            srcIP = row[17]
            dstIP = row[18]
            IPtype = 1

        # UDP or TCP (one string id always empty)
        srcproto = row[6] + row[8]
        dstproto = row[7] + row[9]

        if srcproto == '':  # it's a L2/L1 level protocol
            if row[12] != '':  # is ARP
                srcproto = 'arp'
                dstproto = 'arp'
                srcIP = row[14]  # src IP (ARP)
                dstIP = row[16]  # dst IP (ARP)
                IPtype = 0
            elif row[10] != '':  # is ICMP
                srcproto = 'icmp'
                dstproto = 'icmp'
                IPtype = 0

            #no Network layer, use MACs
            elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                srcIP = row[2]  # src MAC
                dstIP = row[3]  # dst MAC

        self._index = self._index + 1

        try:
            vector = self._nstats.updateGetStats(
                srcMAC,
                dstMAC,
                srcIP,
                srcproto,
                dstIP,
                dstproto,
                int(framelen),
                float(timestamp)
            )

            return vector
        except Exception as e:
            logger.error(e)
            raise StopIteration

    def get_num_features(self):
        return len(self._nstats.getNetStatHeaders())
