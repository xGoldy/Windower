
import numpy
import logging
import weakref
import sys

import tables

import utils

logger = logging.getLogger(__name__)

class FeatureReaderCSV:

    @staticmethod
    def _close_file(file_handle):
        file_handle.close()

    def __init__(self, file_path, limit=sys.maxsize) -> None:
        utils.check_file(file_path, ext="csv")

        self._file_handle = open(file_path, 'rt', encoding="utf8")
        self._finalizer = weakref.finalize(self, FeatureReaderCSV._close_file, self._file_handle)

        self._file_lines = utils.get_csv_lines_count(file_path)
        self._file_columns = utils.get_csv_columns_count(file_path)

        self._index = 0
        self._limit = min(limit, self._file_lines)

    def __iter__(self):
        return self

    def __len__(self):
        return self._limit

    def __next__(self):
        if self._index == self._limit:
            raise StopIteration

        line = self._file_handle.readline()
        if not line:
            raise StopIteration

        self._index = self._index + 1

        return numpy.fromstring(line, sep=",")

    def get_num_features(self):
        return self._file_columns


class FeatureReaderH5:

    @staticmethod
    def _close_file(file_handle):
        file_handle.close()

    def __init__(self, file_path, limit=sys.maxsize) -> None:
        utils.check_file(file_path, ext="h5")

        file_handle = tables.open_file(file_path, mode='r')
        self._finalizer = weakref.finalize(self, FeatureReaderH5._close_file, file_handle)

        self._array = file_handle.root.data
        self._file_lines = self._array.shape[0]
        self._file_columns = self._array.shape[1]

        self._limit = min(limit, self._file_lines)

    def __iter__(self):
        return self._array.iterrows(stop=self._limit)

    def __len__(self):
        return self._limit

    def get_num_features(self):
        return self._file_columns


class FeatureReaderMulti:

    @staticmethod
    def _close_file(file_handle):
        file_handle.close()

    def __init__(self, readers, limit=sys.maxsize) -> None:
        self._readers = readers
        self._features = 0
        self._index = 0
        self._limit = 0
        self._ptr = 0

        for reader in self._readers:
            self._limit += len(reader)

            features = reader.get_num_features()

            if self._features == 0:
                self._features = features
            else:
                if self._features != features:
                    raise Exception(f"All the readers do not have {self._features} features.")

        if limit != sys.maxsize and self._limit < limit:
            raise Exception(f"Not enough samples in the input data ({self._limit} < {limit}).")

        self._limit = min(limit, self._limit)
        self._iterator = iter(self._readers[self._ptr])

    def __iter__(self):
        return self

    def __next__(self):
        if self._index == self._limit:
            raise StopIteration

        try:
            ret = next(self._iterator)
        except StopIteration:
            self._ptr = self._ptr + 1
            self._iterator = iter(self._readers[self._ptr])
            ret = next(self._iterator)

        self._index = self._index + 1

        return ret

    def __len__(self):
        return self._limit

    def get_num_features(self):
        return self._features
