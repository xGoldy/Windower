
import os
import csv
import contextlib
import logging
import sys

logger = logging.getLogger(__name__)

@contextlib.contextmanager
def open_output(filename=None, mode='w', **kwargs):
    if filename and filename != '-':
        fh = open(filename, mode, **kwargs)
    else:
        fh = sys.stdout

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()

@contextlib.contextmanager
def open_input(filename=None, mode='r', **kwargs):
    if filename and filename != '-':
        fh = open(filename, mode, **kwargs)
    else:
        fh = sys.stdin

    try:
        yield fh
    finally:
        if fh is not sys.stdin:
            fh.close()

def check_file(file_path, ext="tsv"):
    if not os.path.isfile(file_path):
        raise Exception(f"File '{file_path}' does not exist")

    file_type = file_path.split('.')[-1]
    if file_type != ext:
        raise Exception(f"Only .{ext} file supported, '{file_type}' given")

def get_csv_lines_count(file_path):
    logger.debug(f"counting lines in '{file_path}' file")
    num_lines = sum(1 for line in open(file_path))
    logger.info(f"there are {num_lines} packets")
    return num_lines

def get_csv_columns_count(file_path):
    with open(file_path, newline='', encoding="utf8") as csvfile:
        reader = csv.reader(csvfile, )
        row = next(reader)
        return len(row)
