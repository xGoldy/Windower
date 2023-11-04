"""
Utilities for time conversion between seconds and nanoseconds

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-08
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

# 1 second in nanoseconds
NSEC_IN_SEC = 1000000000


def sec2nsec(seconds) -> int:
    """Converts seconds to nanoseconds.

    Parameters:
        seconds Value in seconds to convert

    Returns:
        int Value supplied in parameter converted to nanoseconds"""

    return int(seconds * NSEC_IN_SEC)


def nsec2sec(nanoseconds) -> float:
    """Converts nanoseconds to floating point seconds value.

    Parameters:
        seconds Value in nanoseconds to convert

    Returns:
        int Value supplied in parameter converted to floating point seconds"""

    return float(nanoseconds) / NSEC_IN_SEC


def nsec2seci(nanoseconds) -> int:
    """Converts nanoseconds to seconds and rounds to nearest integer.

    Parameters:
        seconds Value in nanoseconds to convert

    Returns:
        int Value supplied in parameter rounded to nearest value in seconds"""

    return round(float(nanoseconds) / NSEC_IN_SEC)
