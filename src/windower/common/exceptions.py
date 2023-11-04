"""
Custom exceptions definitions thrown by various modules to avoid redefinitions.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-22
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

class ArgumentCombinationException(Exception):
    """Invalid argument combination exception that ArgParser throws."""

    def __init__(self, msg: str) -> None:
        """Constructor for Argument combination exception object.

        Parameters:
            msg Message describing the exception"""

        super().__init__(msg)
