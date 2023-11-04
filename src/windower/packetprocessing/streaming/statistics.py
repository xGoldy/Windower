"""
Algorithms for streaming data processing and statistics computations.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-08
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import numpy as np


class Average:
    """Streaming data average computation."""

    def __init__(self) -> None:
        """Initializes the class object to its initial values with no elements processed."""

        self.avg = 0            # Running average value
        self.elems_num = 0      # Number of processed elements


    def process(self, elem) -> None:
        """Processes a single element, recomputing the running average in the process.

        Parameters:
            elem Element to the processed"""

        self.elems_num += 1
        self.avg        = self.avg + (elem - self.avg) / self.elems_num


    def get(self) -> np.double:
        """Obtains a running average value

        Returns:
            np.double Value of the running average"""

        return self.avg


    @staticmethod
    def avg_stateless(new_elem_val, prev_avg, new_elems_cnt):
        """(Re)computes an average of the stream in a classless manner.

        params: new_elem_val   Value of the new element to include
                prev_avg       Previously computed stream average
                new_elems_cnt  Number of elements including new_elem_val"""

        return prev_avg + (new_elem_val - prev_avg) / new_elems_cnt


class Variance:
    """Streaming data variance computation based on Welford's algorithm. Implementation according to [1].

    [1]: COOK John D. Accurately computing running variance. [Online]. Available at:
         https://www.johndcook.com/blog/standard_deviation/"""

    def __init__(self) -> None:
        """Initializes the class object to its initial values with no elements processed."""

        self.avg       = 0          # Running average value
        self.elems_cnt = 0          # Number of processed elements
        self.var_aux   = 0          # Auxiliary value (S) for variance computation


    def process(self, elem) -> None:
        """Processes a single element, internal variables and counters.

        Parameters:
            elem Element to the processed"""

        old_avg         = self.avg
        self.elems_cnt += 1
        self.avg        = Average.avgStateless(elem, self.avg, self.elems_cnt)
        self.var_aux    = self.var_aux + (elem - old_avg) * (elem - self.avg)


    def get(self) -> np.double:
        """Computes variance based on the number of processed elements and auxilliary variance value.

        Returns:
            np.double Approximate variance of all processed elements."""

        return (self.var_aux / (self.elems_cnt - 1)) if self.elems_cnt > 1 else 0


    @staticmethod
    def var_stateless(stream_var_aux_val, elems_cnt):
        """Computes stream (running) variance according to Welford's algorithm.
        Requires an auxiliary value S{k} computed by stream_var_aux() function. Afterwards, the
        function computes variance s^{2} as:
            s^{2} = S_{k} / (k-1)

        Parameters:
            stream_var_aux_val Auxiliary value for streaming variance computation
            elems_cnt          Number of elements included in stream_var_aux_val."""

        return (stream_var_aux_val / (elems_cnt - 1)) if elems_cnt > 1 else 0


    @staticmethod
    def var_aux_stateless(new_elem_val, prev_var_aux, prev_avg, new_avg):
        """Welford's running variance auxiliary value recomputation.
        Auxiliary value in k-th step S_{k} for stream variance is computed as:
            S_{k} = S_{k-1} + (x_{k} - m_{k-1}) * (x_{k} - m_{k})

        where: k    Computation step
            x_{k}   New element to include in variance computation
            m_{k}   Mean with element x_{k} already included
            m_{k-1} Previously computed mean without element x_{k}

        Parameters:
            new_elem_val Value of the new element to include
            prev_var_aux Previous auxiliary value for variance computation
            prev_avg     Previously computed average without new_elem_val included
            new_avg      Average with new_elem_val included"""

        return prev_var_aux + (new_elem_val - prev_avg) * (new_elem_val - new_avg)


class Entropy:
    """Provides interface for Shannon's entropy computation and its normalization."""

    @staticmethod
    def shannon(elems) -> np.double:
        """Computes a Shannon entropy for the data specified by list elems.
        Note that the algorithm is a modified version of [1].

        Parameters:
            elems List of samples to compute Shannon entropy for

        Returns:
            np.double Value of Shannon's entropy for given elements.

        [1]: https://gist.github.com/jaradc/eeddf20932c0347928d0da5a09298147"""

        elems_len = len(elems)
        entropy = 0.0

        if elems_len > 1:
            _, counts   = np.unique(elems, return_counts=True)
            probs       = counts / elems_len
            classes_num = np.count_nonzero(probs)

            if classes_num > 1:
                # Compute entropy
                for prob in probs:
                    entropy -= prob * np.log2(prob)

        return entropy


    @staticmethod
    def shannon_norm(elems) -> np.double:
        """Computes a normalized Shannon entropy for the sample data specified by list elems.
        Normalized Shannon entropy is defined in range [0,1] as:
            H_n(p) = - Sum (p_i log_b(p_i) / log_b n)
        for a vector p_i = 1/n for all i = 1, 2, ... n, such that n > 1

        Parameters:
            elems List of samples to compute Shannon entropy for

        Returns:
            np.double Value of Shannon's entropy for given elemens."""

        elems_cnt = len(elems)

        return Entropy.shannon(elems) / np.log2(elems_cnt) if elems_cnt != 1 else 0


    @staticmethod
    def shannon_dict(frequencies, elems_cnt) -> np.double:
        """Computes a Shannon entropy according to the obtained frequency table.

        Parameters:
            frequencies Frequency table (dictionary) to compute Shannon entropy for
            elems_cnt   Number of elements logged in the frequency table

        Returns:
            np.double Value of Shannon's entropy for given elemens."""

        # Instantly return 0 when only 1 distinct element is present
        if len(frequencies) == 1:
            return 0.0

        entropy = 0.0

        # Update entropy by iterating through all frequencies in the dictionary
        for freq in frequencies.values():
            prob = float(freq) / elems_cnt
            entropy += prob * np.log2(prob)

        return -entropy
