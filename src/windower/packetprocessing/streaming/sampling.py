"""
Reservoir sampling algorithm for stream processing.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-04
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import random


class ReservoirSampler:
    """Reservoir sampling implementation as specified by [1].

    [1] LAHIRI Bibudh and TIRTHAPURA Srikanta. Stream Sampling. In Encyclopedia of Database Systems (2009 edition).
        May 2008. [Online]. Available: https://link.springer.com/referenceworkentry/10.1007%2F978-0-387-39940-9_372
    """

    def __init__(self, samples_num: int) -> None:
        """Initializes the sampler class.

        Parameters:
            samples_num Number of samples to store."""

        self.samples = [0] * samples_num    # Samples storage
        self.samples_num = samples_num      # Number of samples to store
        self.elems_processed = 0            # Number of elements already processed


    def sample(self, elem) -> None:
        """Samples a single element according to the reservoir sampling system.

        Parameters:
            elem Element to be sampled"""

        if self.samples_num > self.elems_processed:
            # Always add a sample to the list if samples_num is not met yet.
            self.samples[self.elems_processed] = elem
        else:
            # Determine if the element should be sampled
            # Choose a random element to replace
            replace_idx = random.randint(0, self.elems_processed)

            if self.samples_num > replace_idx:
                # Element should be sampled, replace the chosen one
                self.samples[replace_idx] = elem

        self.elems_processed += 1


    def get_samples(self):
        """Getter for samples list.

        Returns:
        [Samples] List of sampled elements with of a sample data type."""

        return self.samples


    def get_samples_cnt(self) -> int:
        """Returns the number of sampled elements.

        Returns:
        int Number of sampled elements."""

        return min(self.samples_num, self.elems_processed)


    @staticmethod
    def sample_stateless(elem, samples_storage, samples_max, elem_id):
        """Procedural version of Reservoir sampler algorithm in order to conserve memory and CPU utilization.

        Parameters:
            elem            Element to be processed by the sampler
            samples_storage List where the samples are stored
            samples_max     Maximum number of samples to store
            elem_id         Identifier of the processed element, starting from 0

        Returns:
        [Samples] List of sampled elements with of a sample data type."""

        if samples_max > elem_id:
            # Always add a sample to the list if samples_max is not met yet.
            samples_storage[elem_id] = elem
        else:
            # Determine if the element should be sampled
            # Choose a random element to replace
            replace_idx = random.randint(0, elem_id)

            if samples_max > replace_idx:
                # Element should be sampled, replace the chosen one
                samples_storage[replace_idx] = elem
