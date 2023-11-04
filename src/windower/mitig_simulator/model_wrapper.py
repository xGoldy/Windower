"""
Wrapper around the attack discriminator model.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-06-02
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import numpy as np
import pickle

from abc import ABC, abstractmethod


class ModelWrapper(ABC):
    """Base class for the model wrapper."""

    def __init__(self, model) -> None:
        self._model = None

        with open(model, 'rb') as file_model:
            self._model = pickle.load(file_model)

    @abstractmethod
    def __call__(self, data: np.ndarray) -> np.ndarray:
        """Call for the model evaluation.

        Parametrs:
            data NxM Matrix of N feature vectors of size M

        Returns:
            np.ndarray Vector Nx1 of predictions"""
        pass


class KitNetWrapper(ModelWrapper):
    """Kitnet Abstract class wrapper."""

    def __init__(self, model) -> None:
        super().__init__(model)

    def __call__(self, data: np.ndarray) -> np.ndarray:
        rmses = np.empty(data.shape[0], dtype=np.float32)

        for idx, feature_vec in enumerate(data):
            rmses[idx] = self._model.process(feature_vec)

        return rmses


class SklearnWrapper(ModelWrapper):
    """Wrapper around sklearn models."""

    def __init__(self, model) -> None:
        super().__init__(model)

    def __call__(self, data: np.ndarray) -> np.ndarray:
        return self._model.predict(data)
