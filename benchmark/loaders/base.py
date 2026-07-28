"""Base loader interface + factory for the benchmark datasets.

All concrete loaders yield ``CanFrame`` objects in capture (timestamp) order.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import Iterator, List, Optional

from ..can_frame import CanFrame


class DatasetName(str, enum.Enum):
    CAR_HACKING = "car_hacking"
    OTIDS = "otids"
    CAN_FD = "can_fd"


class BaseLoader(ABC):
    """Abstract dataset loader.

    Concrete loaders take a file path (and optional attack-type / limit) and
    implement ``iter_frames``. ``load`` materializes the full list.
    """

    def __init__(self, path: str, attack_type: Optional[str] = None,
                 max_frames: Optional[int] = None) -> None:
        self.path = path
        self.attack_type = attack_type
        self.max_frames = max_frames

    @abstractmethod
    def iter_frames(self) -> Iterator[CanFrame]:
        """Yield normalized CanFrame objects in timestamp order."""
        raise NotImplementedError

    def load(self) -> List[CanFrame]:
        frames: List[CanFrame] = []
        for i, frame in enumerate(self.iter_frames()):
            if self.max_frames is not None and i >= self.max_frames:
                break
            frames.append(frame)
        return frames


def get_loader(dataset: DatasetName, path: str, **kwargs) -> BaseLoader:
    """Factory: return the concrete loader for a dataset name.

    Imports are local to avoid a circular import at package import time.
    """
    dataset = DatasetName(dataset)
    if dataset is DatasetName.CAR_HACKING:
        from .car_hacking import CarHackingLoader
        return CarHackingLoader(path, **kwargs)
    if dataset is DatasetName.OTIDS:
        from .otids import OtidsLoader
        return OtidsLoader(path, **kwargs)
    if dataset is DatasetName.CAN_FD:
        from .can_fd import CanFdLoader
        return CanFdLoader(path, **kwargs)
    raise ValueError(f"unknown dataset: {dataset!r}")
