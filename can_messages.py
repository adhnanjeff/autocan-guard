"""
Shared CAN message classes for generator and listener
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class CANMessage:
    arbitration_id: int
    data: bytes
    timestamp: float = 0.0

@dataclass
class ECUCommand:
    speed_delta: float = 0.0
    steering_delta: float = 0.0
    brake_pressure: float = 0.0
    reset: bool = False