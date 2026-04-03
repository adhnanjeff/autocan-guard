import numpy as np
import time
from dataclasses import dataclass
from typing import Tuple

@dataclass
class VehicleState:
    x_position: float = 0.0
    y_position: float = 0.0
    speed: float = 0.0  # km/h
    steering_angle: float = 0.0  # degrees
    risk_level: str = "green"
    heading: float = 0.0  # degrees
    brake_pressure: float = 0.0  # percentage
    last_update: float = 0.0

class VehicleStateEngine:
    def __init__(self):
        self.state = VehicleState()
        self.state.last_update = time.time()
        self._brake_thread = None
        self._brake_active = False
        self._position_thread = None
        self._position_running = False
        self._manual_control = False  # Track if in manual control mode
        self._start_position_updates()
    
    def _start_position_updates(self):
        """Start continuous position updates"""
        self._position_running = True
        import threading
        
        def update_position_loop():
            while self._position_running:
                if self.state.speed > 0:  # Only update if moving
                    self._update_position()
                time.sleep(0.1)  # 10Hz update rate
        
        self._position_thread = threading.Thread(target=update_position_loop, daemon=True)
        self._position_thread.start()
    
    def update_speed(self, new_speed: float):
        """Update vehicle speed from CAN message"""
        # Ignore ECU speed updates if in manual control mode
        if self._manual_control:
            return
        # Only accept speed changes when not braking
        if not self._brake_active:
            self.state.speed = max(0, new_speed)
    
    def force_speed_update(self, new_speed: float):
        """Force speed update from user input (speed up/down buttons)"""
        self._manual_control = True  # Enable manual control mode
        self.state.speed = max(0, new_speed)
        print(f"🚗 Speed manually set to: {self.state.speed:.1f} km/h (manual control active)")
    
    def update_steering(self, steering_angle: float):
        """Update steering angle from CAN message"""
        self.state.steering_angle = np.clip(steering_angle, -45, 45)  # Realistic limits
        self._update_heading()
    
    def apply_brake(self, brake_pressure: float):
        """Apply brake from CAN message"""
        self.state.brake_pressure = max(0, min(brake_pressure, 100))  # Store brake pressure
        
        print(f"🛑 Brake pressure set to: {self.state.brake_pressure:.1f}%")
        
        # Start continuous braking if pressure > 0
        if brake_pressure > 0 and not self._brake_active:
            self._start_continuous_braking()
        elif brake_pressure == 0:
            self._stop_continuous_braking()
    
    def _start_continuous_braking(self):
        """Start continuous braking process"""
        if self._brake_active:
            return
            
        self._brake_active = True
        import threading
        
        def continuous_brake():
            while self._brake_active and self.state.brake_pressure > 0:
                # Apply deceleration based on current brake pressure
                deceleration_per_second = self.state.brake_pressure * 0.5  # 0.5 km/h per second per 1% brake
                deceleration_per_cycle = deceleration_per_second * 0.1  # 10Hz update rate
                
                old_speed = self.state.speed
                self.state.speed = max(0, self.state.speed - deceleration_per_cycle)
                
                if old_speed != self.state.speed:
                    print(f"🛑 Braking: {self.state.brake_pressure:.1f}% pressure, speed: {old_speed:.1f} → {self.state.speed:.1f} km/h")
                time.sleep(0.1)  # 10Hz update rate
            
            print(f"🛑 Continuous braking stopped")
            self._brake_active = False
        
        self._brake_thread = threading.Thread(target=continuous_brake, daemon=True)
        self._brake_thread.start()
    
    def _stop_continuous_braking(self):
        """Stop continuous braking"""
        self._brake_active = False
        self.state.brake_pressure = 0.0
        print(f"🛑 Brake released")
    
    def _update_position(self):
        """Update x,y position based on speed and heading"""
        current_time = time.time()
        dt = current_time - self.state.last_update
        
        # Ensure minimum time step for smooth movement
        if dt < 0.01:  # 100Hz max update rate
            return
            
        # Convert speed from km/h to m/s for position calculation
        speed_ms = self.state.speed / 3.6
        
        # Update position based on current heading
        self.state.x_position += speed_ms * np.cos(np.radians(self.state.heading)) * dt
        self.state.y_position += speed_ms * np.sin(np.radians(self.state.heading)) * dt
        
        self.state.last_update = current_time
    
    def _update_heading(self):
        """Update heading based on steering angle and speed"""
        current_time = time.time()
        dt = current_time - self.state.last_update
        
        if dt < 0.01:  # Minimum time step
            return
            
        if self.state.speed > 0 and abs(self.state.steering_angle) > 0.1:
            # Only turn when there's significant steering input
            # Turn rate proportional to steering angle and speed
            turn_rate = self.state.steering_angle * 2.0  # degrees per second
            heading_change = turn_rate * dt
            self.state.heading += heading_change
            self.state.heading = self.state.heading % 360  # Keep in 0-360 range
        
        self.state.last_update = current_time
    
    def get_state(self) -> VehicleState:
        """Get current vehicle state"""
        return self.state
    
    def reset_vehicle(self):
        """Reset vehicle to initial state"""
        self._stop_continuous_braking()  # Stop any active braking
        self._manual_control = False  # Disable manual control
        self.state.speed = 30.0
        self.state.steering_angle = 0.0
        self.state.heading = 0.0
        self.state.brake_pressure = 0.0  # Reset brake pressure
        self.state.last_update = time.time()
        print(f"🔄 Vehicle reset: Speed={self.state.speed:.1f} km/h, Steering={self.state.steering_angle:.1f}°, Brake=0%")
    
    def stop_engine(self):
        """Stop all engine threads"""
        self._position_running = False
        self._brake_active = False