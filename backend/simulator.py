"""
IronLedger - ICS / SCADA Simulation Engine
Simulates industrial physical entities (Centrifugal Pumps, Pressure Vessels, Control Valves, SIS),
generates realistic sensor telemetry, and handles command dispatch and attack injection scenarios.
"""

import time
import math
import random
from typing import Dict, Any, List, Optional

class ICSSimulator:
    def __init__(self):
        self.reset_state()

    def reset_state(self):
        self.tick_count = 0
        self.last_update_time = time.time()
        
        # Physical Entities
        self.pump_a = {
            "id": "PUMP_A_01",
            "name": "Main Feed Pump A",
            "state": "RUNNING", # RUNNING, STOPPED, FAULT
            "rpm": 2400.0,
            "target_rpm": 2400.0,
            "max_rpm": 3600.0,
            "vibration": 1.8,    # mm/s (normal: 1.0 - 2.5, danger > 6.0)
            "flow_rate": 85.0,   # L/min (normal: 70 - 100)
            "power_kw": 42.5,
            "safe_max_rpm": 3000.0
        }
        
        self.pump_b = {
            "id": "PUMP_B_02",
            "name": "Auxiliary Cooling Pump B",
            "state": "STANDBY",
            "rpm": 0.0,
            "target_rpm": 0.0,
            "max_rpm": 3600.0,
            "vibration": 0.2,
            "flow_rate": 0.0,
            "power_kw": 0.0,
            "safe_max_rpm": 3000.0
        }
        
        self.valve_inlet = {
            "id": "VALVE_INLET_01",
            "name": "Feedstock Inlet Valve",
            "open_percent": 75.0, # 0.0 - 100.0%
            "target_percent": 75.0,
            "status": "AUTO"
        }

        self.valve_vent = {
            "id": "VALVE_VENT_02",
            "name": "Emergency Relief Vent Valve",
            "open_percent": 15.0,
            "target_percent": 15.0,
            "status": "AUTO"
        }
        
        self.pressure_vessel = {
            "id": "VESSEL_R101",
            "name": "Primary Pressure Vessel R-101",
            "pressure_bar": 5.4, # Normal: 3.5 - 7.5, Alarm > 9.0, Rupture > 12.0
            "temp_celsius": 68.5,# Normal: 55.0 - 80.0, Alarm > 90.0, Critical > 105.0
            "liquid_level_pct": 62.0,
            "safe_max_pressure": 8.0,
            "safe_max_temp": 85.0
        }

        self.sis = {
            "id": "SIS_INTERLOCK_01",
            "name": "Safety Instrumented System (Triconex Mock)",
            "armed": True,
            "tripped": False,
            "trip_reason": None,
            "bypass_active": False,
            "trip_threshold_pressure": 9.5,
            "trip_threshold_temp": 95.0
        }

        # Active Attack Scenario
        self.active_attack: Optional[str] = None
        self.attack_start_tick = 0
        self.attack_metadata: Dict[str, Any] = {}
        self.spoof_hmi: bool = False

        # Event History (Local DB / Metadata Layer)
        self.event_log: List[Dict[str, Any]] = []

    def update_physics(self, dt: float = 1.0) -> Dict[str, Any]:
        """Runs one physics integration step with industrial thermodynamics & noise."""
        self.tick_count += 1
        noise = (random.random() - 0.5)

        # 1. Pump A Dynamics
        if self.pump_a["state"] == "RUNNING":
            # Lerp towards target RPM
            diff_rpm = self.pump_a["target_rpm"] - self.pump_a["rpm"]
            self.pump_a["rpm"] += diff_rpm * min(1.0, dt * 0.8)
            # Add dynamic jitter
            self.pump_a["rpm"] += noise * 8.0
            
            # Flow rate proportional to RPM and inlet valve
            inlet_factor = self.valve_inlet["open_percent"] / 100.0
            ideal_flow = (self.pump_a["rpm"] / 2400.0) * 85.0 * inlet_factor
            self.pump_a["flow_rate"] = max(0.0, ideal_flow + noise * 1.5)
            
            # Vibration increases sharply as RPM exceeds safe operating limit
            base_vib = 1.6 + (self.pump_a["rpm"] / 2400.0) * 0.5
            if self.pump_a["rpm"] > 3100.0:
                base_vib += math.pow((self.pump_a["rpm"] - 3100.0) / 100.0, 1.7)
            self.pump_a["vibration"] = round(max(0.1, base_vib + noise * 0.2), 2)
            self.pump_a["power_kw"] = round((self.pump_a["rpm"] / 2400.0) * 42.5, 1)
        else:
            self.pump_a["rpm"] = max(0.0, self.pump_a["rpm"] * 0.85)
            self.pump_a["flow_rate"] = 0.0
            self.pump_a["vibration"] = 0.1
            self.pump_a["power_kw"] = 0.0

        # 2. Vessel Pressure Dynamics
        # Inflow from pump vs outflow through vent valve
        inflow = self.pump_a["flow_rate"]
        vent_capacity = (self.valve_vent["open_percent"] / 100.0) * 120.0
        net_mass_rate = (inflow - vent_capacity)

        target_pressure = 4.5 + (net_mass_rate * 0.06)
        if self.valve_vent["open_percent"] < 5.0 and self.pump_a["flow_rate"] > 70.0:
            # Overpressure accumulation
            target_pressure = self.pressure_vessel["pressure_bar"] + 0.35

        self.pressure_vessel["pressure_bar"] += (target_pressure - self.pressure_vessel["pressure_bar"]) * 0.25
        self.pressure_vessel["pressure_bar"] = round(max(0.8, self.pressure_vessel["pressure_bar"] + noise * 0.04), 2)

        # 3. Vessel Temperature Dynamics
        # Friction, compression, and cooling
        target_temp = 65.0 + (self.pressure_vessel["pressure_bar"] - 5.0) * 4.5 + (self.pump_a["power_kw"] * 0.18)
        if self.sis["bypass_active"]:
            # Thermal runaway progression
            target_temp += 18.0

        self.pressure_vessel["temp_celsius"] += (target_temp - self.pressure_vessel["temp_celsius"]) * 0.15
        self.pressure_vessel["temp_celsius"] = round(max(20.0, self.pressure_vessel["temp_celsius"] + noise * 0.2), 1)

        # 4. Safety Instrumented System (SIS) Logic
        if self.sis["armed"] and not self.sis["bypass_active"]:
            if self.pressure_vessel["pressure_bar"] >= self.sis["trip_threshold_pressure"]:
                self._trigger_sis_trip(f"Overpressure limit exceeded: {self.pressure_vessel['pressure_bar']} bar")
            elif self.pressure_vessel["temp_celsius"] >= self.sis["trip_threshold_temp"]:
                self._trigger_sis_trip(f"High-high temperature interlock: {self.pressure_vessel['temp_celsius']} °C")

        # 5. Attack Scenario Progression
        self._progress_attack_scenario()

        return self.get_telemetry_snapshot()

    def _trigger_sis_trip(self, reason: str):
        self.sis["tripped"] = True
        self.sis["trip_reason"] = reason
        # Emergency automated actions: shut pump, vent pressure
        self.pump_a["state"] = "FAULT"
        self.pump_a["target_rpm"] = 0.0
        self.valve_vent["open_percent"] = 100.0
        self.valve_vent["target_percent"] = 100.0

    def _progress_attack_scenario(self):
        if not self.active_attack:
            return

        elapsed_ticks = self.tick_count - self.attack_start_tick

        if self.active_attack == "stuxnet":
            # Oscillate centrifuge/pump RPM rapidly outside design frequency
            cycle = (elapsed_ticks % 10)
            if cycle < 5:
                self.pump_a["target_rpm"] = 3550.0  # Excessive overspeed
            else:
                self.pump_a["target_rpm"] = 1200.0  # Resonant destruction vibration band

        elif self.active_attack == "triton":
            # SIS disabled + heater/cooling sabotaged
            self.sis["bypass_active"] = True
            self.valve_vent["open_percent"] = 0.0
            self.valve_vent["target_percent"] = 0.0
            self.pump_a["target_rpm"] = 3450.0

        elif self.active_attack == "overpressure":
            # Vent closed completely, inlet wide open, pump at max
            self.valve_vent["open_percent"] = 0.0
            self.valve_vent["target_percent"] = 0.0
            self.valve_inlet["open_percent"] = 100.0
            self.pump_a["target_rpm"] = 3600.0

    def inject_attack(self, scenario: str) -> Dict[str, Any]:
        """Injects a standardized MITRE ATT&CK for ICS threat actor scenario."""
        self.active_attack = scenario
        self.attack_start_tick = self.tick_count
        
        info = {
            "stuxnet": {
                "name": "Stuxnet Centrifuge Frequency Cycling (T0836 / T0855)",
                "actor": "Equation Group / Olympic Games",
                "description": "Rapidly alternates rotor speed between resonance frequency (1400 RPM) and overspeed (3550 RPM) to cause physical rotor fatigue.",
                "tactics": ["Inhibit Response Function", "Impair Process Control"],
                "techniques": ["T0836", "T0855", "T0831"]
            },
            "triton": {
                "name": "Triton / HatMan SIS Defeat & Thermal Runaway (T0831 / T0816)",
                "actor": "Xenotime (Russian Central Scientific Research Institute)",
                "description": "Bypasses Triconex Safety Instrumented System (SIS) logic, suppresses relief valves, and drives reactor to critical thermal explosion thresholds.",
                "tactics": ["Impair Process Control", "Inhibit Response Function", "Loss of Safety"],
                "techniques": ["T0831", "T0816", "T0879"]
            },
            "overpressure": {
                "name": "Industroyer2 / Pipeline Over-Pressurization (T0855 / T0879)",
                "actor": "Sandworm (Russian GRU Unit 74455)",
                "description": "Sends forged IEC-104 / Modbus command sequence closing relief vents while forcing primary booster pumps to continuous 100% duty cycle.",
                "tactics": ["Manipulation of Control", "Damage to Property"],
                "techniques": ["T0855", "T0879"]
            },
            "log_tamper": {
                "name": "False Data Injection & Audit Log Tampering (T0815 / T0888)",
                "actor": "Volt Typhoon / Covert ICS Infiltrator",
                "description": "Adversary changes critical setpoints and erases the audit logs in the local database to blind human operators. IronLedger blockchain exposes the mismatch!",
                "tactics": ["Evasion", "Impair Process Control"],
                "techniques": ["T0815", "T0888", "T0855"]
            }
        }

        meta = info.get(scenario, {
            "name": f"Custom Attack ({scenario})",
            "actor": "Unknown Adversary",
            "description": "Arbitrary malicious ICS setpoint alteration.",
            "tactics": ["Impair Process Control"],
            "techniques": ["T0855"]
        })
        self.attack_metadata = meta
        return meta

    def stop_attack(self):
        self.active_attack = None
        self.attack_metadata = {}
        self.sis["bypass_active"] = False
        self.pump_a["target_rpm"] = 2400.0
        self.valve_inlet["open_percent"] = 75.0
        self.valve_vent["open_percent"] = 15.0

    def execute_command(self, source: str, command_type: str, entity_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an operator or RTU control command."""
        timestamp = time.time()
        
        if entity_id == self.pump_a["id"]:
            if command_type == "SET_RPM":
                raw_rpm = parameters.get("rpm", 2400.0)
                if isinstance(raw_rpm, bool):
                    raise ValueError("Parameter 'rpm' must be a numeric value, not boolean.")
                try:
                    self.pump_a["target_rpm"] = float(raw_rpm)
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter 'rpm' must be a valid number, got '{raw_rpm}'.")
            elif command_type == "STOP":
                self.pump_a["state"] = "STOPPED"
                self.pump_a["target_rpm"] = 0.0
            elif command_type == "START":
                self.pump_a["state"] = "RUNNING"
                raw_rpm = parameters.get("rpm", 2400.0)
                if isinstance(raw_rpm, bool):
                    raise ValueError("Parameter 'rpm' must be a numeric value, not boolean.")
                try:
                    self.pump_a["target_rpm"] = float(raw_rpm)
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter 'rpm' must be a valid number, got '{raw_rpm}'.")

        elif entity_id == self.valve_vent["id"]:
            if command_type == "SET_VALVE":
                raw_open = parameters.get("open_percent", 15.0)
                if isinstance(raw_open, bool):
                    raise ValueError("Parameter 'open_percent' must be a numeric value, not boolean.")
                try:
                    val = float(raw_open)
                    self.valve_vent["open_percent"] = val
                    self.valve_vent["target_percent"] = val
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter 'open_percent' must be a valid number, got '{raw_open}'.")

        elif entity_id == self.valve_inlet["id"]:
            if command_type == "SET_VALVE":
                raw_open = parameters.get("open_percent", 75.0)
                if isinstance(raw_open, bool):
                    raise ValueError("Parameter 'open_percent' must be a numeric value, not boolean.")
                try:
                    val = float(raw_open)
                    self.valve_inlet["open_percent"] = val
                    self.valve_inlet["target_percent"] = val
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter 'open_percent' must be a valid number, got '{raw_open}'.")

        elif entity_id == self.sis["id"]:
            if command_type == "OVERRIDE_SIS":
                self.sis["bypass_active"] = bool(parameters.get("bypass", True))
            elif command_type == "RESET_TRIP":
                self.sis["tripped"] = False
                self.sis["trip_reason"] = None
                self.pump_a["state"] = "RUNNING"
                self.pump_a["target_rpm"] = 2400.0

        next_id = 1
        if self.event_log:
            next_id = max(e.get("event_id", 0) for e in self.event_log) + 1
            
        event = {
            "event_id": next_id,
            "timestamp": timestamp,
            "source": source,
            "command_type": command_type,
            "entity_id": entity_id,
            "parameters": parameters,
            "plant_state_snapshot": self.get_telemetry_snapshot()
        }
        self.event_log.append(event)
        return event

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        return {
            "tick": self.tick_count,
            "timestamp": time.time(),
            "pump_a": dict(self.pump_a),
            "pump_b": dict(self.pump_b),
            "valve_inlet": dict(self.valve_inlet),
            "valve_vent": dict(self.valve_vent),
            "pressure_vessel": dict(self.pressure_vessel),
            "sis": dict(self.sis),
            "active_attack": self.active_attack,
            "attack_metadata": self.attack_metadata
        }
