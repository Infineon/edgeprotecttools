"""
Copyright 2024 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging

import serial.tools.list_ports

from .base import ProgrammerBase
from .chipload_runner import ChipLoadRunner

logger = logging.getLogger(__name__)


class ChipLoad(ProgrammerBase):
    """Wrapper around the ChipLoad which implements a single
    interface for OCDs
    """

    def __init__(self, name, settings):
        path = settings.ocd_path if settings else None
        super().__init__(name, path=path)
        self.runner = ChipLoadRunner(settings) if settings else None
        self.probe_id = self.runner.serial_port if self.runner else None

    def connect(self, target_name=None, interface=None, probe_id=None, ap=None,
                acquire=True, power=None, voltage=None, ignore_errors=False):
        """Checks whether the serial port name exists in the comm ports list"""
        target_name = probe_id if probe_id else self.probe_id
        commports = list(serial.tools.list_ports.comports())
        for commport in commports:
            if target_name == commport.name:
                logger.info("Target connected %s", target_name)
                return True
        raise ValueError(f"Unknown probe ID '{target_name}'")

    def disconnect(self):
        """N/A for ChipLoad"""

    def get_ap(self):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def set_ap(self, _):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def set_frequency(self, _):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def halt(self):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def resume(self):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def reset(self, *_):
        """N/A for ChipLoad"""

    def reset_and_halt(self, *_):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def read8(self, address):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def read16(self, address):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def read32(self, address):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def write8(self, *_):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def write16(self, *_):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def write32(self, *_):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def write(self, address, data):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def read_reg(self, _):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def write_reg(self, *_):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def erase(self, address, size):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def program(self, filename, file_format=None, address=None, **kwargs):
        """Programs image into device and run"""
        return self.runner.run(filename, address, **kwargs)

    def read(self, address, length):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def get_probe_list(self):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def get_voltage(self):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def dump_image(self, filename, addr, size, **kwargs):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def verify(self, filename):
        """N/A for ChipLoad"""
        raise NotImplementedError

    def hci_command(self, command, timeout=1):
        """Executes HCI commands and returns received data"""
        return self.runner.hci_run(command, timeout)
