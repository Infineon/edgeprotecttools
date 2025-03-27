"""
Copyright 2025 Cypress Semiconductor Corporation (an Infineon company)
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
from intelhex import IntelHex

from . import MDH, DS


class DlImage:
    """Data structure for downloadable image (the final hex file
    generated by MTB for the direct load)
    """
    def __init__(self):
        self.data = None
        self.mdh = None
        self.ds = None

    def load(self, image):
        """Loads the image"""
        ih = IntelHex(image)
        self.data = ih
        self.mdh = MDH(self.data)
        self.ds = DS(self.data)

    @property
    def sub_ds_sec_fw(self) -> IntelHex:
        """Gets secure firmware sub DS"""
        start = self.mdh.sub_ds_sec_fw.address
        end = start + self.mdh.sub_ds_sec_fw.size
        return self.data[start:end]

    @sub_ds_sec_fw.setter
    def sub_ds_sec_fw(self, value):
        """Sets secure firmware sub DS"""
        start = self.mdh.sub_ds_sec_fw.address
        end = start + self.mdh.sub_ds_sec_fw.size
        self.data[start:end] = list(value)

    @property
    def sub_ds_fw(self) -> IntelHex:
        """Gets non-secure firmware sub DS"""
        start = self.mdh.sub_ds_fw.address
        end = start + self.mdh.sub_ds_fw.size
        return self.data[start:end]

    @sub_ds_fw.setter
    def sub_ds_fw(self, value):
        """Sets non-secure firmware sub DS"""
        start = self.mdh.sub_ds_fw.address
        end = start + self.mdh.sub_ds_fw.size
        self.data[start:end] = list(value)

    @property
    def sub_ds_app(self) -> IntelHex:
        """Gets application sub DS"""
        start = self.mdh.sub_ds_app.address
        end = start + self.mdh.sub_ds_app.size
        return self.data[start:end]

    @sub_ds_app.setter
    def sub_ds_app(self, value):
        """Sets application sub DS"""
        start = self.mdh.sub_ds_app.address
        end = start + self.mdh.sub_ds_app.size
        self.data[start:end] = list(value)

    @property
    def cert_address(self) -> int:
        """Gets the certificates start address"""
        cert_data = self.data[self.ds.address + self.ds.size:]
        address = min(cert_data.addresses(), default=None)
        return address

    @property
    def cert_data(self) -> IntelHex:
        """Gets the certificates data"""
        return self.data[self.ds.address + self.ds.size:]

    @property
    def cert_bytes(self) -> bytes:
        """Gets the certificates bytes"""
        return bytes(self.cert_data.tobinarray())

    def save_hex(self, path):
        """Saves the image to the given path"""
        self.data.tofile(path, 'hex')
        self.__remove_hex_first_line(path)

    def save_bin(self, path):
        """Saves the image to the given path"""
        self.data.tofile(path, 'bin')

    @staticmethod
    def __remove_hex_first_line(path):
        """Removes the first line in hex file.
        There is no segment address record before MDH
        """
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(lines[1:])
