# (c) 2025-2026, Infineon Technologies AG, or an affiliate of Infineon
# Technologies AG.  SPDX-License-Identifier: Apache-2.0
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
from typing import Union

from ..asset_enums import SecBool
from ...common.policy_parser_primitives import PolicyParserPrimitives


class PolicyParserProtectedFw(PolicyParserPrimitives):
    """Provides functionality for searching data in the policy file"""

    def prot_fw_encrypt_enable(self) -> bool:
        """Gets a value of encrypt.enable property"""
        enable = self.field('encrypt', 'enable', 'value')
        return enable

    def prot_fw_encrypt_key(self, ret_value=False) -> Union[str, bytes]:
        """Gets a value of encrypt.key property"""
        if ret_value:
            return self.bin_file_field('encrypt', 'key', 'value')
        else:
            return self.field('encrypt', 'key', 'value')

    def prot_fw_encrypt_iv(self, ret_value=False) -> Union[str, bytes]:
        """Gets a value of encrypt.iv property"""
        iv = self.field('encrypt', 'iv', 'value')
        if ret_value:
            if iv == 'random':
                return os.urandom(16)
            else:
                return bytes.fromhex(iv) if iv else b''
        return iv

    def prot_fw_addr(self) -> int:
        """Gets a value of the prot_fw_addr property"""
        addr = self.field('device_policy', 'prot_fw_addr', 'value')
        return int(str(addr), 0) if addr else 0

    def prot_fw_size(self) -> int:
        """Gets a value of the prot_fw_size property"""
        size = self.field('device_policy', 'prot_fw_size', 'value')
        return int(str(size), 0) if size else 0

    def prot_fw_rw_addr(self) -> int:
        """Gets a value of the prot_fw_rw_addr property"""
        addr = self.field('device_policy', 'prot_fw_rw_addr', 'value')
        return int(str(addr), 0) if addr else 0

    def prot_fw_rw_size(self) -> int:
        """Gets a value of the prot_fw_rw_size property"""
        size = self.field('device_policy', 'prot_fw_rw_size', 'value')
        return int(str(size), 0) if size else 0

    def prot_fw_ram_addr(self) -> int:
        """Gets a value of the prot_fw_ram_addr property"""
        addr = self.field('device_policy', 'prot_fw_ram_addr', 'value')
        return int(str(addr), 0) if addr else 0

    def prot_fw_ram_size(self) -> int:
        """Gets a value of the prot_fw_ram_size property"""
        size = self.field('device_policy', 'prot_fw_ram_size', 'value')
        return int(str(size), 0) if size else 0

    def prot_fw_complete(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the prot_fw_complete property"""
        enable = self.field('device_policy', 'prot_fw_complete', 'value')
        if ret_value:
            return SecBool.SEC_TRUE if enable else SecBool.SEC_FALSE
        return enable

    def rev_prot_fw_rot_key_0(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the
        device_policy.reprovisioning.rev_prot_fw_rot_key_0 property"""
        value = self.field('device_policy', 'reprovisioning',
                           'rev_prot_fw_rot_key_0', 'value')
        if ret_value:
            return SecBool.SEC_TRUE if value else SecBool.SEC_FALSE
        return value is True
