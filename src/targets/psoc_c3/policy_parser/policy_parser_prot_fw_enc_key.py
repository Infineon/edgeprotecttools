# (c) 2026, Infineon Technologies AG, or an affiliate of Infineon
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

from ..asset_enums import KeyInstallationMode
from ....core.key_handlers import load_key
from ...common.policy_parser_primitives import PolicyParserPrimitives
from ....core.key_handlers.ec_handler import ECHandler


class PolicyParserProtectedFwEncKey(PolicyParserPrimitives):
    """Provides functionality for searching data in the policy file"""

    def mode(self, ret_value=False) -> Union[KeyInstallationMode, int]:
        """Gets a value of mode.value property"""
        return self.enum_field(KeyInstallationMode, ret_value, 'mode', 'value')

    def public_key_ecies(self, ret_value=False) -> Union[str, bytes]:
        """Gets a value of the public_key.value property
        @param ret_value: Returns the key value if True, otherwise the key path
        @return: The key path or key hash
        """
        path = self.field('public_key', 'value')
        return self._public_key(path, ret_value=ret_value)

    def ciphertext(self, ret_value=False) -> Union[str, bytes]:
        """Gets a value of the ciphertext.value property
        @return: The key path or key hash
        """
        if ret_value:
            if self.mode() == KeyInstallationMode.KEY_GEN:
                return b'\x00' * 16
            return self.bin_file_or_hex_string_field('ciphertext', 'value')
        return self.field('ciphertext', 'value')

    def _public_key(self, path, ret_value=False):
        """Gets either a key path or key bytes.
        For a simple app, the OEM keys are not used, and
        may not exist or may not be specified. In this case,
        a key hash is 68 null bytes.
        """
        if path:
            if not os.path.isabs(path):
                path = os.path.abspath(os.path.join(self.policy_dir, path))

        if ret_value:
            if path and os.path.isfile(path):
                data = self._raw_key_field(path)
                return data + b'\x00' * (68 - len(data))

            if not path or self.mode() == KeyInstallationMode.KEY_GEN:
                return b'\x00' * 68

        return path

    @staticmethod
    def _raw_key_field(key_path):
        key = load_key(key_path)
        raw = ECHandler.raw_format(key)
        return raw
