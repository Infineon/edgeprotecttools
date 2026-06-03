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
from ..asset_enums import KeyInstallationMode
from ....core.dependecy_validator import DependencyValidator


class ProtectedFwEncKeyValidator(DependencyValidator):
    """Protected FW policy validation"""

    def validate(self, **_kwargs):
        """Validates policy OEM keys section"""
        _pp = self.parser

        mode = _pp.mode()
        public_key = _pp.public_key_ecies()
        ciphertext = _pp.ciphertext()

        if mode == KeyInstallationMode.KEY_GEN:
            self._validate_key_gen(public_key, ciphertext)
        else:
            self._validate_key_install(public_key, ciphertext)

    def _validate_key_gen(self, public_key, ciphertext):
        if public_key:
            self.add_msg('"public_key" should not '
                         'be specified when "mode" is "KEY_GEN"')
        if ciphertext:
            self.add_msg('"ciphertext" should not '
                         'be specified when "mode" is "KEY_GEN"')


    def _validate_key_install(self, public_key, ciphertext):
        if not public_key:
            self.add_msg('"public_key" should be '
                         'specified when "mode" is "KEY_INSTALL"')

        if not ciphertext:
            self.add_msg('"ciphertext" should be '
                         'specified when "mode" is "KEY_INSTALL"')

        ciphertext_data = self.parser.ciphertext(ret_value=True)
        if ciphertext_data and len(ciphertext_data) != 16:
            self.add_msg('"ciphertext" should be 16 bytes long')
