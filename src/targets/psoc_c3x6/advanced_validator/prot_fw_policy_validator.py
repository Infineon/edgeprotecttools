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

from ...psoc_c3.advanced_validator import ProtFwPolicyValidator


class ProtFwPolicyValidatorPsocC3x6(ProtFwPolicyValidator):
    """Protected FW policy validation"""

    def validate(self, **_kwargs):
        """Validates Protected FW policy"""
        for _validate in (self._validate_prot_fw_key_exists,
                          self._validate_prot_fw_key_size,
                          self._validate_encrypt):
            _validate()
            if not self.is_valid:
                break

    def _validate_prot_fw_key_exists(self):
        key = self.parser.enc_key('prot_fw_enc_key', ret_value=False)

        if not os.path.isabs(key):
            key = os.path.abspath(
                os.path.join(self.parser.policy_dir, key)
            )
        if not os.path.isfile(key):
            self.add_msg(f"PROT_FW_ENC_KEY not found: '{key}'")

    def _validate_prot_fw_key_size(self):
        key = self.parser.enc_key('prot_fw_enc_key', ret_value=True)

        if len(key) != 32:
            self.add_msg(f'Unexpected PROT_FW_ENC_KEY size ({len(key)}). '
                         f'Expected size: 32 bytes')
