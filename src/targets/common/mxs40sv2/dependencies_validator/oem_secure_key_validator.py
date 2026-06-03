# (c) 2021-2026, Infineon Technologies AG, or an affiliate of Infineon
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

from ..enums import PolicyType
from .....core.dependecy_validator import DependencyValidator
from .....pkg_globals import PkgData


class OemSecureKeyValidator(DependencyValidator):
    def validate(self, **_kwargs):
        _pp = self.parser

        if _pp.policy_type().startswith(PolicyType.REPROVISIONING):
            return

        key = _pp.get_oem_secure_key(ret_value=False)

        if key:
            if not isinstance(key, str):
                self.add_msg(f'Unexpected OEM secure key type ({type(key)})')
            elif key.endswith('.bin'):
                if not os.path.isabs(key):
                    key = os.path.abspath(os.path.join(_pp.policy_dir, key))
                if not os.path.isfile(key):
                    self.add_msg(f'OEM secure key not found ({key})')
            else:
                if not all(x.lower() in '0123456789abcdef' for x in key):
                    self.add_msg(
                        'OEM secure key must be a hex string or '
                        'a path to a binary (.bin) file'
                    )
                elif len(key) % 2:
                    self.add_msg(
                        'OEM secure key provided as hex string '
                        'must have an even number of digits'
                    )
        else:
            self.add_msg(
                "The OEM secure key is not specified. Ensure specifying the "
                "'oem_secure_key' property in the policy file "
                f"'{_pp.policy_file}'. Ref. {PkgData.pkg_github_url()}"
                "/blob/master/docs/README_ERRORS.md"
                "#oem-secure-key-not-specified")

        if not self.is_valid:
            return

        oem_secure_key = _pp.get_oem_secure_key()

        if oem_secure_key:
            if not (
                isinstance(oem_secure_key, bytes) and len(oem_secure_key) == 16
            ):
                self.add_msg('OEM secure key shall have the length of 16 bytes')
