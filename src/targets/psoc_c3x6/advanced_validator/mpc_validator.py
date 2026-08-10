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
from ...psoc_c3.advanced_validator import MpcValidator


class MpcValidatorPsocC3x6(MpcValidator):
    """MPC policy validation"""

    sect = 'MPC policy configuration'

    def validate(self, **_kwargs):
        """Validates Flash MPC policy"""
        _pp = self.parser

        if _pp.n_flash_mpc() > 10:
            self.add_msg(f"{self.sect}: the maximum total number of "
                         "Flash MPC structures must be 10")

        mpc_flash = _pp.mpc_struct_flash()
        if mpc_flash:
            self.sect = 'Flash MPC policy configuration'
            for item in _pp.mpc_struct_flash():
                self.validate_region('offset', item.get('offset'))
                self.validate_region('size', item.get('size'))
                self.validate_attr(item.get('attr'))
