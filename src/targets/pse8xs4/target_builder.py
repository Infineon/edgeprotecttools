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
from .project_init_pse8xs4 import ProjectInitPse8xs4
from ..pse8xs2 import PSE8xS2Builder


class PSE8xS4Builder(PSE8xS2Builder):
    """ PSoC Edge E8x S4 target builder """

    def _get_openocd_config(self):
        return {
            'target': 'infineon/pse84xgxs4',
            'mcu': 'pse84xgxs4',
            'cm33': 'cm33',
            'cm55': 'cm55',
            'sysap': 'sys',
            'variables': 'set ENABLE_CM33 0; set ENABLE_CM55 0',
            'before_init': '',
            'after_init': 'reset init; targets'
        }

    def _get_jlink_config(self):
        return {
            'device': 'PSE846GP_EPC4_M33',
            'check_domain_security': True
        }

    def get_project_initializer(self):
        return ProjectInitPse8xs4
