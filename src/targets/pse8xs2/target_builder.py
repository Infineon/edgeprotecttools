# (c) 2024-2026, Infineon Technologies AG, or an affiliate of Infineon
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
from .advanced_validator import AdvancedValidatorPse8x
from .maps.asset_map import AssetMapPse8x
from .maps.memory_map import MemoryMapPse8x
from .maps.register_map import RegisterMapPse8x
from .policy_parser.policy_parser import PolicyParser
from .policy_version_validator import PolicyVersionValidator
from .policy_validator import PolicyValidatorPSE8xB0
from .project_init_pse8xs2 import ProjectInitPse8xs2
from .provisioning import RamAppLoaderPSE8x
from ..common.mxs22 import (
    TokenMXS22, CertificateStrategyMXS22,
    ProvisioningPacketMXS22, ProvisioningMXS22, VersionProviderMXS22
)
from ..common.mxs22.si_data_reader import SiliconDataReaderMxs22V1
from ..common.mxs22.data import RamAppStatusMXS22
from ..common.mxs22.device_integrity_mxs22 import DeviceIntegrityMXS22
from ...core import TargetBuilder
from ...core.enums import KeyAlgorithm


class PSE8xS2Builder(TargetBuilder):
    """ PSoC Edge E8x B0 target builder """

    ocd_config_list = {
        'pse84': {
            'openocd': {'mcu': 'pse84'}
        }
    }

    def get_default_policy(self):
        return None

    def get_ocds(self):
        return ['openocd', 'serial', 'jlink']

    def get_ocd_config(self):
        return {
            'openocd': self._get_openocd_config(),
            'jlink': self._get_jlink_config()
        }

    def _get_openocd_config(self):
        return {
            'target': 'infineon/pse84xgxs2',
            'mcu': 'pse84xgxs2',
            'cm33': 'cm33',
            'cm55': 'cm55',
            'sysap': 'sys',
            'variables': 'set ENABLE_CM33 0; set ENABLE_CM55 0',
            'before_init': '',
            'after_init': 'reset init; targets'
        }

    def _get_jlink_config(self):
        return {
            'device': 'PSE846GP_EPC2_M33',
            'check_domain_security': True
        }

    def get_memory_map(self):
        return MemoryMapPse8x()

    def get_register_map(self):
        return RegisterMapPse8x()

    def get_policy_parser(self, policy):
        return PolicyParser(policy)

    def get_policy_validator(self, policy_parser, memory_map):
        version_validator = PolicyVersionValidator(policy_parser)
        dependency_validator = AdvancedValidatorPse8x(policy_parser)
        return PolicyValidatorPSE8xB0(policy_parser, version_validator, None,
                                      dependency_validator)

    def get_policy_filter(self, policy_parser):
        """N/A for PSoC Edge E8x"""

    def get_provisioning_strategy(self):
        return ProvisioningMXS22()

    def get_provisioning_packet_strategy(self, policy_parser):
        return ProvisioningPacketMXS22(policy_parser, AssetMapPse8x())

    def get_entrance_exam(self):
        return DeviceIntegrityMXS22

    def get_voltage_tool(self):
        return None

    def get_key_reader(self):
        return None

    def get_project_initializer(self):
        return ProjectInitPse8xs2

    def get_silicon_data_reader(self):
        return SiliconDataReaderMxs22V1

    def get_key_algorithms(self):
        return [
            KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_P384,
            KeyAlgorithm.RSA2048, KeyAlgorithm.RSA4096,
            KeyAlgorithm.AES128, KeyAlgorithm.AES256
        ]

    def get_sign_tool(self):
        return None

    def get_key_source(self, **kwargs):
        return None

    def get_bootloader_provider(self):
        return None

    def get_version_provider(self):
        return VersionProviderMXS22

    def get_debug_certificate(self):
        return TokenMXS22()

    def get_policy_generator(self, policy_parser):
        return None

    def get_test_packages(self):
        return {
            'testapps': {
                'package': 'testapps_explorer', 'flow_name': 'testapps'
            },
            'testapps_si': {
                'package': 'testapps_explorer', 'flow_name': 'testapps_si'
            }
        }

    def get_certificate_strategy(self):
        return CertificateStrategyMXS22()

    def get_app_loader(self):
        return RamAppLoaderPSE8x(RamAppStatusMXS22())

    def get_silicon_id(self):
        """Gets the target silicon ID"""
        return None
