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
from .maps import MemoryMapPsocC3x6, RegisterMapPsocC3x6, AssetMapPsocC3x6
from .policy_parser.policy_parser import PolicyParser
from .policy_validator import PolicyValidatorPsocC3x6
from .project_init import ProjectInitializerPsocC3x6
from .provisioning_packet import ProvisioningPacketPsocC3x6
from ..common.mxs40sv2.debug_cert import TokenVersionVerifierMXS40Sv2
from ..common.mxs40sv2.integrity_exam_mxs40sv2 import IntegrityExamMXS40Sv2
from .advanced_validator.policy_advanced_validator import (
    AdvancedValidatorPsocC3x6
)
from ..psoc_c3.cert_v2 import CertificateStrategyPsocC3v2
from ..psoc_c3.data import StatusPsocC3v2
from ..psoc_c3.debug_token import (
    DebugTokenPsocC3v2, TokenTemplateValidatorPsocC3v2
)
from ..psoc_c3.provisioning import ProvisioningPsocC3v2, RamAppLoaderPsocC3v2
from ..psoc_c3.silicon_data_reader import SiliconDataReaderPsocC3
from ..psoc_c3.version_provider_v2 import VersionProviderPsocC3v2
from ...core import TargetBuilder
from ...core.enums import KeyAlgorithm


class PsocC3x6Builder(TargetBuilder):
    """ PSOC C3 x6 target builder """

    def get_default_policy(self):
        return None

    def get_ocds(self):
        return ['openocd', 'serial', 'jlink']

    def get_ocd_config(self):
        return {
            'openocd': {
                'variables': 'set ENABLE_CM33 0',
                'before_init': '',
                'after_init': 'targets psc3.sys'
            }
        }

    def get_memory_map(self):
        return MemoryMapPsocC3x6()

    def get_register_map(self):
        return RegisterMapPsocC3x6()

    def get_policy_parser(self, policy):
        return PolicyParser(policy)

    def get_policy_validator(self, policy_parser, memory_map):
        dependency_validator = AdvancedValidatorPsocC3x6(policy_parser)
        return PolicyValidatorPsocC3x6(policy_parser, dependency_validator)

    def get_policy_filter(self, policy_parser):
        return None

    def get_provisioning_strategy(self):
        return ProvisioningPsocC3v2()

    def get_provisioning_packet_strategy(self, policy_parser):
        return ProvisioningPacketPsocC3x6(policy_parser, AssetMapPsocC3x6())

    def get_entrance_exam(self):
        return IntegrityExamMXS40Sv2

    def get_voltage_tool(self):
        return None

    def get_key_reader(self):
        return None

    def get_project_initializer(self):
        return ProjectInitializerPsocC3x6

    def get_silicon_data_reader(self):
        return SiliconDataReaderPsocC3

    def get_key_algorithms(self):
        return [
            KeyAlgorithm.ECDSA_P256,
            KeyAlgorithm.ECDSA_P384,
            KeyAlgorithm.ECDSA_P521,
            KeyAlgorithm.AES128,
            KeyAlgorithm.AES256
        ]

    def get_sign_tool(self):
        return None

    def get_key_source(self, **kwargs):
        return None

    def get_bootloader_provider(self):
        return None

    def get_version_provider(self):
        return VersionProviderPsocC3v2

    def get_debug_certificate(self):
        template_validator = TokenTemplateValidatorPsocC3v2(
            version_verifier=TokenVersionVerifierMXS40Sv2,
            advanced_validator=None)
        return DebugTokenPsocC3v2(template_validator=template_validator)

    def get_policy_generator(self, policy_parser):
        return None

    def get_test_packages(self):
        return {
            'testapps': {
                'package': 'testapps_psoc_c3x6', 'flow_name': 'testapps'
            },
            'testapps_si': {
                'package': 'testapps_psoc_c3x6', 'flow_name': 'testapps_si'
            }
        }

    def get_certificate_strategy(self):
        return CertificateStrategyPsocC3v2()

    def get_app_loader(self):
        return RamAppLoaderPsocC3v2(StatusPsocC3v2())

    def get_silicon_id(self):
        """Gets the target silicon ID"""
        return None
