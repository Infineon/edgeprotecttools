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
from .policy_validator import PolicyValidatorPSE8xB1
from ..pse8xs2 import PSE8xS2Builder
from ..pse8xs2.advanced_validator import AdvancedValidatorPse8x
from ..pse8xs2.policy_version_validator import PolicyVersionValidator


class PSE8xS2B1Builder(PSE8xS2Builder):
    """ PSoC Edge E8x B1 target builder """

    def get_policy_validator(self, policy_parser, memory_map):
        version_validator = PolicyVersionValidator(policy_parser)
        dependency_validator = AdvancedValidatorPse8x(policy_parser)
        return PolicyValidatorPSE8xB1(policy_parser, version_validator, None,
                                      dependency_validator)
