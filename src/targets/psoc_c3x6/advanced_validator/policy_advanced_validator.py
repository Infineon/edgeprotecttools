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
from . import (OemKeysValidator, MpcValidatorPsocC3x6,
               ProtFwKeysValidator, ProtFwPolicyValidatorPsocC3x6)
from ...common.dependencies_validation import DependenciesValidatorRunner


class AdvancedValidatorPsocC3x6(DependenciesValidatorRunner):
    """Does advanced validation on PSoC C3 x6 policy"""

    validators = {}

    def __init__(self, parser):
        super().__init__(parser, self.validators)

    def validate(self, skip_list=None, **kwargs):
        if self.parser.policy_type() == 'oem_provisioning':
            self.validators = {
                'pre_build': [
                    OemKeysValidator,
                    MpcValidatorPsocC3x6
                ]
            }
        elif self.parser.policy_type() == 'prot_fw_policy':
            self.validators = {
                'pre_build': [
                    ProtFwKeysValidator,
                    ProtFwPolicyValidatorPsocC3x6
                ]
            }
        return super().validate(skip_list=skip_list, **kwargs)
