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

from ..psoc_c3.policy_validator import PolicyValidatorPsocC3


class PolicyValidatorPsocC3x8(PolicyValidatorPsocC3):
    """Policy validator for PSoC C3 P8 target"""

    schema_dir = os.path.join(os.path.dirname(__file__), 'schemas')

    schemas = {
        'oem_provisioning':
            os.path.join(schema_dir, 'oem_provisioning_schema.json'),
        'prot_fw_policy':
            os.path.join(schema_dir, 'prot_fw_policy_schema.json'),
        'dfu': os.path.join(schema_dir, 'dfu_schema.json'),
        'sort': None,
        'provisioned': os.path.join(schema_dir, 'device_identity_schema.json'),
        'normal_provisioned':
            os.path.join(schema_dir, 'normal_provisioned_schema.json'),
        'device_integrity_exam': None
    }

