"""
Copyright 2024 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os

from ..common.policy_validator import PolicyValidator


class PolicyValidatorCYW559xx(PolicyValidator):
    """Policy validator for CYW559xx target"""

    schema_dir = os.path.join(os.path.dirname(__file__), 'schemas')

    schemas = {
        'oem_provisioning':
            os.path.join(schema_dir, 'oem_provisioning_schema.json')
    }

    def __init__(self, policy_parser, dependency_validator):
        super().__init__(policy_parser, None, self.schemas,
                         dependency_validator)

    def validate(self, skip=None, skip_prompts=False, **kwargs):
        """
        Policy JSON file validation
        :param skip:
            Validator names to be skipped
        :param skip_prompts:
            Indicates whether to skip interactive prompts
        :return
            Validation status
        """
        if self.policy_parser.json is None:
            self.skip_validation = True
        return super().validate(skip, skip_prompts, **kwargs)
