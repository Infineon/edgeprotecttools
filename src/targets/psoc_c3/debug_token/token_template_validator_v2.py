# (c) 2023-2026, Infineon Technologies AG, or an affiliate of Infineon
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
import logging
import os

from ...common.mxs40sv2.debug_cert import TokenTemplateValidatorMXS40Sv2

logger = logging.getLogger(__name__)


class TokenTemplateValidatorPsocC3v2(TokenTemplateValidatorMXS40Sv2):
    """Implements token template validation. There are two types of
    validation - validation against JSON schema, and custom validation of
    the properties that cannot be validated against schema
    """

    schema_dir = os.path.join(os.path.dirname(__file__), '..', 'schemas')

    schemas = {
        'debug': os.path.join(schema_dir, 'debug_cert_v2_schema.json')
    }
