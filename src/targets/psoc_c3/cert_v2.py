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
import logging

from .key_validator_v2 import KeyValidatorPsocC3v2
from ...core.certificate_strategy import CertificateStrategyV1

logger = logging.getLogger(__name__)


class CertificateStrategyPsocC3v2(CertificateStrategyV1):
    """Create certificates for PSoC C3 platform"""

    def __init__(self):
        super().__init__()
        self.key_validator = KeyValidatorPsocC3v2()
