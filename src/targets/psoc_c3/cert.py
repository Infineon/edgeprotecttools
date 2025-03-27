"""
Copyright 2024-2025 Cypress Semiconductor Corporation (an Infineon company)
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
import logging

from .key_validator import KeyValidatorPsocC3
from ...targets.common.mxs40sv2.cert_mxs40sv2 import CertificateStrategyMXS40Sv2

logger = logging.getLogger(__name__)


class CertificateStrategyPsocC3(CertificateStrategyMXS40Sv2):
    """Create certificates for PSoC C3 platform"""

    def __init__(self):
        super().__init__()
        self.key_validator = KeyValidatorPsocC3()
