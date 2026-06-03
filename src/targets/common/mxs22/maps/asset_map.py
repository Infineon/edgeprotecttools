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
import json
import logging
import os
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AssetMapMXS22(ABC):
    """Asset map for MXS22 platform"""

    @staticmethod
    @abstractmethod
    def get(parser, **kwargs):
        """Gets protected and unprotected parts of the CBOR packet.
        The items represent policy fields as a key-value pairs where
        the key is a field ID
        @param parser: Policy parser object
        @return: CBOR map ID, unprotected data, protected data
        """

    @staticmethod
    def _integrity_cert_data(cert_path):
        """Returns Device Integrity cert data
        @param cert_path: Path to the IFX Device Integrity cert
        @return: Device Integrity certificate data
        """
        cert = None
        try:
            with open(cert_path, encoding="utf-8") as f:
                cert_data = json.load(f)
            logger.debug("JSON cert used to create integrity_exam in_params "
                         "'%s'", cert_path)
            cert_hex_data = cert_data.get('certificate')
            cert = bytes.fromhex(cert_hex_data)
        except UnicodeDecodeError:
            with open(os.path.abspath(cert_path), 'rb') as fp:
                cert = fp.read()
            logger.debug("CBOR cert used to create integrity_exam in_params "
                         "'%s'", cert_path)
        return cert