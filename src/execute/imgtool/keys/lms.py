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
import hashlib

from .general import KeyClass


class LMSUsageError(Exception):
    """Custom exception for LMS usage errors."""


class LMSPublic(KeyClass):
    """
    Represents a public LMS (Leighton-Micali Signature) key.
    """

    def __init__(self, key):
        """
        Initialize an LMS public instance.
        Args: key: The public LMS key object.
        """
        self.key = key

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        """
        Get the public key bytes.
        Returns:
            bytes: The public LMS key.
        """
        return self._get_public().serialize()

    def sig_tlv(self):
        """
        Get the signature TLV (Type-Length-Value) identifier.
        Returns:
            str: The signature TLV identifier for LMS.
        """
        return "LMS_SIG"


class LMS(LMSPublic):
    """
    Represents an LMS (Leighton-Micali Signature) key pair.
    """

    def __init__(self, key):
        """
        Initialize an LMS Private instance.
        Args: key: The public LMS key object.
        """
        self.key = key

    def _get_public(self):
        return self.key.publicKey()

    def sign(self, payload):
        """
        Sign the given payload using the LMS private key.
        Args:
            payload (bytes): The data to be signed.
        Returns:
            bytes: The signature.
        """
        sha = hashlib.sha256()
        sha.update(payload)
        payload_hash = sha.digest()
        return self.key.sign(payload_hash)
