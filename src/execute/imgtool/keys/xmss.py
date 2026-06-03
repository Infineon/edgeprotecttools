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


class XMSSUsageError(Exception):
    """Custom exception for XMSS usage errors."""


class XMSSPublic(KeyClass):
    """
    Represents a public XMSS key.
    """

    def __init__(self, key):
        """
        Initialize an XMSS public instance.
        Args: key: The public XMSS key object.
        """
        self.key = key

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        """
        Get the public key bytes.
        Returns:
            bytes: The public XMSS key.
        """
        return self._get_public().serialize()

    def sig_tlv(self):
        """
        Get the signature TLV (Type-Length-Value) identifier.
        Returns:
            str: The signature TLV identifier for XMSS.
        """
        return "XMSS_SIG"


class XMSSPrivate(XMSSPublic):
    """
    Represents an XMSS key pair.
    """

    def __init__(self, key):
        """
        Initialize an XMSS Private instance.
        Args: key: The public XMSS key object.
        """
        self.key = key

    def _get_public(self):
        return self.key.public_key()

    def sign(self, payload):
        """
        Sign the given payload using the XMSS private key.
        Args:
            payload (bytes): The data to be signed.
        Returns:
            bytes: The signature.
        """
        sha = hashlib.sha256()
        sha.update(payload)
        payload_hash = sha.digest()
        return self.key.sign(payload_hash)
