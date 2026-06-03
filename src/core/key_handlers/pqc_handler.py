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

from pyhsslms import LmsPrivateKey, LmsPublicKey
from ..xmss.xmss import XMSSPrivateKey, XMSSPublicKey

logger = logging.getLogger(__name__)

class PQCHandler:
    """
    Handles operations related to PQC keys.
    This class provides static methods to check if a given key is an PQC key,
    and whether it's a private or public PQC key.
    """
    PUBLIC_LMS_24_KEY_LENGTH = 48
    PRIVATE_LMS_24_KEY_LENGTH = 52

    PUBLIC_LMS_32_KEY_LENGTH = 56
    PRIVATE_LMS_32_KEY_LENGTH = 60

    MIN_LMOTS_TYPE, MAX_LMOTS_TYPE = 1, 17

    MIN_LMS_TYPE, MAX_LMS_TYPE = 5, 25

    DATA_LMOTS_TYPE = [i.to_bytes(4, byteorder='big')
                       for i in range(MIN_LMOTS_TYPE, MAX_LMOTS_TYPE)]
    DATA_LMS_TYPE = [i.to_bytes(4, byteorder='big')
                     for i in range(MIN_LMS_TYPE, MAX_LMS_TYPE)]

    @staticmethod
    def is_lms_key(key):
        """
        Determines whether the given key is an LMS key.
        Args: key (bytes): The key to be checked.
        Returns: bool: True if the key is an LMS key, False otherwise.
        """
        if not isinstance(key, bytes):
            return False
        if len(key) not in (PQCHandler.PRIVATE_LMS_24_KEY_LENGTH,
                            PQCHandler.PRIVATE_LMS_32_KEY_LENGTH,
                            PQCHandler.PUBLIC_LMS_32_KEY_LENGTH,
                            PQCHandler.PUBLIC_LMS_24_KEY_LENGTH):
            return False

        return (key[:4] in PQCHandler.DATA_LMS_TYPE and
                key[4:8] in PQCHandler.DATA_LMOTS_TYPE)

    @staticmethod
    def is_private_lms_key(key):
        """
         Determines if the given key is a valid private LMS
        """
        return PQCHandler.is_lms_key(key) and len(key) in (
            PQCHandler.PRIVATE_LMS_24_KEY_LENGTH,
            PQCHandler.PRIVATE_LMS_32_KEY_LENGTH
        )

    @staticmethod
    def is_public_lms_key(key):
        """
         Determines if the given key is a valid private LMS
        """
        return PQCHandler.is_lms_key(key) and len(key) in (
            PQCHandler.PUBLIC_LMS_24_KEY_LENGTH,
            PQCHandler.PUBLIC_LMS_32_KEY_LENGTH
        )

    @staticmethod
    def load_public_key(key):
        """
        Loads a public PQC key.
        Args:
            key: The key data to be loaded.
        Returns:
            LMS key: An LMS key object if the key is a valid public LMS key.
            XMSS key: An XMSS key object if the key is a valid public XMSS key.
        """
        if PQCHandler.is_public_lms_key(key):
            try:
                return LmsPublicKey.deserialize(key)
            except ValueError as e:
                raise ValueError("Failed to deserialize LMS public key") from e

        try:
            return XMSSPublicKey.deserialize(key)
        except ValueError as e:
            raise ValueError(
                "The provided key is not a valid XMSS public key") from e
        
    @staticmethod
    def load_private_key(key):
        """
        Loads a private PQC key.
        Args:
            key: The key data to be loaded.
        Returns:
            LMS key: An LMS key object if the key is a valid private LMS key.
            XMSS key: An XMSS key object if the key is a valid private LMS key.
        """
        if PQCHandler.is_private_lms_key(key):
            logger.info("Loading LMS private key. This may take a while.")
            try:
                return LmsPrivateKey().deserialize(key)
            except ValueError as e:
                raise ValueError("Failed to deserialize LMS private key") from e

        try:
            return XMSSPrivateKey.deserialize(key)
        except ValueError as e:
            raise ValueError(
                "The provided key is not a valid XMSS private key") from e
