"""
Copyright 2026 Cypress Semiconductor Corporation (an Infineon company)
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
import hashlib
import os

from .general import KeyClass

from ....core.dilithium.ml_dsa import (
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
    HASH_ML_DSA_44, HASH_ML_DSA_65, HASH_ML_DSA_87
)


class MLDSAUsageError(Exception):
    """Custom exception for MLDSA usage errors."""


class MLDSAPublic(KeyClass):
    """
    Represents a public ML-DSA key.
    """

    sig_tlv_map = {
        HASH_ML_DSA_44: "ML_DSA_44_SIG",
        HASH_ML_DSA_65: "ML_DSA_65_SIG",
        HASH_ML_DSA_87: "ML_DSA_87_SIG",
    }

    def __init__(self, key):
        """
        Initialize an ML-DSA public instance.
        Args: key: The public ML-DSA key object.
        """
        self.key = key

    @property
    def signature_type(self):
        if self.key.type == ML_DSA_44:
            return HASH_ML_DSA_44
        elif self.key.type == ML_DSA_65:
            return HASH_ML_DSA_65
        elif self.key.type == ML_DSA_87:
            return HASH_ML_DSA_87
        else:
            raise MLDSAUsageError(f'Invalid key type: {self.key.key_type}')

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        """
        Get the public key bytes.
        Returns:
            bytes: The public ML-DSA key.
        """
        return self._get_public().key

    def sig_tlv(self):
        """
        Get the signature TLV (Type-Length-Value) identifier.
        Returns:
            str: The signature TLV identifier for ML-DSA.
        """
        return self.sig_tlv_map[self.signature_type]

    def sig_type(self):
        if self.key.type == ML_DSA_44:
            return "HASH_ML_DSA_44"
        elif self.key.type == ML_DSA_65:
            return "HASH_ML_DSA_65"
        elif self.key.type == ML_DSA_87:
            return "HASH_ML_DSA_87"
        else:
            raise MLDSAUsageError(f'Invalid key type: {self.key.key_type}')


class MLDSAPrivate(MLDSAPublic):
    """
    Represents a private ML-DSA key.
    """

    def _get_public(self):
        return self.key.public_key()

    def sign_with_pre_hash(self, payload, hash_name, deterministic=False):
        """
        Sign the given payload using the ML-DSA private key.
        Args:
            payload (bytes): The data to be signed.
            hash_name (str): The name of the hash function to use.
            deterministic (bool): Whether to use deterministic signing. Default is False.
        Returns:
            bytes: The signature.
        """
        return self.signature_type.sign_with_pre_hash(
            self.key.key, payload, hash_name,
            ctx=b'', deterministic=deterministic
        )

