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
from abc import ABC, abstractmethod

from ecdsa.der import UnexpectedDER

from ..dilithium.ml_dsa import (
    pkcs,
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
    HASH_ML_DSA_44, HASH_ML_DSA_65, HASH_ML_DSA_87
)

class MLDSABase(ABC):
    """Base class for ML-DSA keys"""
    _key = None
    _type = None

    @abstractmethod
    def __init__(self, key: bytes):
        self._key = key

    @abstractmethod
    def serialize(self, encoding):
        pass

    @property
    def key(self):
        return self._key

    @property
    def type(self):
        return self._type

    @property
    def signature_type(self):
        if self.type == ML_DSA_44:
            return HASH_ML_DSA_44
        elif self.type == ML_DSA_65:
            return HASH_ML_DSA_65
        elif self.type == ML_DSA_87:
            return HASH_ML_DSA_87
        else:
            raise ValueError(f'Invalid key type: {self.type}')


class MLDSAPublicKey(MLDSABase):
    """ Represents an ML-DSA public key """

    def __init__(self, pk: bytes):
        self._key = pk
        self._type = self._get_type()

    def _get_type(self):
        if len(self.key) == 1312:
            return ML_DSA_44
        elif len(self.key) == 1952:
            return ML_DSA_65
        elif len(self.key) == 2592:
            return ML_DSA_87
        else:
            raise ValueError(f'Invalid key length: {len(self.key)}')

    def verify(self, payload, signature, hash_name):
        return self.signature_type.verify_with_pre_hash(
            self.key, payload, signature, hash_name, ctx=b""
        )

    def serialize(self, encoding):
        """Serializes the public key in the specified encoding format"""
        if encoding == 'DER':
            return pkcs.pk_to_der(self.type, self.key)
        elif encoding == 'PEM':
            return pkcs.pk_to_pem(self.type, self.key)
        else:
            raise ValueError(f'Unsupported encoding for ML-DSA: {encoding}')


class MLDSAPrivateKey(MLDSABase):
    """ Represents an ML-DSA private key """

    def __init__(self, sk: bytes):
        self._key = sk
        self._type = self._get_type()

    def _get_type(self):
        if len(self.key) == 2560:
            return ML_DSA_44
        elif len(self.key) == 4032:
            return ML_DSA_65
        elif len(self.key) == 4896:
            return ML_DSA_87
        else:
            raise ValueError(f'Invalid key length: {len(self.key)}')

    def public_key(self):
        """Derives the public key from the private key"""
        return MLDSAPublicKey(self.type.pk_from_sk(self.key))

    def sign(self, payload, hash_name=""):
        """Signs the given payload using the ML-DSA private key"""
        if not hash_name:
            raise ValueError("Hash name must be specified for signing")
        return self.signature_type.sign_with_pre_hash(
            self.key, payload, hash_name, ctx=b'', deterministic=False
        )

    def serialize(self, encoding):
        """Serializes the private key in the specified encoding format"""
        if encoding.upper() == 'DER':
            return pkcs.sk_to_der(self.type, self.key)
        elif encoding.upper() == 'PEM':
            return pkcs.sk_to_pem(self.type, self.key)
        else:
            raise ValueError(f'Unsupported encoding format: {encoding}')


class MLDSAHandler:
    """Handles ML-DSA signature and parse key data operations"""

    @staticmethod
    def populate_public_key(value: bytes) -> MLDSAPublicKey:
        """ Generates an ML-DSA public key from bytes """
        return MLDSAPublicKey(value)

    @staticmethod
    def populate_private_key(value: bytes) -> MLDSAPrivateKey:
        """ Generates an ML-DSA private key from bytes """
        return MLDSAPrivateKey(value)

    @staticmethod
    def export_public_key(private_key: MLDSAPrivateKey) -> MLDSAPublicKey:
        """Exports the public key from a private key"""
        return private_key.public_key()

    @staticmethod
    def serialize(key, encoding):
        """Serializes the key in the specified encoding format"""
        key.serialize(encoding)

    @staticmethod
    def public_bytes(public_key: MLDSAPublicKey) -> bytes:
        """Encoding public key in DER format and return as byte sequence"""
        return public_key.key

    @staticmethod
    def load_pem_private_key(data):
        """Loads a public ML-DSA key from bytes in PEM encoding"""
        try:
            _, sk, _, _ = pkcs.sk_from_pem(data)
        except UnexpectedDER as e:
            raise ValueError("Failed to parse the private key. "
                             "The data may be in an incorrect format") from e
        return MLDSAPrivateKey(sk)

    @staticmethod
    def load_pem_public_key(data):
        """Loads a public ML-DSA key from bytes in PEM encoding"""
        try:
            _, pk = pkcs.pk_from_pem(data)
        except UnexpectedDER as e:
            raise ValueError("Failed to parse the public key. "
                             "The data may be in an incorrect format") from e
        return MLDSAPublicKey(pk)

    @staticmethod
    def load_der_private_key(data: bytes):
        """Loads a public ML-DSA key from bytes in DER encoding"""
        try:
            _, sk, _, _ = pkcs.sk_from_der(data)
        except UnexpectedDER as e:
            raise ValueError("Failed to parse the private key. "
                             "The data may be in an incorrect format") from e
        return MLDSAPrivateKey(sk)

    @staticmethod
    def load_der_public_key(data: bytes):
        """Loads a public ML-DSA key from bytes in DER encoding"""
        try:
            _, pk = pkcs.pk_from_der(data)
        except UnexpectedDER as e:
            raise ValueError("Failed to parse the public key. "
                             "The data may be in an incorrect format") from e
        return MLDSAPublicKey(pk)

    @staticmethod
    def is_private_key(key):
        """ Gets a value indicating whether the key is a private key """
        return isinstance(key, MLDSAPrivateKey)
