"""
Copyright 2023-2024 Cypress Semiconductor Corporation (an Infineon company)
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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


logger = logging.getLogger(__name__)


class EncryptorAES:
    """Encryption and decryption with AES"""

    @staticmethod
    def encrypt(payload, key, iv, mode):
        """Encrypts payload with AES cipher and PKCS7 padding
        @param payload: Bytes to encrypt
        @param key: Key bytes
        @param iv: Input vector or nonce bytes
        @param cipher_mode: Cipher mode (CBC or CTR)
        @return: bytes
        """
        padder = padding.PKCS7(len(key) * 8).padder()
        padded = padder.update(payload) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), EncryptorAES._mode(mode)(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()

        return ct

    @staticmethod
    def decrypt(ct, key, iv, mode):
        """Decrypts payload with AES cipher and PKCS7 padding
        @param ct: Bytes to decrypt
        @param key: Key bytes
        @param iv: Input vector or nonce bytes
        @param cipher_mode: Cipher mode (CBC or CTR)
        @return: bytes
        """
        cipher = Cipher(algorithms.AES(key), EncryptorAES._mode(mode)(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(len(key) * 8).unpadder()
        payload = unpadder.update(padded) + unpadder.finalize()

        return payload

    @staticmethod
    def _mode(mode):
        if mode.upper() == 'CBC':
            return modes.CBC
        elif mode.upper() == 'CTR':
            return modes.CTR
        else:
            raise ValueError('Unsupported cipher mode. Expected: CBC, CTR')
