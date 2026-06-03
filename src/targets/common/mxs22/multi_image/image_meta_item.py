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
import os
import re

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import (
    KBKDFCMAC, Mode, CounterLocation
)

from .....execute.encryption.encryptor_aes import EncryptorAES


class ImageMetaItem:
    """
    Represents a single meta item and its associated image.
    Each field is implemented as a property.
    Parsing and encryption logic is encapsulated in the class.
    """

    def __init__(self, item: dict, image: bytes, template_path: str):
        self.item = item
        self.image = image
        self.template_path = template_path

        known_properties = {
            'img_id', 'addr', 'edc_addr', 'nv_counter', 'nv_counter_addr_nvm',
            'nv_counter_addr_otp', 'hash_addr', 'l1_ver_img_idx',
            'img_info_offset', 'hash', 'enckey', 'salt', 'iv'
        }
        self.custom_properties = {
            k: v for k, v in item.items() if k not in known_properties
        }

        prop = item.get('img_id')
        self.img_id = int(str(prop), 0) if prop is not None else None

        prop = item.get('addr')
        if prop is None:
            raise ValueError("The 'addr' property must be specified")
        self.addr = int(str(prop), 0)

        prop = item.get('edc_addr')
        self.edc_addr = int(str(prop), 0) if prop is not None else None

        prop = item.get('nv_counter')
        self.nv_counter = int(str(prop), 0) if prop is not None else None

        prop = item.get('nv_counter_addr_nvm')
        self.nv_counter_addr_nvm = int(str(prop),
                                       0) if prop is not None else None

        prop = item.get('nv_counter_addr_otp')
        self.nv_counter_addr_otp = int(str(prop),
                                       0) if prop is not None else None

        prop = item.get('hash_addr')
        self.hash_addr = int(str(prop), 0) if prop is not None else None

        prop = item.get('l1_ver_img_idx')
        self.l1_ver_img_idx = int(str(prop), 0) if prop is not None else None

        prop = item.get('img_info_offset')
        self.img_info_offset = int(str(prop), 0) if prop is not None else None

        prop = item.get('hash')
        self.hash = self.process_hash(prop, image) if prop is not None else None

        prop = item.get('enckey')
        self.enckey = self.load_enckey(prop) if prop is not None else None
        prop = item.get('salt')
        self.salt = self.process_nonce(
            prop, 'salt') if prop is not None else None
        prop = item.get('iv')
        self.iv = self.process_nonce(prop, 'iv') if prop is not None else None

        self.wrapped_key = None

    def __repr__(self):
        return f"ImageMetaItem(img_id={self.img_id}, addr=0x{self.addr:08x})"

    def process_hash(self, hash_prop: str, image_bytes: bytes) -> bytes:
        """Processes hash field from the template property"""
        if hash_prop in ('auto', 'sha256'):
            img_hash = hashlib.sha256(image_bytes).digest()
        elif hash_prop == 'sha384':
            img_hash = hashlib.sha384(image_bytes).digest()
        elif hash_prop == 'sha512':
            img_hash = hashlib.sha512(image_bytes).digest()
        else:
            try:
                img_hash = bytes.fromhex(hash_prop)
            except ValueError:
                nonce_path = self.global_path(hash_prop)
                if os.path.isfile(nonce_path):
                    img_hash = self.load_bin(nonce_path)
                else:
                    raise ValueError(
                        "Error parsing property: 'hash'. The value must be "
                        "'sha256', 'sha384', 'sha512', a hex string, "
                        "or a path to a binary file")
        return img_hash

    def process_nonce(self, nonce, prop_name) -> bytes:
        """Processes salt or IV property from the meta item"""
        def validate_hex_string_length(s):
            if len(s) % 2 != 0:
                raise ValueError(
                    'The hex string must contain an even number of characters')

        if isinstance(nonce, bytes):
            return nonce

        m = re.match(r'^random(\d+)$', nonce)
        if m:
            nonce = os.urandom(int(m.group(1), 10))
        else:
            try:
                validate_hex_string_length(nonce)
                nonce = bytes.fromhex(nonce)
            except ValueError as exc:
                try:
                    nonce_path = self.global_path(nonce)
                    if os.path.isfile(nonce_path):
                        nonce = self.load_bin(nonce_path)
                    else:
                        raise ValueError from exc
                except ValueError as e:
                    raise ValueError(
                        f"Error parsing property: '{prop_name}'. "
                        "The value must be a hex string, 'randomN' string, "
                        "or a path to a binary file") from e

        validate_hex_string_length(nonce)
        return nonce

    @staticmethod
    def key_derivation(salt, length):
        """Derives key encryption key (KEK) from the AES key using CMAC"""
        return KBKDFCMAC(
            algorithm=algorithms.AES,
            mode=Mode.CounterMode,
            length=length,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=b'KBKDF_AESCMAC_v1',
            context=salt,
            fixed=None
        )

    def encrypt_image(self):
        """Encrypts image using AES-CTR with a random DEK
        and wraps DEK with KEK
        """
        if self.salt is None:
            raise ValueError(
                "The 'salt' property must be specified for encryption")
        if self.iv is None:
            raise ValueError(
                "The 'iv' property must be specified for encryption")
        if self.enckey is None:
            raise ValueError(
                "The 'enckey' property must be specified for encryption")
        enckey_length = len(self.enckey)
        kek = self.key_derivation(self.salt, enckey_length).derive(self.enckey)
        dek = os.urandom(enckey_length)
        self.wrapped_key = keywrap.aes_key_wrap(kek, dek)
        self.image = EncryptorAES.encrypt(self.image, dek, self.iv, 'CTR',
                                          pad=False)

    def to_dict(self):
        """Converts meta item to a dictionary excluding None values"""
        d = {
            'img_id': self.img_id,
            'addr': self.addr,
            'cnt': self.nv_counter,
            'nv_counter_addr_nvm': self.nv_counter_addr_nvm,
            'nv_counter_addr_otp': self.nv_counter_addr_otp,
            'hash_addr': self.hash_addr,
            'l1_ver_img_idx': self.l1_ver_img_idx,
            'img_info_offset': self.img_info_offset,
            'hash': self.hash,
            'iv': self.iv,
            'salt': self.salt,
            'wrapped_key': self.wrapped_key
        }
        d = {k: v for k, v in d.items() if v is not None}
        d.update(self.custom_properties)
        return d

    def logging_info(self):
        """Returns meta item logging information as a list of strings"""
        info = [
            f'Image ID: {self.img_id or "Not specified"}',
            f'Address: 0x{self.addr:08x}',
            f'Size: {len(self.image)} bytes'
        ]
        if self.hash:
            info.append(f'Hash: {self.hash.hex()}')
        if self.nv_counter is not None:
            info.append(f'NV counter: {self.nv_counter}')
        if self.nv_counter_addr_nvm is not None:
            info.append(f'NV counter addr NVM: 0x{self.nv_counter_addr_nvm:08x}')
        if self.nv_counter_addr_otp is not None:
            info.append(f'NV counter addr OTP: 0x{self.nv_counter_addr_otp:08x}')
        if self.hash_addr is not None:
            info.append(f'Hash addr: 0x{self.hash_addr:08x}')
        if self.l1_ver_img_idx is not None:
            info.append(f'L1 version image index: {self.l1_ver_img_idx}')
        if self.img_info_offset is not None:
            info.append(f'Image info offset: {hex(self.img_info_offset)}')
        if self.enckey:
            info.append('Image encrypted')
            info.append(f'Salt: {self.salt.hex()}')
            info.append(f'IV: {self.iv.hex()}')
            info.append(f'Wrapped key: {self.wrapped_key.hex()}')
        return info

    def global_path(self, path) -> str:
        """Returns absolute path based on the template file location"""
        if os.path.isabs(path):
            return path
        return os.path.join(os.path.dirname(self.template_path), path)

    @staticmethod
    def load_bin(path: str) -> bytes:
        """Loads data from a binary file"""
        with open(path, 'rb') as f:
            return f.read()

    def load_enckey(self, key) -> bytes:
        """Loads encryption key from a file or a hex string"""
        if re.match(r'^random(\d+)$', key):
            raise ValueError(f"Invalid encryption key value '{key}'")
        return self.process_nonce(key, 'enckey')
