# (c) 2026, Infineon Technologies AG, or an affiliate of Infineon
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
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec, rsa, padding, utils
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature
)
from pyhsslms import LmsPrivateKey

from ..core.key_handlers import load_private_key
from ..core.xmss.xmss import XMSSPrivateKey


class DataSigner:
    """Sign data from binary files or hex strings using various key types"""

    @staticmethod
    def sign(
            data_source: Union[str, Path],
            key: Union[
                str, Path,
                ec.EllipticCurvePrivateKey,
                rsa.RSAPrivateKey,
                LmsPrivateKey,
                XMSSPrivateKey
            ],
            password: str = None
    ) -> bytes:
        """
        Signs data from a binary file or hex string.

        Args:
            data_source: Either a file path to binary data or a hex string
            key: Either a path to the private key file or a key object
            password: Optional password for encrypted private keys
                      (only used if key is a path)

        Returns:
            bytes: The signature
        """
        data = DataSigner._load_data(data_source)

        if isinstance(key, (str, Path)):
            key = load_private_key(str(key), password=password)

        if isinstance(key, ec.EllipticCurvePrivateKey):
            return DataSigner._sign_with_ec(key, data)
        elif isinstance(key, rsa.RSAPrivateKey):
            return DataSigner._sign_with_rsa(key, data)
        elif isinstance(key, LmsPrivateKey):
            return DataSigner._sign_with_lms(key, data)
        elif isinstance(key, XMSSPrivateKey):
            return DataSigner._sign_with_xmss(key, data)
        else:
            raise ValueError(f"Unsupported key type: {type(key).__name__}")

    @staticmethod
    def _load_data(data_source: Union[str, Path]) -> bytes:
        """
        Load data from either a binary file or hex string.

        Args:
            data_source: Either a file path to binary data or a hex string

        Returns:
            bytes: The data to be signed

        Raises:
            ValueError: If the input is neither a valid file nor a
                        valid hex string
        """
        data_source = str(data_source)

        # Check if it's a valid hex string
        is_hex = (all(c.lower() in '0123456789abcdef' for c in data_source)
                  and len(data_source) % 2 == 0)
        if is_hex:
            return bytes.fromhex(data_source)

        # Try to load as a file
        file_path = Path(data_source)
        if file_path.is_file():
            with open(file_path, 'rb') as f:
                return f.read()

        raise ValueError(
            f"Invalid data source '{data_source}'. "
            f"Expected hex string or file path"
        )

    @staticmethod
    def _sign_with_ec(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        """
        Sign data with an ECDSA key.

        Args:
            key: The EC private key
            data: The data to sign

        Returns:
            bytes: The signature (R || S format)
        """
        # Select hash algorithm based on key size
        if key.key_size == 256:
            hash_algorithm = hashes.SHA256()
        elif key.key_size == 384:
            hash_algorithm = hashes.SHA384()
        elif key.key_size == 521:
            hash_algorithm = hashes.SHA512()
        else:
            raise ValueError(
                f"Unsupported ECDSA key size {key.key_size}. "
                f"Supported: 256, 384, 521"
            )

        # Sign the data
        signature = key.sign(data, ec.ECDSA(hash_algorithm))

        # Convert ASN.1 signature to R||S format
        r, s = decode_dss_signature(signature)
        values_size = key.key_size // 8 + (key.key_size % 8 > 0)

        r_bytes = r.to_bytes(values_size, byteorder='big')
        s_bytes = s.to_bytes(values_size, byteorder='big')
        return r_bytes + s_bytes

    @staticmethod
    def _sign_with_rsa(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """
        Sign data with an RSA key using PSS padding.

        Args:
            key: The RSA private key
            data: The data to sign

        Returns:
            bytes: The signature
        """
        digest = hashlib.sha256(data).digest()
        signature = key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return signature

    @staticmethod
    def _sign_with_lms(key: LmsPrivateKey, data: bytes) -> bytes:
        """
        Sign data with an LMS (Post-Quantum) key.

        Args:
            key: The LMS private key
            data: The data to sign

        Returns:
            bytes: The signature
        """
        return key.sign(data)

    @staticmethod
    def _sign_with_xmss(key: XMSSPrivateKey, data: bytes) -> bytes:
        """
        Sign data with an XMSS (Post-Quantum) key.

        Args:
            key: The XMSS private key
            data: The data to sign

        Returns:
            bytes: The signature
        """
        return key.sign(data)


def sign_data(
    data_source: Union[str, Path],
    key: Union[
        str, Path,
        ec.EllipticCurvePrivateKey,
        rsa.RSAPrivateKey,
        LmsPrivateKey,
        XMSSPrivateKey
    ],
    password: str = None
) -> bytes:
    """
    Convenience function to sign data from a binary file or hex string.

    Args:
        data_source: Either a file path to binary data or a hex string
        key: Either a path to the private key file or a cryptography
             key object
        password: Optional password for encrypted private keys
                  (only used if key is a path)

    Returns:
        bytes: The signature

    Examples:
        # Sign data from a hex string with key path
        signature = sign_data("0123456789abcdef", "private_key.pem")

        # Sign data from a binary file with encrypted key
        signature = sign_data(
            "data.bin", "private_key.pem", password="secret"
        )

        # Sign with key object
        from cryptography.hazmat.primitives.asymmetric import ec
        key_obj = ec.generate_private_key(ec.SECP256R1())
        signature = sign_data("0123456789abcdef", key_obj)
    """
    return DataSigner.sign(data_source, key, password)
