# Copyright 2025 Giacomo Pope
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
from typing import Tuple
from cryptography.hazmat.primitives.hashes import (
    Hash,
    SHA224, SHA256, SHA384, SHA512,
    SHA512_224, SHA512_256,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256
)

from .ml_dsa import ML_DSA


class HashML_DSA(ML_DSA):
    """
    Implements the HashML-DSA signature scheme compliant with FIPS 204
    """

    @staticmethod
    def _hash_with_oid(m: bytes, hash_name: str) -> Tuple[bytes, bytes]:
        hash_name = hash_name.upper()

        if hash_name in ("SHA256", "SHA2-256"):
            # 2.16.840.1.101.3.4.2.1
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
            h = Hash(SHA256())
        elif hash_name in ("SHA384", "SHA2-384"):
            # 2.16.840.1.101.3.4.2.2
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02'
            h = Hash(SHA384())
        elif hash_name in ("SHA512", "SHA2-512"):
            # 2.16.840.1.101.3.4.2.3
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03'
            h = Hash(SHA512())
        elif hash_name in ("SHA224", "SHA2-224"):
            # 2.16.840.1.101.3.4.2.4
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04'
            h = Hash(SHA224())
        elif hash_name == "SHA2-512/224":
            # 2.16.840.1.101.3.4.2.5
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05'
            h = Hash(SHA512_224())
        elif hash_name == "SHA2-512/256":
            # 2.16.840.1.101.3.4.2.6
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06'
            h = Hash(SHA512_256())
        elif hash_name == "SHA3-224":
            # 2.16.840.1.101.3.4.2.7
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07'
            h = Hash(SHA3_224())
        elif hash_name == "SHA3-256":
            # 2.16.840.1.101.3.4.2.8
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08'
            h = Hash(SHA3_256())
        elif hash_name == "SHA3-384":
            # 2.16.840.1.101.3.4.2.9
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09'
            h = Hash(SHA3_384())
        elif hash_name == "SHA3-512":
            # 2.16.840.1.101.3.4.2.10
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0A'
            h = Hash(SHA3_512())
        elif hash_name == "SHAKE-128":
            # 2.16.840.1.101.3.4.2.11
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B'
            h = Hash(SHAKE128(32))
        elif hash_name == "SHAKE-256":
            # 2.16.840.1.101.3.4.2.12
            oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C'
            h = Hash(SHAKE256(64))
        else:
            raise ValueError(f"unsupported hash algorithm: {hash_name}")

        h.update(m)
        ph_m = h.finalize()

        return oid, ph_m

    def _sign_with_pre_hash(
        self,
        sk: bytes,
        m: bytes,
        hash_name: str,
        rnd: bytes,
        ctx: bytes = b"",
    ) -> bytes:
        """
        Generates a HashML-DSA signature following Algorithm 4 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, "
                f"ctx has length {len(ctx) = }"
            )

        # Prehash the message and return the OID of the used hash
        oid, ph_m = self._hash_with_oid(m, hash_name)

        # Format the message using the context
        m_prime = bytes([1]) + bytes([len(ctx)]) + ctx + oid + ph_m

        # Compute the signature of m_prime
        sig_bytes = self._sign_internal(sk, m_prime, rnd)
        return sig_bytes

    def _verify_with_pre_hash(
        self, pk: bytes, m: bytes, sig: bytes, hash_name: str, ctx: bytes = b""
    ) -> bool:
        """
        Verifies a signature sigma for a message M
        following algorithm 5 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, "
                f"ctx has length {len(ctx) = }"
            )

        # Prehash the message and return the OID of the used hash
        oid, ph_m = self._hash_with_oid(m, hash_name)

        # Format the message using the context
        m_prime = bytes([1]) + bytes([len(ctx)]) + ctx + oid + ph_m

        return self._verify_internal(pk, m_prime, sig)

    def sign_with_pre_hash(
        self,
        sk: bytes,
        m: bytes,
        hash_name: str,
        ctx: bytes = b"",
        deterministic: bool = False,
        rnd=None
    ) -> bytes:
        """
        Generates a HashML-DSA signature following Algorithm 4 (FIPS 204)
        with the specified hash function.
        """
        return self._sign_with_pre_hash(
            sk, m, hash_name, self._rnd(deterministic, rnd), ctx=ctx
        )

    def verify_with_pre_hash(
        self,
        pk: bytes,
        m: bytes,
        sig: bytes,
        hash_name: str,
        ctx: bytes = b""
    ) -> bool:
        """
        Verifies a HashML-DSA for a message M
        following algorithm 5 (FIPS 204)
        with the specified hash function.
        """
        return self._verify_with_pre_hash(pk, m, sig, hash_name, ctx=ctx)

    def sign(self, *_, **__) -> bytes:
        raise NotImplementedError(
            "sign() is not implemented for HashML_DSA, "
            "use sign_with_pre_hash() instead"
        )

    def verify(self, *_, **__) -> bool:
        raise NotImplementedError(
            "verify() is not implemented for HashML_DSA, "
            "use verify_with_pre_hash() instead"
        )
