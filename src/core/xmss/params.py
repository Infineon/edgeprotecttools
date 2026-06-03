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
from enum import IntEnum
import collections


Parameter = collections.namedtuple(
    "Parameter", ["oid", "func", "n", "padding_len", "h", "d", "w"]
)

# XMSS parameter catalog:
# oid_str: (oid, func, n, padding_len, h, d, w)
XMSS_PARAMS = {
    "XMSS-SHA2_10_256":     Parameter(0x01, "SHA256",   32, 32, 10, 1, 16),
    "XMSS-SHA2_16_256":     Parameter(0x02, "SHA256",   32, 32, 16, 1, 16),
    "XMSS-SHA2_20_256":     Parameter(0x03, "SHA256",   32, 32, 20, 1, 16),
    "XMSS-SHA2_10_512":     Parameter(0x04, "SHA512",   64, 64, 10, 1, 16),
    "XMSS-SHA2_16_512":     Parameter(0x05, "SHA512",   64, 64, 16, 1, 16),
    "XMSS-SHA2_20_512":     Parameter(0x06, "SHA512",   64, 64, 20, 1, 16),
    "XMSS-SHAKE_10_256":    Parameter(0x07, "SHAKE128", 32, 32, 10, 1, 16),
    "XMSS-SHAKE_16_256":    Parameter(0x08, "SHAKE128", 32, 32, 16, 1, 16),
    "XMSS-SHAKE_20_256":    Parameter(0x09, "SHAKE128", 32, 32, 20, 1, 16),
    "XMSS-SHAKE_10_512":    Parameter(0x0A, "SHAKE256", 64, 64, 10, 1, 16),
    "XMSS-SHAKE_16_512":    Parameter(0x0B, "SHAKE256", 64, 64, 16, 1, 16),
    "XMSS-SHAKE_20_512":    Parameter(0x0C, "SHAKE256", 64, 64, 20, 1, 16),
    "XMSS-SHA2_10_192":     Parameter(0x0D, "SHA2",     24, 4, 10, 1, 16),
    "XMSS-SHA2_16_192":     Parameter(0x0E, "SHA2",     24, 4, 16, 1, 16),
    "XMSS-SHA2_20_192":     Parameter(0x0F, "SHA2",     24, 4, 20, 1, 16),
    "XMSS-SHAKE256_10_256": Parameter(0x10, "SHAKE256", 32, 32, 10, 1, 16),
    "XMSS-SHAKE256_16_256": Parameter(0x11, "SHAKE256", 32, 32, 16, 1, 16),
    "XMSS-SHAKE256_20_256": Parameter(0x12, "SHAKE256", 32, 32, 20, 1, 16),
    "XMSS-SHAKE256_10_192": Parameter(0x13, "SHAKE256", 24, 4, 10, 1, 16),
    "XMSS-SHAKE256_16_192": Parameter(0x14, "SHAKE256", 24, 4, 16, 1, 16),
    "XMSS-SHAKE256_20_192": Parameter(0x15, "SHAKE256", 24, 4, 20, 1, 16),
}


class AddrType(IntEnum):
    """Address types (commonly used values)"""
    ADDR_TYPE_OTS = 0
    ADDR_TYPE_L_TREE = 1
    ADDR_TYPE_HASH_TREE = 2


class XMSSParams:
    """
    XMSS parameters.
    """
    XMSS_OID_LEN = 4
    INDEX_LEN = 4
    BIT_NUM = 8

    def __init__(self, oid_str: str):
        """
        Initialize XMSS parameters for the given OID string.
        """
        if oid_str not in XMSS_PARAMS:
            raise ValueError(f"Unknown XMSS type: {oid_str}")

        self.oid_str = oid_str
        parameter = XMSS_PARAMS[oid_str]

        self.oid = parameter.oid
        self.func = parameter.func
        self.n = parameter.n
        self.padding_len = parameter.padding_len
        self.h = parameter.h
        self.d = parameter.d
        self.w = parameter.w

        self.tree_height = self.h // self.d
        # Compute per-layer tree height consistently (XMSSMT)
        computed_tree_height = self.h // self.d
        if self.tree_height != computed_tree_height:
            self.tree_height = computed_tree_height

        # Index bytes: 4 for single tree (d == 1), else ceil(h / 8)
        self.index_len = self.INDEX_LEN if self.d == 1 else (
            self.h + self.BIT_NUM - 1) // self.BIT_NUM

        # Public and secret key sizes
        self.pk_with_oid_len = self.XMSS_OID_LEN + 2 * self.n
        self.sk_with_oid_len = self.XMSS_OID_LEN + \
            self.index_len + (4 * self.n)

    @staticmethod
    def oid_to_str(oid_int: int) -> str:
        """
        Return the XMSS parameter name (oid_str) for a given integer OID.
        """
        for name, spec in XMSS_PARAMS.items():
            if spec.oid == oid_int:
                return name
        raise ValueError(f"Unknown XMSS OID: {oid_int}")
