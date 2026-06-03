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
import os

from .address import Address, OtsAddress, LTreeAddress, NodeAddress
from .params import XMSSParams, AddrType
from .wots import Wots


class XMSS:
    """Base class for XMSS private and public keys"""

    def __init__(self, params):
        self.params = params
        self.wots = Wots(params)

    @property
    def n(self):
        """Returns the hash output length in bytes (n)."""
        return self.params.n

    @property
    def tree_height(self):
        """Returns the Merkle tree height relevant for XMSS."""
        return self.params.tree_height

    @property
    def h(self):
        """Returns the parameter h as provided in params."""
        return self.params.h

    @property
    def d(self):
        """Returns the parameter d as provided in params."""
        return self.params.d

    @property
    def index_len(self):
        """Returns the index length as provided in params."""
        return self.params.index_len


class XMSSPrivateKey(XMSS):
    """
    XMSS core.
    This class implements the eXtended Merkle Signature Scheme (XMSS),
    a hash-based, post-quantum secure digital signature algorithm. 
    XMSS constructs a Merkle tree  over many one-time signature (WOTS+) 
    key pairs and authenticates each WOTS+ public key via its path in the tree,
    enabling many-time signatures while preserving  security under standard 
    hash assumptions.
    """

    def __init__(self, params):
        super().__init__(params)
        self.sk_seed = os.urandom(self.params.n)
        self.sk_prf = os.urandom(self.params.n)
        self.pub_seed = os.urandom(self.params.n)
        self.index = bytes(self.params.index_len)
        self.top_tree_addr = Address()
        self.top_tree_addr.layer_addr = self.params.d - 1
        self.leaf_idx = 0
        self.pub_root, _ = self.wots.tree_hash(
            self.sk_seed, self.pub_seed, self.leaf_idx, self.top_tree_addr)
        self.oid_bytes = self.params.oid.to_bytes(
            self.params.XMSS_OID_LEN, byteorder='big')
        self.pk = self.oid_bytes + self.pub_root + self.pub_seed
        self.sk = self.oid_bytes + self.index + self.sk_seed + \
            self.sk_prf + self.pub_root + self.pub_seed
        self.attempt = 0

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using the internal secret key.
        Updates the internal index in self.sk after signing.
        Returns the raw XMSS signature (bytes).
        """
        idx = int.from_bytes(self.index, byteorder='big')
        max_idx = (1 << self.h) - 1
        if idx > max_idx:
            raise ValueError("Secret key exhausted")

        wots_sig_bytes = self.wots.wots_len * self.n
        signature_len = self.index_len + self.n + \
            self.d * wots_sig_bytes + self.h * self.n
        signature = bytearray(signature_len)
        signature[0: self.index_len] = self.index
        idx_bytes_32 = idx.to_bytes(32, byteorder='big')
        R = self.wots.prf(self.sk_prf, idx_bytes_32)
        signature[self.index_len: self.index_len + self.n] = R

        root = self.wots.hash_message(R, self.pub_root, idx, message)
        offset = self.index_len + self.n

        ots_addr = OtsAddress()
        ots_addr.type = AddrType.ADDR_TYPE_OTS

        tmp_idx = idx
        for i in range(self.d):
            idx_leaf = tmp_idx & ((1 << self.tree_height) - 1)
            tmp_idx >>= self.tree_height

            ots_addr.layer_addr = i
            ots_addr.tree_addr = tmp_idx
            ots_addr.ots_leaf_idx = idx_leaf

            wots_sig = self.wots.sign(
                root, self.sk_seed, self.pub_seed, ots_addr
            )
            signature[offset: offset + wots_sig_bytes] = wots_sig
            offset += wots_sig_bytes

            subtree_addr = Address()
            subtree_addr.subtree_addr = ots_addr.address
            subtree_addr.type = AddrType.ADDR_TYPE_HASH_TREE

            auth_root, auth_path = self.wots.tree_hash(
                self.sk_seed, self.pub_seed, idx_leaf, subtree_addr
            )
            root = auth_root
            signature[offset: offset + self.tree_height * self.n] = auth_path
            offset += self.tree_height * self.n

        idx += 1
        self.attempt = idx
        updated_sk = bytearray(self.sk)
        self.index = idx.to_bytes(self.index_len, byteorder='big')
        updated_sk[self.params.XMSS_OID_LEN: self.params.XMSS_OID_LEN +
                   self.index_len] = self.index
        self.sk = bytes(updated_sk)
        return bytes(signature)

    def public_key(self):
        """
        Return the public key that matches this XMSS instance.
        """
        return XMSSPublicKey.deserialize(self.pk)

    def parse_secret_key_no_oid(self, sk: bytes) -> tuple:
        """
        Parse a secret key (without OID) into its constituent fields.

        The input is interpreted in the following order and sizes:
        - idx:      self.index_len bytes (big-endian integer)
        - sk_seed:  self.n bytes (secret seed)
        - sk_prf:   self.n bytes (PRF key)
        - pub_root: self.n bytes (public root / Merkle root)
        - pub_seed: self.n bytes (public seed)

        Args:
            sk: A bytes object containing the concatenation:
                idx || sk_seed || sk_prf || pub_root || pub_seed.
        """
        idx = sk[0: self.index_len]
        sk_seed = sk[self.index_len: self.index_len + self.n]
        sk_prf = sk[self.index_len + self.n: self.index_len + 2 * self.n]
        pub_root = sk[self.index_len + 2 * self.n: self.index_len + 3 * self.n]
        pub_seed = sk[self.index_len + 3 * self.n: self.index_len + 4 * self.n]
        return idx, sk_seed, sk_prf, pub_root, pub_seed

    @classmethod
    def deserialize(cls, key_with_oid: bytes):
        """
        Deserialize XMSS key with OID.
        """
        if not isinstance(key_with_oid, (bytes, bytearray)):
            raise TypeError("key_with_oid must be bytes or bytearray")
        oid_bytes = key_with_oid[: XMSSParams.XMSS_OID_LEN]
        oid_int = int.from_bytes(oid_bytes, byteorder="big")
        xmss_type = XMSSParams.oid_to_str(oid_int)
        params = XMSSParams(xmss_type)

        if params.sk_with_oid_len != len(key_with_oid):
            raise ValueError("Invalid XMSS private key length.")

        xmss = cls(params)
        xmss.oid_bytes = oid_bytes
        total_len = len(key_with_oid)

        if total_len == params.sk_with_oid_len:
            xmss.sk = bytes(key_with_oid)
            (
                xmss.index, xmss.sk_seed, xmss.sk_prf,
                xmss.pub_root, xmss.pub_seed
            ) = xmss.parse_secret_key_no_oid(
                key_with_oid[XMSSParams.XMSS_OID_LEN:])
            xmss.pk = xmss.oid_bytes + xmss.pub_root + xmss.pub_seed
            return xmss
        raise ValueError("Invalid XMSS key length for the given OID/type.")

    def serialize(self) -> bytes:
        """
        SK = OID || idx || sk_seed || SK_PRF || pub root || pub SEED
        """
        return self.sk

    def is_exhausted(self):
        """
        Return True if this private key has been exhausted and must not be used
        for further signing.
        """
        idx = int.from_bytes(self.index, byteorder='big')
        return idx >= 1 << self.h

    def max_signatures(self):
        """
        Return the total number of signatures permitted for this key.
        """
        return 1 << self.h


class XMSSPublicKey(XMSS):
    """
    Public Key
    """

    def __init__(self, params):
        super().__init__(params)
        self.oid_bytes = b''
        self.pk = b''
        self.pub_root = b''
        self.pub_seed = b''

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify signature against this public key.
        """
        wots_sig_bytes = self.wots.wots_len * self.n

        idx = int.from_bytes(
            signature[: self.index_len], byteorder='big')
        R = signature[self.index_len: self.index_len + self.n]
        root = self.wots.hash_message(R, self.pub_root, idx, message)
        offset = self.index_len + self.n

        ots_addr = OtsAddress()
        l_tree_addr = LTreeAddress()
        node_addr = NodeAddress()

        ots_addr.type = AddrType.ADDR_TYPE_OTS
        l_tree_addr.type = AddrType.ADDR_TYPE_L_TREE
        node_addr.type = AddrType.ADDR_TYPE_HASH_TREE

        for i in range(self.d):
            idx_leaf = idx & ((1 << self.tree_height) - 1)
            idx >>= self.tree_height

            ots_addr.layer_addr = i
            l_tree_addr.layer_addr = i
            node_addr.layer_addr = i

            ots_addr.tree_addr = idx
            l_tree_addr.tree_addr = idx
            node_addr.tree_addr = idx

            ots_addr.ots_leaf_idx = idx_leaf
            l_tree_addr.l_tree_leaf_idx = idx_leaf

            wots_sig = signature[offset: offset + wots_sig_bytes]
            offset += wots_sig_bytes

            wots_pk = self.wots.wots_pk_from_sig(
                wots_sig, root, self.pub_seed, ots_addr)
            leaf = self.wots.l_tree(wots_pk, self.pub_seed, l_tree_addr)

            auth_path = signature[offset: offset + self.tree_height * self.n]
            offset += self.tree_height * self.n

            root = self.wots.compute_root(
                leaf, idx_leaf, auth_path, self.pub_seed, node_addr)
        return root == self.pub_root

    def serialize(self) -> bytes:
        """
        Serialize XMSS public key (OID + pk).
        """
        return self.pk

    def parse_public_key_no_oid(self, pk: bytes) -> tuple:
        """
        Parse a public key (without OID) into its constituent fields.

        The input is interpreted in the following order and sizes:
        - pub_root: self.n bytes
        - pub_seed: self.n bytes

        Args:
            pk: A bytes object containing the concatenation:
                pub_root || pub_seed.
        """
        pub_root = pk[: self.n]
        pub_seed = pk[self.n: 2 * self.n]
        return pub_root, pub_seed

    @classmethod
    def deserialize(cls, key_with_oid: bytes):
        """
        Deserialize XMSS public key (OID + pk).
        """
        if not isinstance(key_with_oid, (bytes, bytearray)):
            raise TypeError("key_with_oid must be bytes or bytearray")

        oid_bytes = key_with_oid[:XMSSParams.XMSS_OID_LEN]
        oid_int = int.from_bytes(oid_bytes, byteorder="big")
        xmss_type = XMSSParams.oid_to_str(oid_int)
        params = XMSSParams(xmss_type)

        if params.pk_with_oid_len != len(key_with_oid):
            raise ValueError("Invalid XMSS public key length.")

        xmss = cls(params)
        xmss.oid_bytes = oid_bytes
        total_len = len(key_with_oid)

        if total_len == params.pk_with_oid_len:
            xmss.pk = bytes(key_with_oid)
            xmss.pub_root, xmss.pub_seed = xmss.parse_public_key_no_oid(
                key_with_oid[XMSSParams.XMSS_OID_LEN:])
            return xmss
        raise ValueError(
            "Invalid XMSS public key length for the given OID/type.")
