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
from typing import List, Tuple
from hashlib import sha256, sha512, shake_128, shake_256
from collections import namedtuple

from .address import Address, OtsAddress, LTreeAddress, NodeAddress
from .params import AddrType

Node = namedtuple("Node", ["value", "height"])


class WotsHashPadding(IntEnum):
    """Function padding identifiers."""
    HASH_PADDING_F = 0
    HASH_PADDING_H = 1
    HASH_PADDING_HASH = 2
    HASH_PADDING_PRF = 3
    HASH_PADDING_PRF_KEYGEN = 4


class Wots:
    """
    WOTS+ core.
    This class implements the Winternitz One-Time Signature scheme
    (WOTS/WOTS+), a hash-based, post-quantum one-time signature primitive.
    WOTS+ is commonly  used as the leaf signature algorithm in XMSS,
    where each WOTS+ public key is authenticated by a Merkle tree path
    to enable many-time signatures.
    """
    BIT_NUM = 8

    WOTS_PARAMS = {
        4:    {"lg_w": 2, "len2": 5},
        16:   {"lg_w": 4, "len2": 3},
        256:  {"lg_w": 8, "len2": 2},
    }

    def __init__(self, params):
        self.params = params
        # Derive WOTS parameters
        wots_params = self.WOTS_PARAMS[self.params.w]
        self.wots_lg_w = wots_params["lg_w"]
        self.wots_len1 = (self.BIT_NUM * self.params.n) // self.wots_lg_w
        self.wots_len2 = wots_params["len2"]
        self.wots_len = self.wots_len1 + self.wots_len2

    @property
    def n(self):
        """Returns the hash output length in bytes (n)."""
        return self.params.n

    @property
    def w(self):
        """Returns the Winternitz base (w)."""
        return self.params.w

    @property
    def padding_len(self):
        """
        Returns the padding/alignment length used in higher-level protocols.
        """
        return self.params.padding_len

    @property
    def tree_height(self):
        """Returns the Merkle tree height relevant for XMSS."""
        return self.params.tree_height

    @property
    def func(self):
        """Returns the hash/PRF function used by WOTS+."""
        return self.params.func

    def compute_core_hash(self, payload: bytes) -> bytes:
        """
        Core hash/XOF computation.
        """
        if self.func == "SHA2":
            return sha256(payload).digest()[:self.n]
        elif self.func == "SHA256":
            return sha256(payload).digest()
        elif self.func == "SHA512":
            return sha512(payload).digest()
        elif self.func == "SHAKE128":
            return shake_128(payload).digest(self.n)
        elif self.func == "SHAKE256":
            return shake_256(payload).digest(self.n)
        raise ValueError(f'Unsupported function: "{self.func}"')

    def prf(self, seed: bytes, in_data: bytes) -> bytes:
        """Compute PRF(key, in32) with padding."""
        hash_id = WotsHashPadding.HASH_PADDING_PRF.to_bytes(
            self.padding_len, byteorder="big")
        return self.compute_core_hash(hash_id + seed + in_data)

    def hash_message(self, R: bytes, root: bytes, idx: int, m: bytes) -> bytes:
        """
        Compute the message hash: padding || R || root || toByte(idx, n) || M.
        """
        hash_id = WotsHashPadding.HASH_PADDING_HASH.to_bytes(
            self.padding_len, byteorder="big")
        i = idx.to_bytes(self.n, byteorder="big")
        return self.compute_core_hash(hash_id + R + root + i + m)

    def _base_w(self, out_len: int,
                input_bytes: bytes) -> List[int]:
        """
        Interpret input bytes as base-w digits; requires wots_lg_w divides 8.
        """
        bit_num = 8
        digits_per_byte = bit_num // self.wots_lg_w
        output = []
        for i in range(out_len):
            byte_index = i // digits_per_byte
            shift = bit_num - (i % digits_per_byte + 1) * self.wots_lg_w
            total = input_bytes[byte_index]
            val = (total >> shift) & (self.w - 1)
            output.append(val)
        return output

    def _chain_lengths(self, msg: bytes) -> List[int]:
        """Derive chain lengths from message bytes."""
        bit_num = 8
        lengths = self._base_w(self.wots_len1, msg)
        c_sum = (self.w - 1) * self.wots_len1 - sum(lengths)
        shift = bit_num - self.wots_len2 * self.wots_lg_w % bit_num
        c_sum <<= shift
        c_sum_bytes_len = (self.wots_len2 * self.wots_lg_w +
                           bit_num - 1) // bit_num
        c_sum_bytes = c_sum.to_bytes(c_sum_bytes_len, byteorder="big")
        c_sum_bw = self._base_w(self.wots_len2, c_sum_bytes)
        return lengths + c_sum_bw

    def _prf_keygen(self, in_data: bytes, key: bytes) -> bytes:
        """Compute PRF key gen. (key, in_data=n + 32) with padding."""
        hash_id = WotsHashPadding.HASH_PADDING_PRF_KEYGEN.to_bytes(
            self.padding_len, byteorder="big")
        return self.compute_core_hash(hash_id + key + in_data)

    def _expand_seed(self, sk_seed: bytes, pub_seed: bytes,
                     ots_addr: OtsAddress):
        """Expand n-byte seed into wots_len * n bytes using prf key gen."""
        out_seed = bytearray(self.wots_len * self.n)
        ots_addr.hash_addr = 0
        ots_addr.key_and_mask = 0

        for i in range(self.wots_len):
            ots_addr.chain_addr = i
            buf = pub_seed + ots_addr.addr_to_bytes()  # n + 32 bytes
            out_seed[i * self.n: (i + 1) *
                     self.n] = self._prf_keygen(buf, sk_seed)
        return bytes(out_seed)

    def _rand_hash(self, left: bytes, right: bytes,
                   pub_seed: bytes, addr: Address):
        """
        Randomized Tree Hashing
        addr:
          NodeAddress, OtsAddress, LTreeAddress
        """
        addr.key_and_mask = 0
        key = self.prf(pub_seed, addr.addr_to_bytes())
        addr.key_and_mask = 1
        bm0 = self.prf(pub_seed, addr.addr_to_bytes())
        addr.key_and_mask = 2
        bm1 = self.prf(pub_seed, addr.addr_to_bytes())
        masked_left = bytes(a ^ b for a, b in zip(left, bm0))
        masked_right = bytes(a ^ b for a, b in zip(right, bm1))

        hash_id = WotsHashPadding.HASH_PADDING_H.to_bytes(
            self.padding_len, byteorder="big")
        return self.compute_core_hash(hash_id + key +
                                      masked_left + masked_right)

    def _gen_chain(self, start_val: bytes, start: int, steps: int,
                   pub_seed: bytes, ots_addr: OtsAddress) -> bytes:
        """Compute chaining function from start for given steps."""
        in_data = bytearray(start_val)
        hash_id = WotsHashPadding.HASH_PADDING_F.to_bytes(
            self.padding_len, byteorder="big")

        for i in range(start, min(start + steps, self.w)):
            ots_addr.hash_addr = i
            ots_addr.key_and_mask = 0
            key = self.prf(pub_seed, ots_addr.addr_to_bytes())
            ots_addr.key_and_mask = 1
            mask = self.prf(pub_seed, ots_addr.addr_to_bytes())
            masked = bytes(a ^ b for a, b in zip(in_data, mask))
            in_data = self.compute_core_hash(hash_id + key + masked)
        return bytes(in_data)

    def _pk_gen(
            self, sk_seed: bytes, pub_seed: bytes, ots_addr: OtsAddress
    ) -> bytes:
        """Generate WOTS+ public key from seed."""
        pk_elms = bytearray(self._expand_seed(sk_seed, pub_seed, ots_addr))
        pk_out = bytearray(self.wots_len * self.n)
        for i in range(self.wots_len):
            ots_addr.chain_addr = i
            slice_start = i * self.n
            slice_stop = (i + 1) * self.n
            pk_out[slice_start: slice_stop] = self._gen_chain(
                pk_elms[slice_start: slice_stop],
                0,
                self.w - 1,
                pub_seed, ots_addr
            )
        return bytes(pk_out)

    def sign(self, msg: bytes, sk_seed: bytes,
             pub_seed: bytes, ots_addr: OtsAddress) -> bytes:
        """Compute WOTS+ signature of msg using seed."""
        lengths = self._chain_lengths(msg)
        sk_elms = bytearray(self._expand_seed(sk_seed, pub_seed, ots_addr))
        sig_out = bytearray(self.wots_len * self.n)

        for i in range(self.wots_len):
            ots_addr.chain_addr = i
            slice_start = i * self.n
            slice_stop = (i + 1) * self.n
            sig_out[slice_start: slice_stop] = self._gen_chain(
                sk_elms[slice_start: slice_stop],
                0,
                lengths[i],
                pub_seed, ots_addr)
        return bytes(sig_out)

    def wots_pk_from_sig(self, sig: bytes, msg: bytes, pub_seed: bytes,
                         ots_addr: OtsAddress) -> bytes:
        """Derive WOTS+ public key from signature and message."""
        lengths = self._chain_lengths(msg)
        pk_out = bytearray(self.wots_len * self.n)
        for i in range(self.wots_len):
            ots_addr.chain_addr = i
            slice_start = i * self.n
            slice_stop = (i + 1) * self.n
            pk_out[slice_start: slice_stop] = self._gen_chain(
                sig[slice_start: slice_stop],
                lengths[i],
                self.w - 1 - lengths[i],
                pub_seed, ots_addr
            )
        return bytes(pk_out)

    def l_tree(self, wots_pk: bytes, pub_seed: bytes,
               l_tree_addr: LTreeAddress) -> bytes:
        """Compute a leaf node from a WOTS public key using L-tree."""
        l = self.wots_len
        pk = bytearray(wots_pk)
        n = self.n
        l_tree_addr.tree_height = 0

        while l > 1:
            parent_nodes = l >> 1
            for i in range(parent_nodes):
                l_tree_addr.tree_index = i
                base = (i << 1) * n
                left = pk[base: base + n]
                right = pk[base + n: ((i + 1) << 1) * n]
                hashed = self._rand_hash(left, right, pub_seed, l_tree_addr)
                pk[i * n: (i + 1) * n] = hashed

            if (l & 1) == 1:
                pk[parent_nodes * n: (parent_nodes + 1) * n] = \
                    pk[(l - 1) * n: l * n]

            l = (l + 1) >> 1
            l_tree_addr.tree_height += 1
        return bytes(pk[:n])

    def tree_hash(self, sk_seed: bytes, pub_seed: bytes, leaf_idx: int,
                  subtree_addr: Address) -> Tuple[bytes, bytes]:
        """
        Tree hash to compute root and authentication path for a given
        leaf index.
        """
        stack: list[Node] = []
        auth_path = bytearray(self.tree_height * self.n)

        ots_addr = OtsAddress()
        l_tree_addr = LTreeAddress()
        node_addr = NodeAddress()

        ots_addr.subtree_addr = subtree_addr.address
        l_tree_addr.subtree_addr = subtree_addr.address
        node_addr.subtree_addr = subtree_addr.address

        ots_addr.type = AddrType.ADDR_TYPE_OTS
        l_tree_addr.type = AddrType.ADDR_TYPE_L_TREE
        node_addr.type = AddrType.ADDR_TYPE_HASH_TREE

        for idx in range(1 << self.tree_height):
            l_tree_addr.l_tree_leaf_idx = idx
            ots_addr.ots_leaf_idx = idx
            pk = self._pk_gen(sk_seed, pub_seed, ots_addr)
            leaf_val = self.l_tree(pk, pub_seed, l_tree_addr)

            stack.append(Node(leaf_val, 0))

            if (leaf_idx ^ 0x1) == idx:
                auth_path[0:self.n] = leaf_val

            while len(stack) >= 2 and stack[-1].height == stack[-2].height:
                right = stack.pop()
                left = stack.pop()
                h = right.height

                node_addr.tree_height = h
                node_addr.tree_index = idx >> (h + 1)

                parent_val = self._rand_hash(
                    left.value, right.value,
                    pub_seed, node_addr
                )
                stack.append(Node(parent_val, h + 1))

                if (leaf_idx >> (h + 1)) ^ 0x1 == idx >> (h + 1):
                    start = (h + 1) * self.n
                    auth_path[start:start + self.n] = parent_val

        if len(stack) != 1 or stack[0].height != self.tree_height:
            raise RuntimeError("tree_hash: invalid final stack state")

        root = stack.pop().value
        return root, bytes(auth_path)

    def compute_root(self, leaf: bytes, leaf_idx: int, auth_path: bytes,
                     pub_seed: bytes, node_addr: NodeAddress) -> bytes:
        """Compute root from leaf and authentication path."""
        left = bytearray(self.n)
        right = bytearray(self.n)

        if leaf_idx & 1:
            left = auth_path[: self.n]
            right = leaf
        else:
            left = leaf
            right = auth_path[: self.n]
        auth_offset = self.n

        for i in range(0, self.tree_height - 1):
            node_addr.tree_height = i

            leaf_idx >>= 1
            node_addr.tree_index = leaf_idx

            hashed = self._rand_hash(left, right, pub_seed, node_addr)
            if leaf_idx & 1:
                left = auth_path[auth_offset: auth_offset + self.n]
                right = hashed
            else:
                left = hashed
                right = auth_path[auth_offset: auth_offset + self.n]
            auth_offset += self.n

        node_addr.tree_height = self.tree_height - 1
        leaf_idx >>= 1
        node_addr.tree_index = leaf_idx
        return self._rand_hash(left, right, pub_seed, node_addr)
