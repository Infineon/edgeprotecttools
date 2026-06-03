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
import struct
from typing import List

MASK32 = 0xFFFFFFFF
ADDR_LEN_BYTES = 8


class Address:
    """
    XMSS generic address represented as 8 words (32 bits each), following the
    RFC 8391 address format conventions.

    Layout (indices 0..7):
      - [0]: layer_addr
              Merkle tree layer (top-level layer in XMSSMT; always 0 for XMSS).
      - [1]: tree_addr (high)
              High 32 bits of the 64-bit tree identifier (Merkle subtree).
      - [2]: tree_addr (low)
              Low 32 bits of the 64-bit tree identifier.
      - [3]: type
              Address type selector. Consumers set this to one of:
                - 0: OTS (WOTS+) address
                - 1: L-Tree address
                - 2: Hash-tree node address
              See AddrType for the canonical values.
      - [4..6]: type-specific fields
              Interpreted based on the address type:
                - OTS: [4] OTS/leaf index, [5] chain index, [6] hash index
                - L-Tree: [4] leaf index, [5] node height, [6] node index
                - Hash-tree: [4] padding (0), [5] node height, [6] node index
      - [7]: key_and_mask
              Selector used in t_hash/PRF operations to choose key/mask:
                - 0: use key
                - 1: use mask 1
                - 2: use mask 2

    Notes:
    - All words are stored as unsigned 32-bit values and are masked to 32 bits
      on write.
    - Serialization to bytes uses big-endian order (per common practice in
      reference implementations).
    - For XMSS (single-tree, d=1), layer_addr is typically 0; for XMSSMT, it
      enumerates the layer of the multi-tree structure.
    - The tree identifier (words [1] and [2]) is a 64-bit value split into
      high/low 32-bit halves, consistent with RFC 8391’s address definition.
    """

    def __init__(self):
        self._addr = [0] * ADDR_LEN_BYTES

    def addr_to_bytes(self) -> bytes:
        """
        Serialize the 8 x 32-bit address words to bytes in big-endian order.
        """
        if len(self._addr) != 8:
            raise ValueError("Expected exactly 8 address words")
        return struct.pack(">8I", *self._addr)

    @property
    def address(self) -> List[int]:
        """
        Return the raw address array of 8 words.

        Returns:
            List[int]: A list of 8 unsigned 32-bit integers representing
                       the full address state.

        Notes:
            - Modifying this list directly bypasses masking and validation.
              Prefer using dedicated setters for individual fields.
        """
        return self._addr

    @property
    def layer_addr(self) -> int:
        """
        Word [0]: Merkle tree layer number.

        Returns:
            int: The current layer index stored in word [0].

        Notes:
            - For XMSS (non-multi-tree), this is typically 0.
            - In XMSSMT, this indicates the current layer.
        """
        return self._addr[0]

    @layer_addr.setter
    def layer_addr(self, layer_addr: int) -> None:
        """
        Set the Merkle tree layer number in word [0] (masked to 32 bits).

        Args:
            layer_addr (int): Layer index to store (will be masked to 32 bits).
        """
        self._addr[0] = layer_addr & MASK32

    @property
    def subtree_addr(self) -> List[int]:
        """
        Return the subtree parameters slice [0..2] consisting of layer and
        tree words.

        Returns:
            List[int]: The slice self._addr[0:3], containing:
                [0] layer_addr (32-bit),
                [1] tree_addr high (upper 32 bits),
                [2] tree_addr low (lower 32 bits).
        """
        return self._addr[0:3]

    @subtree_addr.setter
    def subtree_addr(self, in_addr: List[int]) -> None:
        """
        Copy subtree parameters (layer and tree) from another address array.

        Copies:
            [0] layer_addr
            [1] tree_addr high (upper 32 bits)
            [2] tree_addr low (lower 32 bits)

        Args:
            in_addr (List[int]): A list-like object with at least three 32-bit
                             values representing layer and tree high/low words.
        """
        self._addr[0] = in_addr[0]
        self._addr[1] = in_addr[1]
        self._addr[2] = in_addr[2]

    @property
    def tree_addr(self) -> List[int]:
        """
        Return the two 32-bit tree-address words from self._addr[1:3].

        Returns:
            List[int]: The slice self._addr[1:3], containing:
                self._addr[1] -> tree_addr high (upper 32 bits)
                self._addr[2] -> tree_addr low (lower 32 bits)

        Notes:
          - This property returns raw words, not a reconstructed 64-bit integer.
            Use the high/low words to build the integer if needed.
        """
        return self._addr[1:3]

    @tree_addr.setter
    def tree_addr(self, tree_addr: int) -> None:
        """
        Set the 64-bit tree identifier into words [1] (high) and [2] (low).

        Args:
            tree_addr (int): 64-bit tree identifier.
        """
        self._addr[1] = (tree_addr >> 32) & MASK32
        self._addr[2] = tree_addr & MASK32

    @property
    def type(self) -> int:
        """
        Word [3]: Address type (consumer-specific, per RFC 8391).

        Returns:
            int: The address type stored in word [3].

        Expected values:
            - AddrType.ADDR_TYPE_OTS (0): OTS/WOTS+ address
            - AddrType.ADDR_TYPE_L_TREE (1): L-tree address
            - AddrType.ADDR_TYPE_HASH_TREE (2): Hash-tree node address
        """
        return self._addr[3]

    @type.setter
    def type(self, type_addr: int) -> None:
        """
        Set the address type in word [3] (masked to 32 bits).

        Args:
            type_addr (int): One of the defined type constants (see AddrType).
        """
        self._addr[3] = type_addr & MASK32

    @property
    def key_and_mask(self) -> int:
        """
        Word [7]: Auxiliary selector for PRF/t_hash operations.

        Typical values:
            - 0: use key
            - 1: use mask 1
            - 2: use mask 2

        Returns:
            int: The selector stored in word [7].

        Notes:
            - This field is used to differentiate inputs when computing
              hash/PRF in RFC 8391’s address-based constructions.
        """
        return self._addr[7]

    @key_and_mask.setter
    def key_and_mask(self, key_and_mask: int) -> None:
        """
        Set key_and_mask in word [7] (masked to 32 bits).

        Args:
            key_and_mask (int): Selector value; see typical values above.
        """
        self._addr[7] = key_and_mask & MASK32


class OtsAddress(Address):
    """
    OTS (WOTS+) address compliant with RFC 8391.

    Layout (indices 0..7):
      - [0]: layer_addr               (Merkle tree layer)
      - [1]: tree_addr (high)         (64-bit tree identifier, high 32 bits)
      - [2]: tree_addr (low)          (64-bit tree identifier, low  32 bits)
      - [3]: type                     (must be 0 = OTS)
      - [4]: OTS address              (WOTS/leaf index)
      - [5]: chain_addr               (WOTS chain index)
      - [6]: hash_addr                (hash step index within the WOTS chain)
      - [7]: key_and_mask             (PRF key/mask selector)

    Notes:
      - Ensure word [3] is set to AddrType.ADDR_TYPE_OTS (0) before use.
      - The layer/tree fields determine which OTS keypair you are addressing.
      - All setter operations mask inputs to 32 bits.
    """

    @property
    def ots_addr(self) -> int:
        """
        Word [4]: WOTS/leaf index associated with this OTS address.

        Returns:
            int: OTS/leaf index.
        """
        return self._addr[4]

    @ots_addr.setter
    def ots_leaf_idx(self, leaf_idx: int) -> None:
        """
        Set the WOTS/leaf index in word [4] (masked to 32 bits).

        Args:
            leaf_idx (int): Leaf index for OTS/WOTS+.
        """
        self._addr[4] = leaf_idx & MASK32

    @property
    def chain_addr(self) -> int:
        """
        Word [5]: WOTS chain index (which chain within the WOTS keypair).

        Returns:
            int: The chain index.
        """
        return self._addr[5]

    @chain_addr.setter
    def chain_addr(self, chain_addr: int) -> None:
        """
        Set the WOTS chain index in word [5] (masked to 32 bits).

        Args:
            chain_addr (int): Chain index within the WOTS keypair.
        """
        self._addr[5] = chain_addr & MASK32

    @property
    def hash_addr(self) -> int:
        """
        Word [6]: Hash step index within the given WOTS chain.

        Returns:
            int: The hash-step index.
        """
        return self._addr[6]

    @hash_addr.setter
    def hash_addr(self, hash_val: int) -> None:
        """
        Set the WOTS hash-step index in word [6] (masked to 32 bits).

        Args:
            hash_val (int): Hash step index within the chain.
        """
        self._addr[6] = hash_val & MASK32


class LTreeAddress(Address):
    """
    L-tree address (XMSS) compliant with RFC 8391.

    Layout (indices 0..7):
      - [0]: layer_addr              (Merkle tree layer)
      - [1]: tree_addr (high)        (64-bit tree identifier, high 32 bits)
      - [2]: tree_addr (low)         (64-bit tree identifier, low  32 bits)
      - [3]: type                    (must be 1 = L-tree)
      - [4]: L-tree leaf index       (keypair/leaf index associated with L-tree)
      - [5]: tree_height             (node height within the L-tree)
      - [6]: tree_index              (node index at the current height)
      - [7]: key_and_mask            (PRF key/mask selector)

    Notes:
      - Ensure word [3] is set to AddrType.ADDR_TYPE_L_TREE (1) before use.
      - The L-tree represents the reduction of a WOTS public key into a single
        n-byte value; height/index select nodes during L-tree hashing.
    """
    @property
    def l_tree_leaf_idx(self) -> int:
        """
        Word [4]: keypair/leaf index associated with this L-tree.

        Returns:
            int: Leaf index corresponding to the keypair.
        """
        return self._addr[4]

    @l_tree_leaf_idx.setter
    def l_tree_leaf_idx(self, leaf_idx: int) -> None:
        """
        Set the keypair/leaf index in word [4] (masked to 32 bits).

        Args:
            leaf_idx (int): Leaf index.
        """
        self._addr[4] = leaf_idx & MASK32

    @property
    def tree_height(self) -> int:
        """
        Word [5]: Node height within the L-tree.

        Returns:
            int: Current node height for an L-tree node.
        """
        return self._addr[5]

    @tree_height.setter
    def tree_height(self, tree_height: int) -> None:
        """
        Set the node height in word [5] (masked to 32 bits).

        Args:
            tree_height (int): Node height.
        """
        self._addr[5] = tree_height & MASK32

    @property
    def tree_index(self) -> int:
        """
        Word [6]: Node index at the current height.

        Returns:
            int: Current node index.
        """
        return self._addr[6]

    @tree_index.setter
    def tree_index(self, tree_index: int) -> None:
        """
        Set the node index in word [6] (masked to 32 bits).

        Args:
            tree_index (int): Node index at the current height.
        """
        self._addr[6] = tree_index & MASK32


class NodeAddress(Address):
    """
    Hash-tree node address (XMSS) compliant with RFC 8391.

    Layout (indices 0..7):
      - [0]: layer_addr               (Merkle tree layer)
      - [1]: tree_addr (high)         (64-bit tree identifier, high 32 bits)
      - [2]: tree_addr (low)          (64-bit tree identifier, low  32 bits)
      - [3]: type                     (should be 2 = hash-tree node)
      - [4]: padding                  (must be 0 for hash-tree nodes)
      - [5]: tree_height              (node height within the hash tree)
      - [6]: tree_index               (node index at the current height)
      - [7]: key_and_mask             (PRF key/mask selector)

    Notes:
      - Ensure word [3] is set to AddrType.ADDR_TYPE_HASH_TREE (2).
      - As per RFC 8391 conventions, word [4] is padding and should remain 0.
      - Height and index select the specific node within the hash tree.
    """

    @property
    def tree_height(self) -> int:
        """
        Word [5]: Node height within the hash tree.

        Returns:
            int: Current node height for a hash-tree node.
        """
        return self._addr[5]

    @tree_height.setter
    def tree_height(self, tree_height: int) -> None:
        """
        Set the node height in word [5] (masked to 32 bits).

        Args:
            tree_height (int): Node height.
        """
        self._addr[5] = tree_height & MASK32

    @property
    def tree_index(self) -> int:
        """
        Word [6]: Node index at the current height.

        Returns:
            int: Current node index for a hash-tree node.
        """
        return self._addr[6]

    @tree_index.setter
    def tree_index(self, tree_index: int) -> None:
        """
        Set the node index in word [6] (masked to 32 bits).

        Args:
            tree_index (int): Node index at the current height.
        """
        self._addr[6] = tree_index & MASK32
