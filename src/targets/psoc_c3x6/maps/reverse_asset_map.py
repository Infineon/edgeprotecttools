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
from .asset_map import asset_item_data
from ...common.mxs40sv2.asset_enums import ApPermission
from ...psoc_c3.maps.reverse_asset_map import ReverseAssetMap


class ReverseAssetMapPsocC3x6(ReverseAssetMap):
    """Reverse asset map class"""

    def reverse_asset(self, asset_name, asset_value):
        """
        Gets policy field path and value from the asset bytes
        @param asset_name: The name of the asset
        @param asset_value: The asset bytes
        @return: List of the tuples containing policy field path and value
        """
        handler_map = {
            'control_word': None,
            'nv_counter_a1': None,
            'nv_counter_a2': None,
            'failed_signature_counter': None,
            'iak_cfg': None,
            'prov_oem_complete': None,
            'access_restrict': self._access_restrict,
            'access_restrict_2': None,
            'listen_window': None,
            'boot_cfg_id': None,
            'boot_bank_ctr_offset': None,
            'boot_hash_locking': None,
            'boot_auth': None,
            'boot_app_layout': None,
            'boot_od_clk': None,
            'pc_ctl_valid': None,
            'oem_device_cert_blocks': None,
            'unused_2': None,
            'pc2_handler': None,
            'pc3_handler': None,
            'dfu_enable': None,
            'oem_device_cert_addr': None,
            'boundary_scan': None,
            'unused_3': None,
            'oem_debug_key': None,
            'oem_enc_key': None,
            'n_flash_mpc': None,
            'padding_1': None,
            'mpc_struct': None,
            'raw_data_pc012': None,
            'nonce': None,
            'ifx_revocation_signature': None,
        }

        asset_handler = handler_map.get(asset_name)
        return asset_handler(asset_value) if asset_handler else [[None, None]]

    def _access_restrict(self, asset_value):
        """Parses access_restrict field"""
        value = int.from_bytes(asset_value, byteorder='little')
        p = self.policy_parser
        lst = []
        shift, mask = asset_item_data(p, 'access_restrict', 'SYS_ENABLE')
        sys_enable = (value >> shift) & mask
        shift, mask = asset_item_data(p, 'access_restrict', 'SYS_DISABLE')
        sys_disable = (value >> shift) & mask

        lut = {
            0b00: 0b01,
            0b01: 0b00,
            0b10: 0b10
        }

        sys_ap = (sys_disable & 0x1) << 1 | (sys_enable & 0x1)
        lst.append((
            'device_policy.debug.system.ap.value',
            ApPermission(lut[sys_ap]).name))
        shift, mask = asset_item_data(
            p, 'access_restrict', 'SYS_SECURE_ENABLE'
        )
        sys_secure_enable = (value >> shift) & mask

        shift, mask = asset_item_data(
            p, 'access_restrict', 'SYS_SECURE_DISABLE'
        )
        sys_secure_disable = (value >> shift) & mask

        secure_ap = (sys_secure_disable & 0x1) << 1 | (sys_secure_enable & 0x1)
        lst.append((
            'device_policy.debug.system.secure.value',
            ApPermission(lut[secure_ap]).name))
        return lst
