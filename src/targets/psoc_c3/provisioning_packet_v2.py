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
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .key_validator_v2 import KeyValidatorPsocC3v2
from .ram_app_package_v2 import RamAppPackagePsocC3v2
from .packet_builder_v2 import PacketBuilder
from .provisioning_packet import ProvisioningPacketPsocC3
from .asset_builder import AssetBuilderPsocC3


logger = logging.getLogger(__name__)


class ProvisioningPacketPsocC3v2(ProvisioningPacketPsocC3):
    """ Provisioning packet generator for PSoC C3 family """

    def __init__(self, policy_parser, asset_map):
        super().__init__(policy_parser, asset_map)
        self.packet_builder = PacketBuilder(self.policy_parser, asset_map)

    def prot_fw_policy_data(self):
        """Gets Protected FW policy packet data"""
        assets_list = self._provisioning_assets()
        asset_builder = AssetBuilderPsocC3(self.policy_parser, assets_list,
                                           self.asset_map,
                                           policy_type=self.policy_type)
        input_data = asset_builder.get_assets()

        if self.policy_parser.prot_fw_encrypt_enable():
            iv = self.prot_fw_policy_encrypt_iv()
            key = self.prot_fw_policy_encrypt_key()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ct = encryptor.update(input_data) + encryptor.finalize()
            data = iv + ct
        else:
            iv = bytes(16)
            data = iv + input_data

        return data

    def prot_fw_policy_encrypt_iv(self):
        """Gets Protected FW policy encryption IV"""
        return self.policy_parser.prot_fw_encrypt_iv(ret_value=True)

    def prot_fw_policy_encrypt_key(self):
        """Gets Protected FW policy encryption key"""
        if self.policy_parser.prot_fw_encrypt_key(ret_value=False):
            return self.policy_parser.prot_fw_encrypt_key(ret_value=True)
        else:
            return self.policy_parser.enc_key('prot_fw_enc_key', ret_value=True)

    def generate_packet(self, key_path, signature, **kwargs):
        if key_path:
            KeyValidatorPsocC3v2().validate_private_key(key_path)
            packet = self.packet_builder.build_signed(key_path, **kwargs)
            logger.info(
                "Signed packet with '%s'", os.path.abspath(key_path)
            )
            info = 'Provisioning packet created'
            packet = len(packet).to_bytes(4, byteorder='little') + packet
        elif signature:
            packet = self.packet_builder.build_add_signature(
                signature, **kwargs
            )
            logger.info("Added signature '%s'", os.path.abspath(signature))
            info = 'Provisioning packet created'
            packet = len(packet).to_bytes(4, byteorder='little') + packet
        else:
            packet = self.packet_builder.build_unsigned(**kwargs)
            info = 'Data for signing created'

        return packet, info

    @staticmethod
    def _get_ram_app_package(app_path, input_params=None):
        return RamAppPackagePsocC3v2(app_path, input_params)

    def _get_packet_data(self, **kwargs):
        key = kwargs.get('key')
        signature = kwargs.get('signature')
        integrity_cert = kwargs.get('integrity_cert')

        info = 'Provisioning packet created'

        if self.policy_type == 'reprovisioning':
            logger.error("Invalid policy type '%s'", self.policy_type)
            return False
        elif self.policy_type == 'device_integrity_exam':
            packet = self.device_integrity_data(integrity_cert)
        elif self.policy_type == 'prot_fw_policy':
            packet = self.prot_fw_policy_data()
        elif self.policy_type == 'oem_provisioning':
            packet, info = self.generate_packet(
                key, signature,
                **{k: v for k, v in kwargs.items()
                   if k not in ("key", "signature")}
            )
        else:
            packet = self.provisioning_data()

        return packet, info
