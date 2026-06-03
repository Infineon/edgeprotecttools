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
import logging

from cbor import cbor

from ..common.mxs40sv2.enums import CoseSign1Packet

logger = logging.getLogger(__name__)


class DLMPolicy:
    """Extracts configuration data from the DLM packet"""

    def __init__(self, dlm_params):
        """
        @param dlm_params: The provisioning_package data
        """
        self.dlm_params = dlm_params
        self.oem_packet = None
        self.policy = None
        self.oem_cert = None
        self._access_restrict = None

        self.oem_packet = self.dlm_params.get(CoseSign1Packet.OEM_PROV_PACKET)
        if self.oem_packet:
            self.packet_type = CoseSign1Packet.OEM_PROV_PACKET
            packet_data = self.oem_packet.get(CoseSign1Packet.COSE_PACKET_ID)
            if packet_data:
                self.policy = self.load_policy(packet_data)
                self._access_restrict = self.policy.get(
                    CoseSign1Packet.ACCESS_RESTRICT_ID
                )

    @staticmethod
    def load_policy(packet_data):
        """DLM in_params from cbor to dictionary"""
        if packet_data:
            data = cbor.loads(packet_data)
            try:
                return cbor.loads(data.value[2])
            except Exception:  # pylint: disable=broad-except
                pass
        return None

    @property
    def debug_system_ap(self):
        """System AP configuration"""
        if self._access_restrict:
            return (self._access_restrict >> 2) & 0x01
        return None
