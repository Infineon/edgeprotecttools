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

from ..psoc_c3.provisioning_packet_v2 import ProvisioningPacketPsocC3v2


logger = logging.getLogger(__name__)


class ProvisioningPacketPsocC3x8(ProvisioningPacketPsocC3v2):
    """ Provisioning packet generator for PSoC C3 P8 family """

    ASSETS_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), 'flows')
    )

    ASSETS_FILE = {
        'provisioned': 'device_identity_assets.json',
        'normal_provisioned': 'prov_icv_assets.json',
        'oem_provisioning': 'oem_assets.json',
        'prot_fw_policy': 'prot_fw_assets.json',
        'dfu': 'dfu_assets.json',
    }
