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

from intelhex import IntelHex

from ....core.enums import ProvisioningStatus
from ...common.dlm_package import DLMPackage
from ...common.mxs40sv2.asset_enums import ApPermission
from ..dlm_policy import DLMPolicy
from .swd_loader import SwdLoaderPsocC3

logger = logging.getLogger(__name__)


class SwdLoaderPsocC3v2(SwdLoaderPsocC3):
    """Loads applications through the SWD port"""

    def __init__(self, tool, target, app, app_status_codes):
        super().__init__(tool, target, app, app_status_codes)
        self.dlm_policy = DLMPolicy

    def check_ap_config(self, dlm_path, lcs):
        """Deserialize RAM app input parameters and check AP configuration"""
        status = ProvisioningStatus.OK
        if not self.target.policy_generator:
            return status
        ihex = IntelHex(dlm_path)
        dlm = ihex.tobinarray().tobytes()
        dlm_data = DLMPackage(dlm)
        dlm_data.load_in_params()
        prov_packet = self.dlm_policy(dlm_data.in_params)
        if prov_packet.oem_packet:
            if prov_packet.debug_system_ap != ApPermission.Enabled.value:
                logger.info('System AP disabled')
                status = ProvisioningStatus.STOP
        return status

