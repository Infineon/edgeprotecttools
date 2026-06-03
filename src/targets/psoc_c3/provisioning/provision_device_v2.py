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

from ....core.enums import ProvisioningStatus
from ....core.target_director import Target
from ....execute.programmer.dfuht_wrapper import Dfuht
from ..provisioning import ProvisioningPsocC3

logger = logging.getLogger(__name__)


class ProvisioningPsocC3v2(ProvisioningPsocC3):
    """A high-level class for provisioning PSoC C3 targets"""

    def provision(self, tool, target: Target, bootloader=None,
                  **kwargs) -> ProvisioningStatus:
        """Starts provisioning process using the specified flow"""
        if not kwargs.get('config'):
            if 'dfu' in target.policy_parser.policy_type():
                image = kwargs.get('image')
                if image:
                    target.context['image'] = image
                else:
                    raise ValueError('Device Firmware Update '
                                     '"image" must be specified')

                if not isinstance(tool, Dfuht):
                    raise ValueError('This flow can be executed '
                                     'only with "serial" tool')

        mode = None
        config = kwargs.get('config')

        if config is None:
            mode = target.policy_parser.policy_type()

        if mode is not None and 'reprovisioning' in mode:
            raise ValueError('Reprovisioning policy type specified for the '
                             'provisioning operation')

        status = self._provision(
            tool, target, mode, config, kwargs.get('testapps'))

        if status in (ProvisioningStatus.OK, ProvisioningStatus.STOP):
            logger.info('*****************************************')
            logger.info('       PROVISIONING PASSED               ')
            logger.info('*****************************************\n')
            status = ProvisioningStatus.OK
        elif status == ProvisioningStatus.SKIPPED:
            logger.error('The device cannot be provisioned due to invalid '
                         'lifecycle stage')

        return status
