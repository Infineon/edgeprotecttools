# (c) 2023-2026, Infineon Technologies AG, or an affiliate of Infineon
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
import time
from collections import namedtuple

from ..enums import LifecycleStage
from ..si_data_reader.si_data_reader_mxs22_v1 import SiliconDataReaderMxs22V1

logger = logging.getLogger(__name__)

DeviceInfo = namedtuple('DeviceInfo', 'silicon_id silicon_rev family_id')
FwVersion = namedtuple(
    'FwVersion',
    'rom_boot rram_boot base_se_rt_services se_rt_services extended_boot')


class SiliconDataReaderMxs22V2(SiliconDataReaderMxs22V1):
    """ Implements reading data from the devices from ACWx4xx family """

    bootrow_lcs_map = {
        '00000000': LifecycleStage.VIRGIN,
        '00000003': LifecycleStage.SORT,
        '0000000f': LifecycleStage.PROVISIONED,
        '00000c03': LifecycleStage.NORMAL,
        '00000cc3': LifecycleStage.NORMAL_NO_SECURE,
        '00000c0f': LifecycleStage.NORMAL_PROVISIONED,
        '00000c3f': LifecycleStage.SECURE,
        '00000f03': LifecycleStage.RMA,
        '00000fc3': LifecycleStage.RMA,
        '0000030f': LifecycleStage.RMA,
        '00000f3f': LifecycleStage.RMA,
        '00000f0f': LifecycleStage.RMA,
    }

    def read_lifecycle_stage(self, tool, timeout=25) -> LifecycleStage:
        """ Reads device lifecycle stage """
        lcs = None
        start_time = time.time()
        while lcs is None:
            data = self.read32(tool, self.target.register_map.decoded_lcs_data)
            value = data.to_bytes(4, byteorder='big').hex()
            try:
                lcs = self.bootrow_lcs_map[value]
                logger.debug('BOOTROW value = %s', value)
                break
            except KeyError as ex:
                lcs = None
                logger.debug('Unknown BOOTROW value %s', ex)
                time.sleep(0.2)
            logger.debug('LCS = %s', lcs)
            if time.time() - start_time >= timeout:
                logger.error("Unknown BOOTROW value '%s'", value)
                raise TimeoutError('Reading BOOTROW timeout')
        return lcs

