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

from ...execute.imgtool.image import TLV_VALUES
from .ram_app_package import RamAppPackagePsocC3

logger = logging.getLogger(__name__)


class RamAppPackagePsocC3v2(RamAppPackagePsocC3):
    """A class representing the RAM application package"""

    def __init__(self, ram_app, input_params=None):
        """
        Creates an instance of RAM application package
        @param ram_app: Path to the RAM application
        @param input_params: Path to the RAM application input
            parameters
        """
        super().__init__(ram_app, input_params)
        self.options.update({
            'remove_tlv': [TLV_VALUES['SHA256'],
                           TLV_VALUES['SHA384'],
                           TLV_VALUES['SHA512'],
                           TLV_VALUES['KEYHASH'],
                           TLV_VALUES['PUBKEY']]
        })

