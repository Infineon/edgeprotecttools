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

from .swd_loader import SwdLoaderPSE8x
from ...common.mxs22.provisioning import RamAppLoaderMXS22, SerialLoader

logger = logging.getLogger(__name__)


class RamAppLoaderPSE8x(RamAppLoaderMXS22):
    """ A class that implements loading RAM application routine """

    def __init__(self, app_status_codes):
        super().__init__(app_status_codes)
        self.swd_loader = SwdLoaderPSE8x
        self.serial_loader = SerialLoader
