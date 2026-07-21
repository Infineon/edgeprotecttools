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

from .swd_loader_v2 import SwdLoaderPsocC3v2
from .serial_loader_v2 import SerialLoaderPsocC3v2
from .ram_app_loader import RamAppLoaderPsocC3
from ....execute.programmer.dfuht_wrapper import Dfuht

logger = logging.getLogger(__name__)


class RamAppLoaderPsocC3v2(RamAppLoaderPsocC3):
    """ A class that implements loading RAM application routine """

    def load(self, tool, target, app):
        """ Loads application and its input parameters into RAM """
        self.tool = tool
        self.target = target
        self.app = app

        if isinstance(self.tool, Dfuht):
            loader = SerialLoaderPsocC3v2(
                self.tool, self.target, self.app, self.app_status_codes
            )
        else:
            loader = SwdLoaderPsocC3v2(
                self.tool, self.target, self.app, self.app_status_codes
            )
        return loader.load()

