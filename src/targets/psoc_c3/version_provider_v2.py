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

from .version_provider import VersionProviderPsocC3
from ..common.mxs40sv2.enums import LifecycleStage

logger = logging.getLogger(__name__)


class VersionProviderPsocC3v2(VersionProviderPsocC3):
    """
    This class encapsulates the routine for getting a version
    of different parts of the package
    """
    alt_names = {
        LifecycleStage.NORMAL_PROVISIONED.name: 'DEVELOPMENT',
        LifecycleStage.SECURE.name: 'PRODUCTION'
    }

    def log_lifecycle_stage(self, tool):
        """
        Reads device lifecycle stage and creates a
        logger info message
        """
        stage = self.get_lifecycle_stage(tool, alt_name=True)
        logger.info('Chip lifecycle stage: %s', stage.upper())

    def get_lifecycle_stage(self, tool, alt_name=False, **_):
        """Gets a lifecycle stage name
        @param tool: OCD tool
        @param alt_name: Indicates whether to use LCS alternative name
        @return: LCS name
        """
        lcs = super().get_lifecycle_stage(tool, **_)
        return self.alt_names.get(lcs, lcs) if alt_name else lcs
