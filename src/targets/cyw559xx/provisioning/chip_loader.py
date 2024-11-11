"""
Copyright 2024 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging
import os

from ....core.enums import ProvisioningStatus

logger = logging.getLogger(__name__)


class ChipLoad:
    """Loads applications with ChipLoad"""

    def __init__(self, tool, target, app):
        self.tool = tool
        self.target = target
        self.app = app

    def load(self):
        """Loads applications"""
        logger.info("Image programming '%s'", self.app.dlm_path)
        status = ProvisioningStatus.FAIL
        btp_config = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'patch_test.btp'))
        if self.tool.program(filename=self.app.dlm_path,
                             address=self.app.image_address,
                             btp_config=btp_config):
            status = ProvisioningStatus.OK
        return status

    def reset(self):
        """ Not implemented for chip_loader """
