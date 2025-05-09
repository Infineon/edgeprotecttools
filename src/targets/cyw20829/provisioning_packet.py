"""
Copyright 2021-2025 Cypress Semiconductor Corporation (an Infineon company)
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
import os
import logging

from ..cyw20829_a0.provisioning_packet import ProvisioningPacketCYW20829

logger = logging.getLogger(__name__)


class ProvisioningPacketCYW20829B1(ProvisioningPacketCYW20829):
    """ Provisioning packet generator for CYW20829 B1 target """

    ASSETS_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), 'flows')
    )
