# (c) 2024-2026, Infineon Technologies AG, or an affiliate of Infineon
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

from cbor import cbor

from ...execute.image_signing.image import Image

logger = logging.getLogger(__name__)


class DLMPackage:
    """Extracts configuration data from the DLM packet"""

    def __init__(self, dlm):
        self.dlm = dlm
        self.image = Image(self.dlm)
        self.image_app = Image(self.image.body)
        self.in_params = None

    def load_in_params(self):
        """Creates dictionary from the CBOR in_params"""
        data_len = int.from_bytes(self.image_app.trailer[:4], 'little')
        if data_len == len(self.image_app.trailer[4:]):
            self.in_params = cbor.loads(self.image_app.trailer[4:])
