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
import os
import logging

from ...core.xmss.params import XMSSParams
from ...core.xmss.xmss import XMSSPrivateKey

logger = logging.getLogger(__name__)


def generate_key(xmss_type_name):
    """Generates XMSS private and public key pair
    @return: A tuple containing the private key and public key
    """
    logger.info('Generating a key. This may take a while')
    try:
        params = XMSSParams(xmss_type_name)
    except ValueError as e:
        raise ValueError(f'Invalid XMSS type: {xmss_type_name}') from e
    try:
        xmss = XMSSPrivateKey(params)
    except ValueError as e:
        raise ValueError("XMSS instance not created: invalid parameters") from e
    private = xmss.serialize()
    public = xmss.public_key().serialize()
    return private, public

def save_key(data, output):
    """Saves the XMSS key to the file
    @param data: Key data in bytes  
    @param output: Key output path
    """
    if not isinstance(data, bytes):
        raise ValueError('Key data must be of type bytes')
    if not isinstance(output, str):
        raise ValueError('Incorrect file name or no paths')
    if not data:
        raise ValueError('Missing data for key generation')
    if not output:
        raise ValueError('Missing paths for key generation')

    try:
        if os.path.dirname(output):
            os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, 'wb') as w_data:
            w_data.write(data)
    except OSError as e:
        raise OSError(f"Unable to save key to '{output}': {e}") from e
