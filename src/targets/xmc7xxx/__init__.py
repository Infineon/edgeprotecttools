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
from .target_builder import XMC7xxxBuilder

target_map = {
    'xmc7100': {
        'class': XMC7xxxBuilder,
        'family': 'XMC7000 Family',
        'display_name': 'XMC7xxx',
        'type': 'family',
        'platform': 'traveo_t2g'
    },
    'xmc7200': {
        'class': XMC7xxxBuilder,
        'family': 'XMC7000 Family',
        'display_name': 'XMC7xxx',
        'type': 'family',
        'platform': 'traveo_t2g'
    },
    'xmc5000': {
        'class': XMC7xxxBuilder,
        'family': 'XMC5000 Family',
        'display_name': 'XMC5xxx',
        'type': 'family',
        'platform': 'traveo_t2g'
    }
}
