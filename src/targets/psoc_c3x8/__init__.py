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
from .target_builder import PsocC3x8Builder

target_map = {
    'psoc_c3p8': {
        'default': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 P8',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
        'a1': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 P8',
            'type': 'family',
            'platform': 'mxs40sv2'
        }
    },
    'psoc_c3x7': {
        'default': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 x7',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
        'a1': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 x7',
            'type': 'family',
            'platform': 'mxs40sv2'
        }
    },
    'psoc_c3x8': {
        'default': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 x8',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
        'a1': {
            'class': PsocC3x8Builder,
            'family': 'PSOC™ Control Family',
            'display_name': 'PSOC™ Control C3 x8',
            'type': 'family',
            'platform': 'mxs40sv2'
        }
    }
}
