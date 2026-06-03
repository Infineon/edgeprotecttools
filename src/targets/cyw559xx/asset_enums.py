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
from enum import Enum


AssetType = Enum(
    value='The type of the provided asset',
    names=[
        ('ASSET_NO_KEY', 0x00),
        ('ASSET_PLAIN_KEY', 0x01)
    ]
)

HbkType = Enum(
    value='Type of the HBK',
    names=[
        ('DMPU_HBK_TYPE_HBK1', 0x01)
    ]
)
