# Copyright 2025 Giacomo Pope
# (c) 2026, Infineon Technologies AG, or an affiliate of Infineon
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
from .dilithium import Dilithium

DEFAULT_PARAMETERS = {
    "dilithium2": {
        "d": 13,
        "k": 4,
        "l": 4,
        "eta": 2,
        "tau": 39,
        "omega": 80,
        "gamma_1": 131072,  # 2^17
        "gamma_2": 95232,  # (q-1)/88
    },
    "dilithium3": {
        "d": 13,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "omega": 55,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/32
    },
    "dilithium5": {
        "d": 13,
        "k": 8,
        "l": 7,
        "eta": 2,
        "tau": 60,
        "omega": 75,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/32
    },
}

Dilithium2 = Dilithium(DEFAULT_PARAMETERS["dilithium2"])
Dilithium3 = Dilithium(DEFAULT_PARAMETERS["dilithium3"])
Dilithium5 = Dilithium(DEFAULT_PARAMETERS["dilithium5"])
