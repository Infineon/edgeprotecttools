"""
Copyright 2026 Cypress Semiconductor Corporation (an Infineon company)
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

from ...core.key_handlers.ml_dsa_handler import MLDSAHandler, MLDSAPrivateKey, MLDSAPublicKey
from ...core.dilithium.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


logger = logging.getLogger(__name__)


def generate_key(key_type, seed=None) -> (MLDSAPrivateKey, MLDSAPublicKey):
    """Creates keypair using ML-DSA algorithm
    @return: Private key, public key
    """

    if key_type == 'ML-DSA-44':
        ml_dsa = ML_DSA_44
    elif key_type == 'ML-DSA-65':
        ml_dsa = ML_DSA_65
    elif key_type == 'ML-DSA-87':
        ml_dsa = ML_DSA_87
    else:
        raise ValueError(f'Invalid key type: {key_type}')

    pk, sk = ml_dsa.keygen(zeta=seed)

    private_key = MLDSAHandler.populate_private_key(sk)
    public_key = MLDSAHandler.populate_public_key(pk)

    return private_key, public_key

def save_key(key, output, encoding):
    dir_name = os.path.dirname(output)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    data = key.serialize(encoding)

    with open(output, 'wb') as fp:
        fp.write(data)
