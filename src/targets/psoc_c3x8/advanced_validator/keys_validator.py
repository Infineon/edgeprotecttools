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
import os.path

from cryptography.hazmat.primitives.asymmetric import ec

from ..asset_enums import BootCfgId
from ....core.dependecy_validator import DependencyValidator
from ....core.key_handlers import load_key


class KeysValidator(DependencyValidator):
    """Keys policy validation"""

    _key_names = ()

    key_type_map = {
        'ES256': ec.SECP256R1,
        'ES384': ec.SECP384R1,
        'ES512': ec.SECP521R1,
    }

    def validate(self, **_kwargs):
        """Validates policy OEM keys section"""
        _pp = self.parser
        policy_version = _pp.policy_version()
        if policy_version == 1:
            self._validate_version_1()
        elif policy_version == 2:
            self._validate_version_2()

    def _validate_version_1(self):
        _pp = self.parser

        keys = [_pp.oem_key(name) for name in self._key_names]

        boot_cfg_id = _pp.boot_cfg_id()
        boot_auth_signature = _pp.boot_auth_signature()

        if boot_cfg_id == BootCfgId.SIMPLE_APP:
            self._validate_simple_app(self._key_names, keys)
        else:
            self._validate_not_simple_app(self._key_names, keys)
            if self.is_valid:
                self._validate_boot_auth_signature(
                    self._key_names, boot_auth_signature
                )

    def _validate_version_2(self):
        self._validate_oem_debug_key()

    def _validate_oem_debug_key(self):
        _pp = self.parser
        debug_key = _pp.oem_debug_public_key(ret_value=False)
        boot_auth = _pp.boot_auth_signature()

        if not debug_key:
            self.add_msg(
                "Skip 'oem_debug_public_key' validation", severity='info'
            )
            return

        key_path = debug_key \
            if os.path.isabs(debug_key) \
            else os.path.join(_pp.policy_dir, debug_key)

        if os.path.isfile(key_path):
            try:
                key = load_key(key_path)
            except Exception as e:  # pylint: disable=broad-except
                self.add_msg(f"Error 'oem_debug_public_key': {e}")
                return

            if not isinstance(key.curve,
                              self.key_type_map.get(boot_auth.name)):
                self.add_msg('"oem_debug_public_key" value must be aligned '
                             'with "boot_auth_signature" value')
                self.add_msg(f'Unexpected "oem_debug_public_key" curve: '
                             f'{key.curve.name}. '
                             f'Expected curve: '
                             f'{self.key_type_map.get(boot_auth.name).name}')
        else:
            try:
                key = bytes.fromhex(debug_key)
                assert len(key) in (65, 97, 133)
            except ValueError:
                self.add_msg("Neither an existing file nor a valid hex string "
                             "was found in the 'oem_debug_public_key' property")
                return
            except AssertionError:
                self.add_msg("Invalid length of the 'oem_debug_public_key' "
                             "property. Expected 65, 97, or 133 bytes")
                return

            bits_size = self.key_type_map.get(boot_auth.name)().key_size
            bytes_size = 2 * (bits_size // 8 + (bits_size % 8 > 0)) + 1

            if len(key) != bytes_size:
                self.add_msg("'oem_debug_public_key' value must be aligned "
                             "with 'boot_auth_signature' value")
                self.add_msg(f"Invalid length of the 'oem_debug_public_key' "
                             f"property. Expected {bytes_size} bytes for "
                             f"{boot_auth.name}")
                return

    def _validate_simple_app(self, names, keys):
        """Validates SIMPLE_APP case"""
        for name, key in zip(names, keys):
            if not key or not os.path.isfile(key):
                self.add_msg(
                    f"Skip '{name}' validation, not used with simple app",
                    severity='info'
                )

    def _validate_not_simple_app(self, names, keys):
        """Validates NOT SIMPLE_APP case"""
        for name, key in zip(names, keys):
            if key:
                if not os.path.isfile(key):
                    self.add_msg(f"'{name}': file not found '{key}'")
            else:
                self.add_msg(f"'{name}': key is not specified")

    def _validate_boot_auth_signature(self, names, key_type):
        """Validates keys of a specific type"""
        for name in names:
            self._validate_key_type(name, key_type)

    def _validate_key_type(self, name, key_type):
        key_path = self.parser.oem_key(name, ret_hash=False, ret_value=False)

        try:
            key = load_key(key_path)
        except Exception as e:  # pylint: disable=broad-except
            self.add_msg(f'Error {name}: {e}')
            return

        if not isinstance(key.curve, self.key_type_map.get(key_type.name)):
            self.add_msg(f'"{name}" value must be aligned '
                         f'with "boot_auth_signature" value')
            self.add_msg(f'Unexpected {name} curve: {key.curve.name}. '
                         f'Expected curve: '
                         f'{self.key_type_map.get(key_type.name).name}')
