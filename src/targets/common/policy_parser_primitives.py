# (c) 2022-2026, Infineon Technologies AG, or an affiliate of Infineon
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


class PolicyParserPrimitives:
    """Provides functionality for parsing data in the policy file"""

    def __init__(self, json, policy_dir):
        """Provides access to the main policy parser class members"""
        self.json = json
        self.policy_dir = policy_dir

    def field(self, *keys):
        """Gets a field from the policy as is"""
        value = self.json
        try:
            for key in keys:
                value = value[key]
        except KeyError:
            value = None
        return value

    def hex_field(self, *keys):
        """Gets a hex string field"""
        value = self.field(*keys)
        if value:
            value = int(value, 16)
        else:
            value = None
        return value

    def bytes_field(self, *keys):
        """Gets a byte string field"""
        value = self.field(*keys)
        if value:
            value = bytes.fromhex(value)
        else:
            value = None
        return value

    def bytes_list_field(self, *keys):
        """Gets a list of byte string field"""
        value = self.field(*keys)
        if value:
            byte_strings = []
            for item in value:
                byte_strings.append(bytes.fromhex(item))
        else:
            byte_strings = None
        return byte_strings

    def enum_field(self, enum_type, ret_value, *keys):
        """Gets enum field"""
        value = self.field(*keys)
        if value is not None:
            for item in enum_type:
                if item.name.lower() == value.lower():
                    value = item
                    break
            if not isinstance(value, enum_type):
                raise ValueError(f"Invalid enum value '{value}'")
            value = value.value if ret_value else value
        return value

    def bin_file_field(self, *keys):
        """Gets a field containing path to binary file"""
        value = self.field(*keys)
        if value:
            if not os.path.isabs(value):
                value = os.path.abspath(os.path.join(self.policy_dir, value))
            with open(value, 'rb') as fp:
                value = fp.read()
        else:
            value = None
        return value

    def bin_file_list_field(self, *keys):
        """Gets a field containing list of paths to binary files"""
        value = self.field(*keys)
        if value:
            contents = []
            for item in value:
                if not os.path.isabs(item):
                    item = os.path.abspath(os.path.join(self.policy_dir, item))
                with open(item, 'rb') as fp:
                    contents.append(fp.read())
        else:
            contents = None
        return contents

    def bin_file_or_hex_string_field(self, *keys):
        """Gets a field containing path to binary file or hex string"""
        try:
            data = self.bin_file_field(*keys)
        except (FileNotFoundError, OSError, ValueError):
            try:
                data = self.bytes_field(*keys)
            except ValueError as e:
                raise ValueError(
                    f"Error parsing data: '{'.'.join(keys)}'"
                ) from e
        return data

    def int_field(self, *keys):
        """Gets an integer field"""
        value = self.field(*keys)
        if value is not None:
            try:
                value = int(str(value), 0)
            except ValueError as e:
                raise ValueError(f"Invalid integer value '{value}'") from e
        return value if value else 0

    def abs_path(self, path):
        """ Converts policy related path to the absolute. """
        if not os.path.isabs(path):
            path = os.path.abspath(os.path.join(self.policy_dir, path))
        return path

    def mac_address(self, field_name, byte_len):
        """
        Parse a MAC/BD-address policy field.

        Reads a colon-separated hex string, validates its length, and returns
        the value packed as little-endian bytes (low DWORD first, high half
        second). For a 6-byte address the high half is zero-padded to 8 bytes.
        Returns None when the field is empty.
        """
        value = self.field(field_name, 'value')
        if not value:
            return None

        hex_str = value.replace(':', '')
        try:
            data = bytes.fromhex(hex_str)
        except ValueError as exc:
            raise ValueError(f"Invalid '{field_name}' format") from exc

        if len(data) != byte_len:
            raise ValueError(
                f"'{field_name}' must be {byte_len} bytes long")

        return int.from_bytes(data, 'big').to_bytes(8, 'little')
