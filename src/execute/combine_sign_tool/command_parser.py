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
import json
import logging
import re
from typing import List

from .command_group import CommandGroup

logger = logging.getLogger(__name__)


class CommandGroupParser:
    """Implements translation of JSON file properties into a
    groups of commands
    """
    def __init__(self, infile):
        self.infile = infile
        with open(infile, 'r', encoding='utf-8') as f:
            content = f.read()
        self.template = json.loads(self.remove_comments(content))

    def interpolate(self, interpolation_map: dict) -> None:
        """Interpolates template with specified key-value map"""
        self.template = self._interpolate(self.template, interpolation_map)

    def _interpolate(self, data, interpolation_map: dict):
        """Interpolates an object recursively"""
        if isinstance(data, dict):
            return {
                k: self._interpolate(v, interpolation_map)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self._interpolate(itm, interpolation_map) for itm in data]
        elif isinstance(data, str):
            split_data = re.split(r'(\{\{ *\w+ *\}\})', data.strip())
            result_data = []
            for part in split_data:
                m = re.fullmatch(r'(\{\{ *(?P<cmd>\w+) *\}\})', part)
                if m:
                    if m['cmd'] in interpolation_map:
                        result_data.append(interpolation_map[m['cmd']])
                    else:
                        raise KeyError(f'Unknown variable: {m["cmd"]}')
                else:
                    result_data.append(part)

            filtered = list(filter(lambda x: x != '', result_data))
            if len(filtered) == 1:
                return filtered[0]
            return ''.join(list(map(str, filtered)))
        else:
            return data

    def parse(self) -> List[CommandGroup]:
        """Gets a list of command groups based on JSON file properties
        @return: List of command groups
        """
        groups = [CommandGroup(**group) for group in self.template['content']]

        return groups

    @staticmethod
    def remove_comments(content: str):
        """Remove single and multi-line comments"""
        single_line_comment_pattern = re.compile(r"//.*$", re.MULTILINE)
        multi_line_comment_pattern = re.compile(r"/\*.*?\*/", re.DOTALL)

        content = re.sub(multi_line_comment_pattern, "", content)
        content = re.sub(single_line_comment_pattern, "", content)

        return content
