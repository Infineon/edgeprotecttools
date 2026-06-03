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
import json
import logging
import os

from cbor import cbor
from intelhex import IntelHex, HexRecordError

from .....execute.image_signing import MultiImage, SplitTool
from .....targets.common.mxs22.multi_image.image_meta_item import ImageMetaItem
from .....targets.common.mxs22.key_validator_mxs22 import KeyValidatorMXS22

logger = logging.getLogger(__name__)


class MultiImageMXS22(MultiImage):
    """
    Creates a multiple images COSE packet
    """

    def __init__(self, input_path, output, **kwargs):
        super().__init__(input_path, output, **kwargs)
        self._template = kwargs.get('template')

    @property
    def template(self):
        """Additional image data template path"""
        return os.path.abspath(self._template) if self._template else None

    def load_image(self):
        """Loads input file and splits it into segments"""
        try:
            try:
                segments = SplitTool.split(self.input_path)
            except UnicodeDecodeError:
                ih = IntelHex()
                ih.loadbin(self.input_path)
                seg_start, seg_end = ih.segments()[0]
                segments = [ih[seg_start:seg_end]]
        except (HexRecordError, IndexError):
            raise ValueError(f"Invalid file format '{self.input_path}'")
        return segments

    def collect_data(self):
        """Collects data from input file"""
        segments = self.load_image()

        if self.template:
            data = self.image_template(segments)
        else:
            data = self.image_no_template(segments)

        return data

    def image_template(self, segments):
        """Creates image package according to the template data
        @param segments: List of IntelHex objects containing hex segments
        """
        with open(self.template, 'r', encoding='utf-8') as f:
            meta_data = json.load(f)
        meta = meta_data.get('meta')
        addresses = self.meta_addresses(meta)
        if len(segments) < len(addresses):
            logger.debug('A .hex image without gap is used')
            segments = self.process_no_gap_img(segments, addresses)
        if len(segments) != len(addresses):
            raise ValueError('The number of images does not correspond '
                             'to the meta address fields')
        image_info = []
        images = []
        for item in meta:
            addr = int(str(item.get('addr')), 0)
            segment = self.select_segment_bytes(segments, addr)
            meta_item = ImageMetaItem(item, segment, self.template)
            if meta_item.enckey:
                meta_item.encrypt_image()
            image_info.append(meta_item.to_dict())
            images.append(meta_item.image)
            for msg in meta_item.logging_info():
                logger.info(msg)
            if meta_item.edc_addr:
                image_info.append({'addr': meta_item.edc_addr})
                segment = self.select_segment_bytes(segments, meta_item.edc_addr)
                images.append(segment)
        packet = [cbor.dumps(image_info)]
        packet.extend(images)
        return packet

    @staticmethod
    def process_no_gap_img(ihex_img, addr_list):
        """Creates a list of IntelHex objects based on a list of
        template addresses
        """
        addr_list.sort()
        segments = []
        for itm in ihex_img:
            hex_max_addr = itm.maxaddr()
            hex_addresses = itm.addresses()
            for i in addr_list:
                if i in hex_addresses:
                    if i == addr_list[-1] or addr_list[addr_list.index(i) + 1] \
                            > hex_max_addr:
                        img = itm.gets(i, hex_max_addr - i + 1)
                    else:
                        img = itm.gets(i, addr_list[addr_list.index(i) + 1] - i)
                    ih = IntelHex()
                    ih.frombytes(bytearray(img), i)
                    segments.append(ih)

        return segments

    @staticmethod
    def image_no_template(segments):
        """Creates image package without template
        @param segments: List of IntelHex objects containing hex segments
        """
        packet = []
        for seg in segments:
            packet.append({
                'addr': seg.minaddr(),
                'img': seg.tobinarray().tobytes()
            })
        return packet

    @staticmethod
    def process_field(meta_item, field):
        """Converts field name and value to the CBOR packet format"""
        data = meta_item.get(field)
        if data is not None:
            if field == 'nv_counter':
                field = 'cnt'
            elif field == 'edc_addr':
                field = 'addr'
            return {field: int(str(data), 0)}
        raise ValueError(f"The '{field}' field is empty")

    @staticmethod
    def meta_addresses(metadata):
        """Creates address list based on template"""
        addresses = []
        for item in metadata:
            for field in item:
                if field in ('addr', 'edc_addr'):
                    addr = item.get(field)
                    if addr:
                        addresses.append(int(str(addr), 0))
        return addresses

    @staticmethod
    def select_segment_bytes(segments, addr):
        """Selects image from list if IntelHex objects by the address
        @param segments: List of IntelHex objects containing hex segments
        @param addr: Segment address to select
        @return Segment bytes
        """
        for seg in segments:
            if seg.minaddr() == addr:
                return seg.tobinarray().tobytes()
        raise ValueError(f"No image with min address '{hex(addr)}' found")

    def validate_args(self):
        """Validates arguments"""
        if self.key:
            KeyValidatorMXS22().validate_private_key(self.key)
