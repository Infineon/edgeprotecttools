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
import hashlib
import os.path
import re
import struct
from typing import Union

from ....core.key_handlers import load_key, load_public_key
from ...common.policy_parser_primitives import PolicyParserPrimitives
from ...common.mxs40sv2.asset_enums import LifecycleStage, ApPermission
from ..asset_enums import (
    ControlWord, SecBool, BootCfgId, BootAuthImages,
    BootAuthSignature, MMIORestrictions, DebugPins, BootOdClk, IakCfg,
    DfuInterface, BootHashLocking
)
from ....core.key_handlers.ec_handler import ECHandler


class PolicyParserOemProvisioning(PolicyParserPrimitives):
    """Provides functionality for searching data in the policy file"""

    def target_lcs(self, ret_value=False) -> Union[LifecycleStage, int]:
        """Gets a value of the device_policy.target_lcs property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(LifecycleStage, ret_value, 'device_policy',
                               'target_lcs', 'value')

    def control_word(self) -> int:
        """Gets a control word that is a combination of
        program_sflash_assets, program_iak, and program_hash properties
        """
        value = 0
        if self.program_sflash_assets():
            value |= ControlWord.PROG_SFLASH_ASSETS
        if self.program_hash():
            value |= ControlWord.PROG_HASH_EN
        if self.rev_ifx_rot_key_0():
            value |= ControlWord.REV_IFX_ROT_KEY_0
        if self.rev_ifx_rma_master_key_0():
            value |= ControlWord.REV_IFX_RMA_MASTER_KEY_0
        if self.rev_oem_rot_key_0():
            value |= ControlWord.REV_OEM_ROT_KEY_0
        return value

    def program_sflash_assets(self) -> bool:
        """Gets a value of the device_policy.program_sflash_assets property"""
        value = self.field('device_policy', 'program_sflash_assets', 'value')
        return value is True

    def program_hash(self) -> bool:
        """Gets a value of the device_policy.program_hash property"""
        value = self.field('device_policy', 'program_hash', 'value')
        return value is True

    def rev_ifx_rot_key_0(self) -> bool:
        """Gets a value of the
        device_policy.reprovisioning.rev_ifx_rot_key_0 property"""
        value = self.field('device_policy', 'reprovisioning',
                           'revoke_ifx_rot_key_0', 'value')
        return value is True

    def rev_ifx_rma_master_key_0(self) -> bool:
        """Gets a value of the
        device_policy.reprovisioning.rev_ifx_rma_master_key_0 property"""
        value = self.field('device_policy', 'reprovisioning',
                           'revoke_ifx_rma_master_key_0', 'value')
        return value is True

    def rev_oem_rot_key_0(self) -> bool:
        """Gets a value of the
        device_policy.reprovisioning.rev_oem_rot_key_0 property"""
        value = self.field('device_policy', 'reprovisioning',
                           'revoke_oem_rot_key_0', 'value')
        return value is True
    
    def access_restrict(self) -> int:
        """Gets a value of the device_policy.access_restrict property"""
        fmt = {
            'size': 4,
            'data': [
                {
                    'name': 'CM33_0_ENABLE',
                    'shift': 0,
                    'mask': 0x01,
                    'value': int(
                        self.debug_ap_cm33() == ApPermission['Enable'])
                },
                {
                    'name': 'SYS_ENABLE',
                    'shift': 2,
                    'mask': 0x01,
                    'value': int(
                        self.debug_ap_system() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_DBG_ENABLE',
                    'shift': 4,
                    'mask': 0x01,
                    'value': int(
                        self.debug_cm33_dbg() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_NID_ENABLE',
                    'shift': 5,
                    'mask': 0x01,
                    'value': int(
                        self.debug_cm33_nid() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_SPID_ENABLE',
                    'shift': 6,
                    'mask': 0x01,
                    'value': int(
                        self.debug_cm33_spid() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_SPNID_ENABLE',
                    'shift': 7,
                    'mask': 0x01,
                    'value': int(
                        self.debug_cm33_spnid() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_SECURE_ENABLE',
                    'shift': 12,
                    'mask': 0x01,
                    'value': int(
                        self.debug_cm33_secure() == ApPermission['Enable'])
                },
                {
                    'name': 'SYS_SECURE_ENABLE',
                    'shift': 14,
                    'mask': 0x01,
                    'value': int(
                        self.debug_sys_secure() == ApPermission['Enable'])
                },
                {
                    'name': 'CM33_0_DISABLE',
                    'shift': 16,
                    'mask': 0x01,
                    'value': int(self.debug_ap_cm33() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'SYS_DISABLE',
                    'shift': 18,
                    'mask': 0x01,
                    'value': int(self.debug_ap_system() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'CM33_0_DBG_DISABLE',
                    'shift': 20,
                    'mask': 0x01,
                    'value': int(self.debug_cm33_dbg() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'CM33_0_NID_DISABLE',
                    'shift': 21,
                    'mask': 0x01,
                    'value': int(self.debug_cm33_nid() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'CM33_0_SPID_DISABLE',
                    'shift': 22,
                    'mask': 0x01,
                    'value': int(self.debug_cm33_spid() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'CM33_0_SPNID_DISABLE',
                    'shift': 23,
                    'mask': 0x01,
                    'value': int(self.debug_cm33_spnid() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'CM33_0_SECURE_DISABLE',
                    'shift': 28,
                    'mask': 0x01,
                    'value': int(self.debug_cm33_secure() == ApPermission[
                        'Permanently Disable'])
                },
                {
                    'name': 'SYS_SECURE_DISABLE',
                    'shift': 30,
                    'mask': 0x01,
                    'value': int(self.debug_sys_secure() == ApPermission[
                        'Permanently Disable'])
                },
            ],
        }

        value = 0
        for item in fmt['data']:
            value |= (item['value'] & item['mask']) << item['shift']
        return value

    def access_restrict_2(self) -> int:
        """Gets a value of the device_policy.access_restrict_2 property"""
        fmt = {
            'size': 4,
            'data': [
                {
                    'name': 'SYS_AP_MMIO',
                    'shift': 0,
                    'mask': 0x03,
                    'value': self.debug_mmio_restrictions(ret_value=True)
                },
                {
                    'name': 'DEBUG_PINS',
                    'shift': 4,
                    'mask': 0x0F,
                    'value': self.debug_debug_pins(ret_value=True)
                },
                {
                    'name': 'TAG',
                    'shift': 24,
                    'mask': 0xFF,
                    'value': 0xA3
                },
            ],
        }

        value = 0
        for item in fmt['data']:
            value |= (item['value'] & item['mask']) << item['shift']
        return value
    
    def reprovisioning_nonce(self, nullable=False) -> Union[bytes, None]:
        """Gets a value of the device_policy.reprovisioning.nonce property"""
        field = self.field(
            'device_policy', 'reprovisioning', 'nonce', 'value'
        )

        if not field and nullable:
            return None

        if field:
            nonce = self.bin_file_or_hex_string_field(
                'device_policy', 'reprovisioning', 'nonce', 'value'
            )[:16]
            nonce += b'\x00' * (16 - len(nonce))
        else:
            nonce = b'\x00' * 16
        return nonce

    def ifx_revocation_signature(self, nullable=False) -> Union[bytes, None]:
        """Gets a value of the
        device_policy.reprovisioning.ifx_revocation_signature property"""
        field = self.field(
            'device_policy', 'reprovisioning',
            'ifx_revocation_signature', 'value'
        )

        if not field and nullable:
            return None

        if field:
            signature = self.bin_file_or_hex_string_field(
                'device_policy', 'reprovisioning',
                'ifx_revocation_signature', 'value'
            )[:136]
            signature += b'\x00' * (136 - len(signature))
        else:
            signature = b'\x00' * 136
        return signature

    def failed_signature_counter(self, names=None) -> bytes:
        """Gets a value of the
        device_policy.reprovisioning.failed_signature_counter property"""
        values = [
            self.int_field(
                'device_policy', 'failed_signature_counter', name, 'value'
            ) for name in names
        ]

        return struct.pack(
            '<' + 'H' * len(values),
            *values
        )

    def nv_counter(self, slot) -> int:
        """Gets a value of the device_policy.nv_counter_slot property"""
        nv_counter = self.int_field(
            'device_policy', f'nv_counter_{slot}', 'value'
        )
        return nv_counter

    def iak_cfg(self, ret_value=False) -> Union[IakCfg, int]:
        """Gets a value of the device_policy.iak_cfg property"""
        return self.enum_field(
            IakCfg, ret_value, 'device_policy', 'iak', 'cfg', 'value'
        )

    def prov_oem_complete(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the device_policy.prov_oem_complete property"""
        complete = self.field('device_policy', 'prov_oem_complete', 'value')
        if ret_value:
            return SecBool.SEC_TRUE if complete else SecBool.SEC_FALSE
        return complete

    def debug_ap_cm33(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.ap_cm33 property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'ap_cm33', 'value')

    def debug_listen_window(self, ret_value=False) -> int:
        """Gets a value of the device_policy.debug.cpu.listen_window property
        @return: The listen window value in milliseconds (0-127)
        """
        value = self.int_field(
            'device_policy', 'debug', 'cpu', 'listen_window', 'value'
        )
        if ret_value:
            return SecBool.SEC_FALSE if value == 0 else (
                (SecBool.SEC_TRUE & 0xFFFFFF00)| (value & 0x7F)
            )
        return value

    def debug_cm33_dbg(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.cm33_dbg property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'cm33_dbg', 'value')

    def debug_cm33_nid(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.cm33_nid property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'cm33_nid', 'value')

    def debug_cm33_spid(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.cm33_spid property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'cm33_spid', 'value')

    def debug_cm33_spnid(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.cm33_spnid property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'cm33_spnid', 'value')

    def debug_cm33_secure(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.cm33_secure property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'cpu', 'cm33_secure', 'value')

    def debug_ap_system(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.system.ap property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'system', 'ap', 'value')

    def debug_sys_secure(self, ret_value=False) -> Union[ApPermission, int]:
        """Gets a value of the device_policy.debug.cpu.secure property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(ApPermission, ret_value, 'device_policy',
                               'debug', 'system', 'secure', 'value')

    def debug_mmio_restrictions(self, ret_value=False) -> Union[
            MMIORestrictions, int]:
        """Gets a value of the device_policy.debug.system.mmio_restrictions
        property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(MMIORestrictions, ret_value, 'device_policy',
                               'debug', 'system', 'mmio_restrictions', 'value')

    def debug_debug_pins(self, ret_value=False) -> Union[
            MMIORestrictions, int]:
        """Gets a value of the device_policy.debug.system.debug_pins
        property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(DebugPins, ret_value, 'device_policy',
                               'debug', 'system', 'debug_pins', 'value')

    def boot_cfg_id(self, ret_value=False) -> Union[BootCfgId, int]:
        """Gets a value of the device_policy.boot.boot_cfg_id property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(BootCfgId, ret_value, 'device_policy', 'boot',
                               'boot_cfg_id', 'value')

    def boot_bank_ctr_offset(self) -> int:
        """Gets a value of the device_policy.boot.boot_bank_ctr_offset
        property
        """
        if self.boot_cfg_id() not in (BootCfgId.DUAL_BANK_SIMPLE_APP,
                                      BootCfgId.DUAL_BANK_SECURE_APP):
            return SecBool.SEC_TRUE

        offset = self.int_field(
            'device_policy', 'boot', 'boot_bank_ctr_offset', 'value'
        )
        return offset

    def boot_hash_locking(self, ret_value=False) -> Union[BootHashLocking, int]:
        """Gets a value of the device_policy.boot.boot_hash_locking property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(BootHashLocking, ret_value, 'device_policy',
                               'boot', 'boot_hash_locking', 'value')

    def boot_auth_images(self, ret_value=False) -> Union[BootAuthImages, int]:
        """Gets a value of the device_policy.boot.boot_auth_images property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(
            BootAuthImages, ret_value, 'device_policy', 'boot',
            'boot_auth_images', 'value'
        )

    def boot_auth_signature(self, ret_value=False) -> Union[
        BootAuthSignature, int
    ]:
        """Gets a value of the device_policy.boot.boot_auth_signature property
        @param ret_value: Returns value if True, otherwise enum object
        @return: The enum object or its value
        """
        return self.enum_field(
            BootAuthSignature, ret_value, 'device_policy', 'boot',
            'boot_auth_signature', 'value'
        )

    def boot_auth(self) -> int:
        """Gets a combination of the device_policy.boot.boot_auth_signature and
        device_policy.boot.boot_auth_signature properties
        """
        return (self.boot_auth_images(ret_value=True) +
                self.boot_auth_signature(ret_value=True))

    def boot_app_layout(self,
                        ret_value=False, ret_array=False) -> Union[list, bytes]:
        """Gets a value of the device_policy.boot.app_layout property"""
        app_layout = self.field('device_policy', 'boot', 'boot_app_layout',
                                'value')
        if ret_array:
            return [[int(str(item['address']), 0), int(str(item['size']), 0)]
                    for item in app_layout]

        if ret_value:
            val = b''
            for item in app_layout:
                val += int(str(item['address']), 0).to_bytes(4,
                                                             byteorder='little')
                val += int(str(item['size']), 0).to_bytes(4, byteorder='little')
            return val
        return app_layout

    def boot_od_clk(self, ret_value=False) -> Union[BootOdClk, int]:
        """Gets a value of the device_policy.boot_od_clk property"""
        return self.enum_field(BootOdClk, ret_value, 'device_policy', 'boot',
                               'boot_od_clk', 'value')

    def pc2_ctl_valid(self):
        """Gets a value of the device_policy.pc2_ctl_valid property"""
        return self.field('device_policy', 'pc2_ctl_valid', 'value')

    def pc3_ctl_valid(self):
        """Gets a value of the device_policy.pc3_ctl_valid property"""
        return self.field('device_policy', 'pc3_ctl_valid', 'value')

    def pc_ctl_valid(self):
        """Gets a value that is a combination of the
        pc2_ctl_valid, and pc3_ctl_valid properties
        """
        pc2 = 1 if self.pc2_ctl_valid() is True else 0
        pc3 = 1 if self.pc3_ctl_valid() is True else 0
        return (pc2 << 2) | (pc3 << 3)

    def pc2_handler(self) -> int:
        """Gets a value of the device_policy.pc2_handler property"""
        addr = self.int_field('device_policy', 'pc2_handler', 'value')
        return addr

    def pc3_handler(self) -> int:
        """Gets a value of the device_policy.pc3_handler property"""
        addr = self.int_field('device_policy', 'pc3_handler', 'value')
        return addr

    def oem_device_cert_addr(self) -> int:
        """Gets a value of the device_policy.oem_device_cert_addr property"""
        addr = self.int_field('device_policy', 'oem_device_cert_addr', 'value')
        return addr

    def oem_device_cert_blocks(self) -> int:
        """Gets a value of the device_policy.oem_device_cert_blocks property"""
        size = self.int_field(
            'device_policy', 'oem_device_cert_blocks', 'value'
        )
        return size

    def dfu(self):
        dfu_enable = self.dfu_enable(ret_value=True)
        dfu_if = self.dfu_if(ret_value=True)
        dfu_pins_ctl = self.dfu_pins_ctl()
        dfu_en_pin = self.dfu_en_pin(ret_value=True)
        dfu_config = self.dfu_config()
        return struct.pack(
            '<IBBHI',
            dfu_enable,
            dfu_if,
            dfu_pins_ctl,
            dfu_en_pin,
            dfu_config
        )

    def dfu_enable(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the device_policy.dfu.dfu_enable property"""
        enable = self.field('device_policy', 'dfu', 'dfu_enable', 'value')
        if ret_value:
            return SecBool.SEC_TRUE.value if enable else SecBool.SEC_FALSE.value
        return enable is True

    def dfu_if(self, ret_value=False) -> Union[DfuInterface, int]:
        """Gets a value of the device_policy.dfu.dfu_if property"""
        return self.enum_field(DfuInterface, ret_value, 'device_policy', 'dfu',
                               'dfu_if', 'value')

    def dfu_pins_ctl(self) -> int:
        """Gets a value of the device_policy.dfu.dfu_pins_ctl property.

        Packs the primary and alternate GPIO port numbers into a single
        byte using the layout: bits [3:0] hold primary_port (0-13) and
        bits [7:4] hold alternate_port (0-13, or 0 for single-port SCBs).
        """
        primary_port = self.int_field(
            'device_policy', 'dfu', 'dfu_pins_ctl', 'primary_port', 'value'
        )
        alternate_port = self.int_field(
            'device_policy', 'dfu', 'dfu_pins_ctl', 'alternate_port', 'value'
        )
        if primary_port not in range(0, 14):
            raise ValueError(
                "The 'dfu_pins_ctl.primary_port' property must be in the "
                "range 0-13."
            )
        if alternate_port not in range(0, 14):
            raise ValueError(
                "The 'dfu_pins_ctl.alternate_port' property must be in the "
                "range 0-13."
            )
        return (alternate_port << 4) | (primary_port << 0)

    def dfu_en_pin(self, ret_value=False) -> Union[str, int]:
        """Gets a value of the device_policy.dfu.dfu_en_pin property"""
        value = self.field('device_policy', 'dfu', 'dfu_en_pin', 'value')
        if ret_value:
            try:
                m = re.fullmatch(r'^P(\d+)_(\d+)$', value)

                port = int(m.group(1))
                assert port in range(0, 14)

                pin = int(m.group(2))
                assert pin in range(0, 8)

                value = port << 8 | pin
            except (AttributeError, ValueError, AssertionError) as e:
                raise ValueError(
                    "Failed to parse the 'dfu_en_pin' property. "
                    "The 'dfu_en_pin' property must be in the format "
                    "'Px_y', where x is the port number (0-13) and y is the "
                    "pin number (0-8)."
                ) from e
        return value

    def dfu_config(self) -> int:
        """Gets a value of the device_policy.dfu.dfu_config property.

        Packs the configuration of the active DFU interface into a 32-bit
        word using the following bit layout:

        [3:0]   scb             SCB instance number (0-5)
        [5:4]   spi_clk_mode    SPI SCLK mode 0-3 (SPI only)
        [10:8]  pin_d num       NSS pin number 0-7 (SPI only)
        [11]    pin_d alt_port  0 primary port, 1 alternate port
        [14:12] pin_c num       CLK pin number 0-7 (SPI only)
        [15]    pin_c alt_port  0 primary port, 1 alternate port
        [18:16] pin_b num       SCL / MISO / TX pin number 0-7
        [19]    pin_b alt_port  0 primary port, 1 alternate port
        [22:20] pin_a num       SDA / MOSI / RX pin number 0-7
        [23]    pin_a alt_port  0 primary port, 1 alternate port
        [30:24] address         I2C slave address, 7 bits (I2C only)

        The interface-specific signal names used in the policy are mapped
        to the hardware pin slots (pin_a..pin_d) as follows:

                    pin_a   pin_b   pin_c   pin_d
            UART    rx      tx      -       -
            I2C     sda     scl     -       -
            SPI     mosi    miso    clk     nss
        """
        pin_map = {
            'UART': {
                'pin_a': 'rx',
                'pin_b': 'tx'
            },
            'I2C': {
                'pin_a': 'sda',
                'pin_b': 'scl'
            },
            'SPI': {
                'pin_a': 'mosi',
                'pin_b': 'miso',
                'pin_c': 'clk',
                'pin_d': 'nss'
            },
        }

        pin_shift = {
            'pin_a': 20,
            'pin_b': 16,
            'pin_c': 12,
            'pin_d': 8
        }
        interface = self.dfu_if(ret_value=False).name

        value = self._dfu_config_scb(interface) << 0
        value |= self._dfu_config_spi_clk_mode(interface) << 4

        for slot, signal in pin_map[interface].items():
            value |= self._dfu_config_pin(interface, signal) << pin_shift[slot]

        value |= self._dfu_config_i2c_address(interface) << 24

        return value

    def _dfu_config_scb(self, interface) -> int:
        """Gets a value of the device_policy.dfu.dfu_config.scb property"""
        scb = self.int_field(
            'device_policy', 'dfu', 'dfu_config', interface, 'scb', 'value'
        )
        if scb not in range(0, 6):
            raise ValueError(
                "The 'dfu_config.scb' property must be in the range 0-5."
            )
        return scb

    def _dfu_config_i2c_address(self, interface) -> int:
        """Gets a value of the device_policy.dfu.dfu_config.address property"""
        if interface != 'I2C':
            return 0
        address = self.int_field(
            'device_policy', 'dfu', 'dfu_config', interface,
            'address', 'value'
        )
        if address not in range(0, 128):
            raise ValueError(
                "The 'dfu_config.address' property must be in the "
                "range 0-127."
            )
        return address

    def _dfu_config_spi_clk_mode(self, interface) -> int:
        """Gets a value of the device_policy.dfu.dfu_config.spi_clk_mode
        property"""
        if interface != 'SPI':
            return 0
        spi_clk_mode = self.int_field(
            'device_policy', 'dfu', 'dfu_config', interface,
            'spi_clk_mode', 'value'
        )
        if spi_clk_mode not in range(0, 4):
            raise ValueError(
                "The 'dfu_config.spi_clk_mode' property must be in the "
                "range 0-3."
            )
        return spi_clk_mode

    def _dfu_config_pin(self, interface, pin) -> int:
        """Packs a DFU pin into a nibble: bits [2:0] hold the pin number
        (0-7) and bit [3] holds the port selector (0 primary port,
        1 alternate port).
        @param interface: The active DFU interface name
        @param pin: The interface-specific signal name (e.g. 'rx', 'sda',
            'mosi')
        """
        num = self.int_field(
            'device_policy', 'dfu', 'dfu_config', interface, pin, 'num'
        )
        alternate_port = self.field(
            'device_policy', 'dfu', 'dfu_config', interface, pin,
            'alternate_port'
        )
        if num not in range(0, 8):
            raise ValueError(
                f"The 'dfu_config.{pin}.num' property must be in the "
                "range 0-7."
            )
        if not isinstance(alternate_port, bool):
            raise ValueError(
                f"The 'dfu_config.{pin}.alternate_port' property must be a "
                "boolean."
            )
        return (int(alternate_port) << 3) | num

    def gpio_cfg(self):
        """Gets a value of the device_policy.gpio.Px.cfg properties"""
        value = [self.int_field(
            'device_policy', 'gpio', f'P{port}', 'cfg'
        ) for port in range(0, 14)]
        return struct.pack('<' + 'B'*14, *value)

    def gpio_out(self):
        """Gets a value of the device_policy.gpio.Px.out properties"""
        value = [self.int_field(
            'device_policy', 'gpio', f'P{port}', 'out'
        ) for port in range(0, 14)]
        return struct.pack('<' + 'I'*14, *value)

    def boundary_scan(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the device_policy.boundary_scan property"""
        enable = self.field('device_policy', 'boundary_scan', 'value')
        if ret_value:
            return SecBool.SEC_TRUE if enable else SecBool.SEC_FALSE
        return enable is True

    def disable_ramapp(self, ret_value=False) -> Union[bool, int]:
        """Gets a value of the device_policy.disable_ramapp property"""
        enable = self.field('device_policy', 'disable_ramapp', 'value')
        if enable is None:
            return None
        if ret_value:
            return SecBool.SEC_TRUE if enable else SecBool.SEC_FALSE
        return enable

    def mpc_struct_flash(self, ret_value=False) -> Union[list, bytes]:
        """Gets a value of the device_policy.mpc.mpc_struct_flash property"""
        mpc_struct = self.field('device_policy', 'mpc', 'mpc_struct_flash',
                                'value')
        if ret_value:
            return self._mpc_struct(mpc_struct)
        return mpc_struct

    def mpc_structs_bytes(self) -> bytes:
        """Gets a combined value of the device_policy.mpc.mpc_struct_ram
        and device_policy.mpc.mpc_struct_flash properties padded up to
        128 bytes
        """
        mpc_structs = self.mpc_struct_flash(ret_value=True)
        padding = bytes(80 - len(mpc_structs))
        return mpc_structs + padding

    def n_flash_mpc(self) -> int:
        """Gets number of Flash MPC structures"""
        mpc = self.mpc_struct_flash()
        return len(mpc) if mpc else 0

    def mpc_policy_t(self) -> bytes:
        """Gets MPC policy structure bytes"""
        return (bytes(1) +
                self.n_flash_mpc().to_bytes(length=1, byteorder='little') +
                bytes(2) + self.mpc_structs_bytes())

    @staticmethod
    def _mpc_struct(mpc_struct) -> bytes:
        """Gets MPC structure bytes"""
        val = b''
        for item in mpc_struct:
            offset_kb = int(item['offset'].upper().replace('KB', ''), 0)
            size_kb = int(item['size'].upper().replace('KB', ''), 0)
            val += int(offset_kb / 2).to_bytes(2, byteorder='little')
            val += int(size_kb / 2).to_bytes(2, byteorder='little')
            attr_value = 0
            cnt = 0
            for pc in item['attr']['value'].values():
                pc = pc.replace(' ', '')
                if pc[2] == 'N':
                    attr_value |= 1 << cnt
                cnt += 1
                if pc[1] == 'R':
                    attr_value |= 1 << cnt
                cnt += 1
                if pc[0] == 'W':
                    attr_value |= 1 << cnt
                cnt += 2  # skip the fourth bit
            val += attr_value.to_bytes(4, byteorder='little')
        return val

    def oem_debug_public_key(self, ret_value=True):
        """Gets a value of oem_debug_public_key property
        @return: debug key as raw bytes
        """
        key_value = self.field(
            'pre_build', 'keys', 'oem_debug_public_key', 'value'
        )

        if not ret_value:
            return key_value

        if not key_value:
            return bytes(136)

        if os.path.isabs(key_value):
            key_path = key_value
        else:
            key_path = os.path.join(self.policy_dir, key_value)

        if os.path.isfile(key_path):
            key_value = ECHandler.raw_format(load_public_key(key_path))
        else:
            try:
                key_value = bytes.fromhex(key_value)
                assert len(key_value) in (65, 97, 133)
            except ValueError as e:
                raise ValueError("Neither an existing file nor a valid "
                                 "hex string was found in the policy "
                                 "'oem_debug_public_key' property") from e
            except AssertionError as e:
                raise ValueError("The 'oem_debug_public_key' property must be "
                                 "a hex string of 65, 97, or 133 bytes") from e

        return key_value + b'\x00' * (136 - len(key_value))

    def oem_key(self, name, ret_hash=False, ret_value=False, nullable=False):
        """Gets a value of the pre_build.keys.name property
        @param name: The key name
        @param ret_hash: Returns the key hash if True, otherwise the key
        @param ret_value: Returns the data value if True, otherwise the key path
        @param nullable: If True, returns None if the key is not specified
        @return: The key path or key hash
        """
        path = self.field('pre_build', 'keys', name, 'value')
        value = self._oem_rot_public_key(
            path, ret_hash=ret_hash, ret_value=ret_value, nullable=nullable
        )
        return value

    def _oem_rot_public_key(self, path, ret_hash=False, ret_value=False,
                            nullable=False):
        """Gets either a key path or a key hash.
        For a simple app, the OEM keys are not used, and
        may not exist or may not be specified. In this case,
        a key hash is 136 null bytes.
        """
        if path:
            if not os.path.isabs(path):
                path = os.path.abspath(os.path.join(self.policy_dir, path))
        elif nullable:
            return None

        if ret_value:
            if path and os.path.isfile(path):
                if ret_hash:
                    data = self._key_hash(path)
                else:
                    data = self._raw_key_field(path)
                return data + b'\x00' * (136 - len(data))

            if self.boot_cfg_id() == BootCfgId.SIMPLE_APP:
                return b'\x00' * 136

        return path

    def enc_key(self, name, ret_value=False):
        """Gets a value of the pre_build.keys.name property
        @return: The key value
        """
        if ret_value:
            value = self.bin_file_field('pre_build', 'keys', name, 'value')
        else:
            value = self.field('pre_build', 'keys', name, 'value')
        return value

    @staticmethod
    def _raw_key_field(key_path):
        key = load_key(key_path)
        raw = ECHandler.raw_format(key)
        return raw

    def _key_hash(self, key_path):
        """Gets hash or the key"""
        raw = self._raw_key_field(key_path)
        sha = hashlib.sha256()
        sha.update(raw[1:])
        return sha.digest()

    def raw_data_pc012(self):
        """Gets a value of the raw_data_pc012 property"""
        try:
            data = self.bin_file_field('raw_data_pc012', 'value')
            return data + b'\x00' * (84 - len(data))
        except (FileNotFoundError, TypeError):
            return b'\x00' * 84
