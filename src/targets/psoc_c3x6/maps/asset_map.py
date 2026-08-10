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
import json
import logging
import os
import time

from ...common.mxs40sv2.asset_enums import ApPermission, DeviceIntegrity
from ...common.mxs40sv2.enums import CoseSign1Packet

logger = logging.getLogger(__name__)

OEM_PROVISIONING_CBOR_MAP_ID = 0x11000000


class AssetMapPsocC3x6:
    """Asset map for PSOC C3 x6"""

    @staticmethod
    def get(p, **kwargs):
        """
        RAM applications asset map
        @params p: Policy parser
        @return: Initialized asset map

        Map fields description:
        size  - asset size in bytes
        shift - represents asset bits number that store a parameter. It says
                about the number of bits the value should be shifted to the left
        mask  - the number of bits used to store the asset item
        value - integer value of the bits.
        """
        policy_type = kwargs.get('policy_type')
        if not policy_type:
            policy_type = p.policy_type()

        if policy_type == 'oem_provisioning':
            map_id = OEM_PROVISIONING_CBOR_MAP_ID
            unprotected_map, protected_map, cbor_blobs = (
                AssetMapPsocC3x6.oem_provisioning_asset_map(p, **kwargs)
            )
            return map_id, unprotected_map, protected_map, cbor_blobs
        if policy_type == 'prot_fw_policy':
            return AssetMapPsocC3x6.prot_fw_assets(p)
        if policy_type == 'dfu':
            return AssetMapPsocC3x6.dfu_assets(p)
        if policy_type == 'device_integrity_exam':
            return AssetMapPsocC3x6.device_integrity_exam_assets(p, **kwargs)
        if policy_type == 'provisioned':
            return AssetMapPsocC3x6.device_identity(p)
        if policy_type == 'normal_provisioned':
            return AssetMapPsocC3x6.prov_icv(p)

        raise ValueError(f"Unknown policy type '{policy_type}'")

    @staticmethod
    def device_integrity_exam_assets(_, **kwargs):
        """Gets device integrity exam assets"""
        cert_path = kwargs.get('integrity_cert')

        cert_data = AssetMapPsocC3x6._integrity_cert_data(cert_path)

        assets = {
            'nonce': {
                'id': DeviceIntegrity.NONCE,
                'value': nonce()
            },
            'cert': {
                'id': CoseSign1Packet.COSE_PACKET_ID,
                'value': cert_data
            }
        }

        return assets

    @staticmethod
    def prot_fw_assets(p):
        """Gets bytes for Protected FW assets"""
        assets = {
            'access_restrict': {
                'size': 4,
                'data': [
                    {
                        'name': 'CM33_0_ENABLE',
                        'shift': 0,
                        'mask': 0x01,
                        'value': int(
                            p.debug_ap_cm33() == ApPermission['Enable'])
                    },
                    {
                        'name': 'SYS_ENABLE',
                        'shift': 2,
                        'mask': 0x01,
                        'value': int(
                            p.debug_ap_system() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_DBG_ENABLE',
                        'shift': 4,
                        'mask': 0x01,
                        'value': int(
                            p.debug_cm33_dbg() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_NID_ENABLE',
                        'shift': 5,
                        'mask': 0x01,
                        'value': int(
                            p.debug_cm33_nid() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_SPID_ENABLE',
                        'shift': 6,
                        'mask': 0x01,
                        'value': int(
                            p.debug_cm33_spid() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_SPNID_ENABLE',
                        'shift': 7,
                        'mask': 0x01,
                        'value': int(
                            p.debug_cm33_spnid() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_SECURE_ENABLE',
                        'shift': 12,
                        'mask': 0x01,
                        'value': int(
                            p.debug_cm33_secure() == ApPermission['Enable'])
                    },
                    {
                        'name': 'SYS_SECURE_ENABLE',
                        'shift': 14,
                        'mask': 0x01,
                        'value': int(
                            p.debug_sys_secure() == ApPermission['Enable'])
                    },
                    {
                        'name': 'CM33_0_DISABLE',
                        'shift': 16,
                        'mask': 0x01,
                        'value': int(p.debug_ap_cm33() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'SYS_DISABLE',
                        'shift': 18,
                        'mask': 0x01,
                        'value': int(p.debug_ap_system() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'CM33_0_DBG_DISABLE',
                        'shift': 20,
                        'mask': 0x01,
                        'value': int(p.debug_cm33_dbg() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'CM33_0_NID_DISABLE',
                        'shift': 21,
                        'mask': 0x01,
                        'value': int(p.debug_cm33_nid() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'CM33_0_SPID_DISABLE',
                        'shift': 22,
                        'mask': 0x01,
                        'value': int(p.debug_cm33_spid() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'CM33_0_SPNID_DISABLE',
                        'shift': 23,
                        'mask': 0x01,
                        'value': int(p.debug_cm33_spnid() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'CM33_0_SECURE_DISABLE',
                        'shift': 28,
                        'mask': 0x01,
                        'value': int(p.debug_cm33_secure() == ApPermission[
                            'Permanently Disable'])
                    },
                    {
                        'name': 'SYS_SECURE_DISABLE',
                        'shift': 30,
                        'mask': 0x01,
                        'value': int(p.debug_sys_secure() == ApPermission[
                            'Permanently Disable'])
                    },
                ],
            },
            'access_restrict_2': {
                'size': 4,
                'data': [
                    {
                        'name': 'SYS_AP_MMIO',
                        'shift': 0,
                        'mask': 0x03,
                        'value': p.debug_mmio_restrictions(ret_value=True)
                    },
                    {
                        'name': 'DEBUG_PINS',
                        'shift': 4,
                        'mask': 0x0F,
                        'value': p.debug_debug_pins(ret_value=True)
                    },
                    {
                        'name': 'TAG',
                        'shift': 24,
                        'mask': 0xFF,
                        'value': 0xA3
                    }
                ],
            },
            'boot_cfg_id': {
                'size': 4,
                'data': [
                    {
                        'name': 'BOOT_CFG_ID',
                        'shift': 0,
                        'value': p.boot_cfg_id(ret_value=True)
                    },
                ],
            },
            'boot_hash_locking': {
                'size': 4,
                'data': [
                    {
                        'name': 'BOOT_HASH_LOCKING',
                        'shift': 0,
                        'value': p.boot_hash_locking(ret_value=True)
                    },
                ],
            },
            'boot_auth': {
                'size': 4,
                'data': [
                    {
                        'name': 'BOOT_AUTH',
                        'shift': 0,
                        'value': p.boot_auth()
                    },
                ],
            },
            'boot_app_layout': {
                'size': 8,
                'data': [
                    {
                        'name': 'boot_app_layout',
                        'shift': 0,
                        'value': p.boot_app_layout(ret_value=True)
                    },
                ],
            },
            'pc_ctl_valid': {
                'size': 1,
                'data': [
                    {
                        'name': 'PC_CTL_VALID',
                        'shift': 0,
                        'value': p.pc_ctl_valid()
                    },
                ],
            },
            'padding_3': {
                'size': 3,
                'data': [
                    {
                        'name': 'padding',
                        'shift': 0,
                        'value': bytes(3)
                    },
                ],
            },
            'pc2_handler': {
                'size': 4,
                'data': [
                    {
                        'name': 'PC2_HANDLER',
                        'shift': 0,
                        'value': p.pc2_handler()
                    },
                ],
            },
            'prot_fw_addr': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_ADDR',
                        'shift': 0,
                        'value': p.prot_fw_addr()
                    },
                ],
            },
            'prot_fw_size': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_SIZE',
                        'shift': 0,
                        'value': p.prot_fw_size()
                    },
                ],
            },
            'prot_fw_rw_addr': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_RW_ADDR',
                        'shift': 0,
                        'value': p.prot_fw_rw_addr()
                    },
                ],
            },
            'prot_fw_rw_size': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_RW_SIZE',
                        'shift': 0,
                        'value': p.prot_fw_rw_size()
                    },
                ],
            },
            'prot_fw_ram_addr': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_RAM_ADDR',
                        'shift': 0,
                        'value': p.prot_fw_ram_addr()
                    },
                ],
            },
            'prot_fw_ram_size': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_RAM_SIZE',
                        'shift': 0,
                        'value': p.prot_fw_ram_size()
                    },
                ],
            },
            'prot_fw_complete': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_COMPLETE',
                        'shift': 0,
                        'value': p.prot_fw_complete(ret_value=True)
                    },
                ],
            },
            'failed_signature_counter': {
                'size': 2,
                'data': [
                    {
                        'name': 'FAILED_SIGNATURE_COUNTER',
                        'shift': 0,
                        'value': p.failed_signature_counter(names=(
                            'boot_app_layout_0',
                        ))
                    },
                ],
            },
            'nv_counter_a1': {
                'size': 1,
                'data': [
                    {
                        'name': 'NV_COUNTER_A1',
                        'shift': 0,
                        'value': p.nv_counter('a1')
                    },
                ],
            },
            'padding_1': {
                'size': 1,
                'data': [
                    {
                        'name': 'padding',
                        'shift': 0,
                        'value': bytes(1)
                    },
                ],
            },
            'prot_fw_rot_key_0': {
                'size': 136,
                'data': [
                    {
                        'name': 'PROT_FW_ROT_KEY_0',
                        'shift': 0,
                        'value': p.oem_key(
                            'prot_fw_rot_public_key_0', ret_value=True
                        )
                    },
                ],
            },
            'prot_fw_rot_key_1': {
                'size': 136,
                'data': [
                    {
                        'name': 'PROT_FW_ROT_KEY_1',
                        'shift': 0,
                        'value': p.oem_key(
                            'prot_fw_rot_public_key_1', ret_value=True
                        )
                    },
                ],
            },
            'prot_fw_debug_key': {
                'size': 136,
                'data': [
                    {
                        'name': 'PROT_FW_DEBUG_KEY',
                        'shift': 0,
                        'value': p.oem_key(
                            'prot_fw_debug_public_key', ret_value=True
                        )
                    },
                ],
            },
            'prot_fw_enc_key': {
                'size': 32,
                'data': [
                    {
                        'name': 'DFU_PROT_FW_ENC_KEY',
                        'shift': 0,
                        'value': p.enc_key('prot_fw_enc_key', ret_value=True)
                    },
                ],
            },
            'prot_fw_rot_key_rev': {
                'size': 4,
                'data': [
                    {
                        'name': 'PROT_FW_ROT_KEY_REV',
                        'shift': 0,
                        'value': p.rev_prot_fw_rot_key_0(ret_value=True)
                    },
                ],
            }
        }
        return assets

    @staticmethod
    def dfu_assets(p):
        """Gets bytes for Protected FW assets"""
        assets = {
            'iv': {
                'size': 16,
                'data': [
                    {
                        'name': 'iv',
                        'shift': 0,
                        'value': p.iv()
                    },
                ],
            }
        }
        return assets

    @staticmethod
    def device_identity(p):
        """Gets bytes for device_identity assets"""
        assets = {
            'nonce': {
                'size': 16,
                'data': [
                    {
                        'name': 'nonce',
                        'shift': 0,
                        'value': nonce(
                            p.dev_id_incremental_counter(ret_value=True),
                            p.dev_id_initial_value(ret_value=True)
                        )
                    },
                ],
            }
        }
        return assets

    @staticmethod
    def prov_icv(p):
        """Gets bytes for prov_icv assets"""
        assets = {
            'control_word': {
                'size': 4,
                'data': [
                    {
                        'name': 'CONTROL_WORD',
                        'shift': 0,
                        'value': p.prov_icv_control_word(ret_value=True)
                    },
                ],
            },
            'wounding': {
                'size': 4,
                'data': [
                    {
                        'name': 'CAN_WOUND',
                        'shift': 0,
                        'mask': 0x01,
                        'value': p.wound_can(ret_value=True)
                    },
                    {
                        'name': 'FLASH_WOUND',
                        'shift': 1,
                        'mask': 0x03,
                        'value': p.wound_flash(ret_value=True)
                    },
                    {
                        'name': 'SRAM_WOUND',
                        'shift': 3,
                        'mask': 0x03,
                        'value': p.wound_sram(ret_value=True)
                    },
                    {
                        'name': 'SPEED_WOUND',
                        'shift': 5,
                        'mask': 0x01,
                        'value': p.wound_speed(ret_value=True)
                    },
                    {
                        'name': 'DS_GLITCH_SENSOR',
                        'shift': 6,
                        'mask': 0x01,
                        'value': p.wound_glitch_sensor(ret_value=True)
                    },
                    {
                        'name': 'DS_AES',
                        'shift': 7,
                        'mask': 0x01,
                        'value': p.wound_aes(ret_value=True)
                    },
                    {
                        'name': 'SRAM_REPAIRED',
                        'shift': 8,
                        'mask': 0x01,
                        'value': p.wound_sram_repaired(ret_value=True)
                    }
                ]
            },
            'wounding_ppss': {
                'size': 4,
                'data': [
                    {
                        'name': 'DS_CPU0',
                        'shift': 0,
                        'mask': 0x01,
                        'value': p.wound_ppss_cpu_0(ret_value=True)
                    },
                    {
                        'name': 'DS_CPU1',
                        'shift': 1,
                        'mask': 0x01,
                        'value': p.wound_ppss_cpu_1(ret_value=True)
                    },
                    {
                        'name': 'DS_ADCGRP0',
                        'shift': 2,
                        'mask': 0x01,
                        'value': p.wound_ppss_adc_group_0(ret_value=True)
                    },
                    {
                        'name': 'DS_ADCGRP1',
                        'shift': 3,
                        'mask': 0x01,
                        'value': p.wound_ppss_adc_group_1(ret_value=True)
                    },
                    {
                        'name': 'DS_ADCGRP2',
                        'shift': 4,
                        'mask': 0x01,
                        'value': p.wound_ppss_adc_group_2(ret_value=True)
                    },
                    {
                        'name': 'DS_ADCGRP3',
                        'shift': 5,
                        'mask': 0x01,
                        'value': p.wound_ppss_adc_group_3(ret_value=True)
                    },
                    {
                        'name': 'DS_DCSG_GRP0',
                        'shift': 6,
                        'mask': 0x01,
                        'value': p.wound_ppss_dcsg_group_0(ret_value=True)
                    },
                    {
                        'name': 'DS_DCSG_GRP1',
                        'shift': 7,
                        'mask': 0x01,
                        'value': p.wound_ppss_dcsg_group_1(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS0',
                        'shift': 8,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss0(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS0_MOTIF',
                        'shift': 9,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss0_motif(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS0_HR',
                        'shift': 10,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss0_hr(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS1',
                        'shift': 11,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss1(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS1_MOTIF',
                        'shift': 12,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss1_motif(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS1_HR',
                        'shift': 13,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss1_hr(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS2',
                        'shift': 14,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss2(ret_value=True)
                    },
                    {
                        'name': 'DS_PWM_SS3',
                        'shift': 15,
                        'mask': 0x01,
                        'value': p.wound_ppss_pwm_ss3(ret_value=True)
                    },
                    {
                        'name': 'DS_HWFILT_SS0',
                        'shift': 16,
                        'mask': 0x01,
                        'value': p.wound_ppss_hwfilt_ss0(ret_value=True)
                    },
                    {
                        'name': 'DS_HWFILT_SS1',
                        'shift': 17,
                        'mask': 0x01,
                        'value': p.wound_ppss_hwfilt_ss1(ret_value=True)
                    },
                    {
                        'name': 'DS_CLB',
                        'shift': 18,
                        'mask': 0x01,
                        'value': p.wound_ppss_clb(ret_value=True)
                    },
                    {
                        'name': 'DS_CORDIC0',
                        'shift': 19,
                        'mask': 0x01,
                        'value': p.wound_ppss_cordic_0(ret_value=True)
                    },
                    {
                        'name': 'DS_CORDIC1',
                        'shift': 20,
                        'mask': 0x01,
                        'value': p.wound_ppss_cordic_1(ret_value=True)
                    },
                    {
                        'name': 'CNFG_CODE_MEM',
                        'shift': 21,
                        'mask': 0x01,
                        'value': p.wound_ppss_code_mem(ret_value=True)
                    },
                    {
                        'name': 'CNFG_DATA_MEM',
                        'shift': 22,
                        'mask': 0x01,
                        'value': p.wound_ppss_data_mem(ret_value=True)
                    },
                    {
                        'name': 'DS_M2_M3_M4_MEM',
                        'shift': 23,
                        'mask': 0x01,
                        'value': p.wound_ppss_m2_m3_m4_mem(ret_value=True)
                    }
                ]
            },
            'padding': {
                'size': 4,
                'data': [
                    {
                        'name': 'padding',
                        'shift': 0,
                        'value': bytes(4)
                    },
                ],
            }
        }
        return assets

    @staticmethod
    def _integrity_cert_data(cert_path):
        """Returns Device Integrity cert data
        @param cert_path: Path to the IFX Device Integrity cert
        @return: Device Integrity certificate data
        """
        try:
            with open(cert_path, encoding="utf-8") as f:
                cert_data = json.load(f)
            logger.debug("JSON cert used to create integrity_exam in_params "
                         "'%s'", cert_path)
            cert_hex_data = cert_data.get('certificate')
            cert = bytes.fromhex(cert_hex_data)
        except UnicodeDecodeError:
            with open(os.path.abspath(cert_path), 'rb') as fp:
                cert = fp.read()
            logger.debug("CBOR cert used to create integrity_exam in_params "
                         "'%s'", cert_path)
        return cert

    @staticmethod
    def oem_provisioning_asset_map(parser, **kwargs):
        """Gets protected and unprotected parts of the OEM provisioning packet
        @param parser: Policy parser object
        @param kwargs:
            :revoke: IFX key revocation certificate
        @return: Unprotected data, protected data, list of IDs that have to
        be represented as a CBOR blob
        """

        def _read_cert(cert):
            if cert:
                with open(cert, 'rb') as fp:
                    return fp.read()
            return None

        unprotected = {
            'ifx_oem_cert.value': {
                'id': 0x11010010,
                'value': _read_cert(kwargs.get('ifx_oem_cert'))
            }
        }

        protected = {
            'control_word': {
                'id': 0x10010002,
                'value': parser.control_word()
            },
            'nv_counter_a1': {
                'id': 0x10010003,
                'value': parser.nv_counter('a1')
            },
            'nv_counter_a2': {
                'id': 0x10010004,
                'value': parser.nv_counter('a2')
            },
            'failed_signature_counter': {
                'id': 0x10010007,
                'value': parser.failed_signature_counter(names=(
                    'ram_app',
                    'boot_app_layout_0',
                    'boot_app_layout_1'
                ))
            },
            'iak_cfg': {
                'id': 0x10010008,
                'value': parser.iak_cfg(ret_value=True)
            },
            'prov_oem_complete': {
                'id': 0x11010009,
                'value': parser.prov_oem_complete(ret_value=True)
            },
            'access_restrict': {
                'id': 0x1101000A,
                'value': parser.access_restrict()
            },
            'access_restrict_2': {
                'id': 0x1101000B,
                'value': parser.access_restrict_2()
            },
            'listen_window': {
                'id': 0x1101000C,
                'value': parser.debug_listen_window(ret_value=True)
            },
            'boot_cfg_id': {
                'id': 0x1101000D,
                'value': parser.boot_cfg_id(ret_value=True)
            },
            'boot_bank_ctr_offset': {
                'id': 0x1101000E,
                'value': parser.boot_bank_ctr_offset()
            },
            'boot_hash_locking': {
                'id': 0x1101000F,
                'value': parser.boot_hash_locking(ret_value=True)
            },
            'boot_auth': {
                'id': 0x11010011,
                'value': parser.boot_auth()
            },
            'boot_app_layout': {
                'id': 0x11010012,
                'value': parser.boot_app_layout(ret_array=True)
            },
            'boot_od_clk': {
                'id': 0x11010013,
                'value': parser.boot_od_clk(ret_value=True)
            },
            'pc_ctl_valid': {
                'id': 0x11010014,
                'value': parser.pc_ctl_valid()
            },
            'oem_device_cert_blocks': {
                'id': 0x11010015,
                'value': parser.oem_device_cert_blocks()
            },
            'pc2_handler': {
                'id': 0x11010016,
                'value': parser.pc2_handler()
            },
            'pc3_handler': {
                'id': 0x11010017,
                'value': parser.pc3_handler()
            },
            'dfu': {
                'id': 0x11010018,
                'value': parser.dfu()
            },
            'oem_device_cert_addr': {
                'id': 0x11010019,
                'value': parser.oem_device_cert_addr()
            },
            'boundary_scan': {
                'id': 0x1101001A,
                'value': parser.boundary_scan(ret_value=True)
            },
            'oem_debug_key': {
                'id': 0x1101001B,
                'value': parser.oem_debug_public_key(ret_value=True)
            },
            'disable_ramapp': {
                'id': 0x1101001C,
                'value': parser.disable_ramapp(ret_value=True)
            },
            'oem_enc_key': {
                'id': 0x1101001D,
                'value': parser.enc_key('oem_enc_key', ret_value=True)
            },
            'mpc_struct': {
                'id': 0x1101001E,
                'value': parser.mpc_policy_t()
            },
            'raw_data_pc012': {
                'id': 0x1101001F,
                'value': parser.raw_data_pc012()
            },
            'nonce': {
                'id': 0x11010020,
                'value': parser.reprovisioning_nonce(nullable=True)
            },
            'ifx_revocation_signature': {
                'id': 0x11010021,
                'value': parser.ifx_revocation_signature(nullable=True)
            },
            'gpio_cfg': {
                'id': 0x11010022,
                'value': parser.gpio_cfg()
            },
            'gpio_out': {
                'id': 0x11010023,
                'value': parser.gpio_out()
            },
        }
        cbor_blobs = [0x11010012]

        return unprotected, protected, cbor_blobs


def asset_item_data(p, asset_name, asset_item_name):
    """ Gets a tuple with the asset item size and mask """
    shift = None
    mask = None
    assets = AssetMapPsocC3x6.get(p)
    for item in assets[asset_name]['data']:
        if item['name'] == asset_item_name:
            shift = item['shift']
            mask = item['mask']
            break
    return shift, mask


def nonce(incremental_counter=None, initial_value=None):
    """Gets a value in the following format:
      - bits 0...31 - incremental counter
      - bits 32...63 - initial value
      - bits 64...127 - Unix timestamp
    Custom values are used for the incremental counter and initial value
    if specified. Otherwise, the random values are generated.
    """
    ic = incremental_counter or os.urandom(4)
    iv = initial_value or os.urandom(4)
    ts = unix_timestamp_bytes()
    return ic + iv + ts


def unix_timestamp_bytes():
    """Gets 64-bit Unix timestamp"""
    return int.to_bytes(int(time.time()), length=8, byteorder='big')
