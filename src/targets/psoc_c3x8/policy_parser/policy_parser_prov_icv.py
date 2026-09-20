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
from typing import Union

from ..asset_enums import (FlashWounding, SramWounding, SpeedWounding,
                           ProvIcvControlWord, DisabledEnum, ReducedEnum)
from ...common.policy_parser_primitives import PolicyParserPrimitives


class PolicyParserProvIcv(PolicyParserPrimitives):
    """Provides functionality for searching data in the policy file"""

    def prov_icv_control_word(self, ret_value=False) -> Union[ProvIcvControlWord,
                                                              int]:
        """Gets a value of the 'control_word.value' property"""
        return self.enum_field(ProvIcvControlWord, ret_value, 'control_word',
                               'value')

    def wound_can(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding.can.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding', 'can', 'value')

    def wound_flash(self, ret_value=False) -> Union[FlashWounding, int]:
        """Gets a value of the 'wounding.flash.value' property"""
        return self.enum_field(FlashWounding, ret_value, 
                               'wounding', 'flash', 'value')

    def wound_sram(self, ret_value=False) -> Union[SramWounding, int]:
        """Gets a value of the 'wounding.sram.value' property"""
        return self.enum_field(SramWounding, ret_value,
                               'wounding', 'sram', 'value')

    def wound_sram_repaired(self, ret_value=False) -> Union[int, bool]:
        """Gets a value of the 'wounding.sram_repaired.value' property"""
        value = self.field('wounding', 'sram_repaired', 'value')
        return int(value) if ret_value else value

    def wound_speed(self, ret_value=False) -> Union[SpeedWounding, int]:
        """Gets a value of the 'wounding.speed.value' property"""
        return self.enum_field(SpeedWounding, ret_value,
                               'wounding', 'speed', 'value')

    def wound_glitch_sensor(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding.glitch_sensor.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding', 'glitch_sensor', 'value')

    def wound_aes(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding.aes.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding', 'aes', 'value')

    def wound_ppss_cpu_0(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.cpu_0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'cpu_0', 'value')

    def wound_ppss_cpu_1(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.cpu_1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'cpu_1', 'value')

    def wound_ppss_adc_group_0(self, ret_value=False) -> Union[DisabledEnum,
                                                               int]:
        """Gets a value of the 'wounding_ppss.adc_group_0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'adc_group_0', 'value')

    def wound_ppss_adc_group_1(self, ret_value=False) -> Union[DisabledEnum,
                                                               int]:
        """Gets a value of the 'wounding_ppss.adc_group_1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'adc_group_1', 'value')

    def wound_ppss_adc_group_2(self, ret_value=False) -> Union[DisabledEnum,
                                                               int]:
        """Gets a value of the 'wounding_ppss.adc_group_2.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'adc_group_2', 'value')

    def wound_ppss_adc_group_3(self, ret_value=False) -> Union[DisabledEnum,
                                                               int]:
        """Gets a value of the 'wounding_ppss.adc_group_3.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'adc_group_3', 'value')

    def wound_ppss_dcsg_group_0(self, ret_value=False) -> Union[DisabledEnum,
                                                                int]:
        """Gets a value of the 'wounding_ppss.dcsg_group_0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'dcsg_group_0', 'value')

    def wound_ppss_dcsg_group_1(self, ret_value=False) -> Union[DisabledEnum,
                                                                int]:
        """Gets a value of the 'wounding_ppss.dcsg_group_1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'dcsg_group_1', 'value')

    def wound_ppss_pwm_ss0(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.pwm_ss0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss0', 'value')

    def wound_ppss_pwm_ss1(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.pwm_ss1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss1', 'value')

    def wound_ppss_pwm_ss2(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.pwm_ss2.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss2', 'value')

    def wound_ppss_pwm_ss3(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.pwm_ss3.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss3', 'value')

    def wound_ppss_pwm_ss0_motif(self, ret_value=False) -> Union[DisabledEnum,
                                                                 int]:
        """Gets a value of the 'wounding_ppss.pwm_ss0_motif.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss0_motif', 'value')

    def wound_ppss_pwm_ss1_motif(self, ret_value=False) -> Union[DisabledEnum,
                                                                 int]:
        """Gets a value of the 'wounding_ppss.pwm_ss1_motif.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss1_motif', 'value')

    def wound_ppss_pwm_ss0_hr(self, ret_value=False) -> Union[DisabledEnum,
                                                              int]:
        """Gets a value of the 'wounding_ppss.pwm_ss0_hr.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss0_hr', 'value')

    def wound_ppss_pwm_ss1_hr(self, ret_value=False) -> Union[DisabledEnum,
                                                              int]:
        """Gets a value of the 'wounding_ppss.pwm_ss1_hr.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'pwm_ss1_hr', 'value')

    def wound_ppss_hwfilt_ss0(self, ret_value=False) -> Union[DisabledEnum,
                                                              int]:
        """Gets a value of the 'wounding_ppss.hwfilt_ss0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'hwfilt_ss0', 'value')

    def wound_ppss_hwfilt_ss1(self, ret_value=False) -> Union[DisabledEnum,
                                                              int]:
        """Gets a value of the 'wounding_ppss.hwfilt_ss1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'hwfilt_ss1', 'value')

    def wound_ppss_clb(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.clb.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'clb', 'value')

    def wound_ppss_cordic_0(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.cordic_0.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'cordic_0', 'value')

    def wound_ppss_cordic_1(self, ret_value=False) -> Union[DisabledEnum, int]:
        """Gets a value of the 'wounding_ppss.cordic_1.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'cordic_1', 'value')

    def wound_ppss_code_mem(self, ret_value=False) -> Union[ReducedEnum, int]:
        """Gets a value of the 'wounding_ppss.code_mem.value' property"""
        return self.enum_field(ReducedEnum, ret_value,
                               'wounding_ppss', 'code_mem', 'value')
    
    def wound_ppss_data_mem(self, ret_value=False) -> Union[ReducedEnum, int]:
        """Gets a value of the 'wounding_ppss.data_mem.value' property"""
        return self.enum_field(ReducedEnum, ret_value,
                               'wounding_ppss', 'data_mem', 'value')
    
    def wound_ppss_m2_m3_m4_mem(self, ret_value=False) -> Union[DisabledEnum,
                                                                int]:
        """Gets a value of the 'wounding_ppss.m2_m3_m4_mem.value' property"""
        return self.enum_field(DisabledEnum, ret_value,
                               'wounding_ppss', 'm2_m3_m4_mem', 'value')
