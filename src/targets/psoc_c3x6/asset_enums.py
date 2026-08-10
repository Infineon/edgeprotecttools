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
from enum import Enum, IntEnum


class CoseSign1Packet(IntEnum):
    """Key ID for COSE_Sign1 CBOR packet"""
    IFX_PROV_PACKET = 0x10000000
    OEM_PROV_PACKET = 0x11000000
    REPROVISIONING_ID = 0x11010001
    DEBUG_ID = 0x11010002
    IFX_OEM_CERT = 0x11010010
    USER_CERTIFICATE_ID = 0x11010008
    COSE_PACKET_ID = 0x1F000000


class ControlWord(IntEnum):
    """OEM provisioning control word asset values"""
    PROG_SFLASH_ASSETS = 0x01
    PROG_HASH_EN = 0x04
    REV_IFX_ROT_KEY_0 = 0x08
    REV_IFX_RMA_MASTER_KEY_0 = 0x10
    REV_OEM_ROT_KEY_0 = 0x20


class KeyRevocation(IntEnum):
    """Key revocation asset value"""
    IFX_ROT_KEY_0 = 0x01
    OEM_ROT_KEY_0 = 0x02
    PROT_FW_ROT_KEY_0 = 0x03


class SecBool(IntEnum):
    """OEM provisioning boolean asset values"""
    SEC_TRUE = 0xC39D5455
    SEC_FALSE = 0x151DD9BB


DfuInterface = Enum(
    value='DFU_IF',
    names=[
        ('Reserved', 0),
        ('UART', 1),
        ('SPI', 2),
        ('I2C', 3),
        ('None', 0),
    ]
)

ListenWindow = Enum(
    value='Time',
    names=[
        ('100 ms', 0xC39D0001),
        ('20 ms', 0xC39D0002),
        ('2 ms', 0xC39D0003),
        ('0 ms', 0x151DD9BB),
        ('None', 0x151DD9BB),
    ]
)

BootHashLocking = Enum(
    value='Hash Locking',
    names=[
        ('Enable', 0xC39D5455),
        ('Disable', 0x151DD9BB),
        ('Permanently Lock', 0x631A1FAC),
    ]
)

BootCfgId = Enum(
    value='Behavior',
    names=[
        ('SIMPLE_APP', 0x9ADC8D08),
        ('SECURE_APP', 0x4FBEEF63),
        ('DUAL_BANK_SIMPLE_APP', 0x39B92974),
        ('DUAL_BANK_SECURE_APP', 0x77D56A80),
        ('PROT_FW', 0x4A656DBD),
        ('None', 0),
    ]
)

BootAuthImages = Enum(
    value='Authentication',
    names=[
        ('NONE', 0x0000_07DB),
        ('ONE', 0x0000_5368),
        ('ALL', 0x0000_2644),
        ('ALL_MOVE', 0x0000_363E),
    ]
)

BootAuthSignature = Enum(
    value='Authentication',
    names=[
        ('ES256', 0xFE2D_0000),
        ('ES384', 0xEAE2_0000),
        ('ES512', 0x16FF_0000),
    ]
)

ProtFwAuthMethod = Enum(
    value='Authentication',
    names=[
        ('SHA256', 0x0000_5A3C),
        ('Signature', 0x0000_0F96),
        ('None', 0),
    ]
)

ProtFwAuthNextApp = Enum(
    value='Authentication',
    names=[
        ('Skip', 0x5A3C_0000),
        ('AuthNext', 0x0F96_0000),
        ('None', 0),
    ]
)

MMIORestrictions = Enum(
    value='Restrictions',
    names=[
        ('No restrictions', 0),
        ('SRSS_GENERAL2 only', 1),
        ('No access', 2),
        ('None', 0),
    ]
)

DebugPins = Enum(
    value='Debug Pins',
    names=[
        ('0000', 0b0000),
        ('0011', 0b0011),
        ('0101', 0b0101),
        ('0110', 0b0110),
        ('1001', 0b1001),
        ('1010', 0b1010),
    ]
)

BootOdClk = Enum(
    value='Frequency',
    names=[
        ('48 MHz', 0x00),
        ('100 MHz', 0x55),
        ('180 MHz', 0xAA),
        ('None', 0),
    ]
)

ProvIcvControlWord = Enum(
    value='Control word',
    names=[
        ('EFUSE_DATA', 1),
        ('BOOTROW', 2),
        ('ALL', 3),
        ('None', 0)
    ]
)

FlashWounding = Enum(
    value='Size',
    names=[
        ('512K', 0),
        ('384K', 1),
        ('256K', 2),
        ('128K', 3),
        ('None', 0)
    ]
)

SramWounding = Enum(
    value='Size',
    names=[
        ('128K', 0),
        ('96K', 1),
        ('64K', 2),
        ('32K', 3),
        ('None', 0)
    ]
)

SerialInterface = Enum(
    value='Interface',
    names=[
        ('i2c', 1),
        ('uart', 2),
        ('spi', 3),
    ]
)

DisabledEnum = Enum(
    value='Disabled',
    names=[
        ('Enabled', 0),
        ('Disabled', 1),
        ('None', 0)
    ]
)

ReducedEnum = Enum(
    value='Reduced',
    names=[
        ('Full', 0),
        ('Half', 1),
        ('None', 0)
    ]
)

SpeedWounding = Enum(
    value='Speed',
    names=[
        ('180 MHz', 0),
        ('100 MHz', 1),
        ('None', 0)
    ]
)


IakCfg = Enum(
    value='IAK Configuration',
    names=[
        ('NONE', 0),
        ('AES256', 1),
        ('ECC256', 2),
        ('ECC384', 3),
        ('ECC521', 4)
    ]
)