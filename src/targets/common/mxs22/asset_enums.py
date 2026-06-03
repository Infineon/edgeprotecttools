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
from enum import Enum

from .psa_constants import (PsaKeyAlgorithms, PsaKeyUsage)


RamPortion = Enum(
    value='Portion',
    names=[
        ('256KB', 0),
        ('224KB', 1),
        ('192KB', 2),
        ('160KB', 3),
        ('128KB', 4),
        ('96KB', 5),
        ('64KB', 6),
        ('32KB', 7),
        ('None', 0),
    ]
)

RRamOtpPart = Enum(
    value='Part',
    names=[
        ('Entire region', 0),
        ('1/2', 1),
        ('1/4th', 4),
        ('Nothing', 3),
        ('None', 0),
    ]
)

RamPart = Enum(
    value='Part',
    names=[
        ('Entire region', 0),
        ('7/8th', 1),
        ('3/4th', 2),
        ('1/2', 3),
        ('1/4th', 4),
        ('1/8th', 5),
        ('1/16th', 6),
        ('Nothing', 7),
        ('None', 0),
    ]
)

SlWound = Enum(
    value='SlWound',
    names=[
        ('None', 0),
        ('CAN0', 1),
    ]
)

ApPermission = Enum(
    value='Permission',
    names=[
        ('Disabled', 0),
        ('Enabled', 1),
        ('Allowed', 2),
        ('None', 1),
    ]
)

ApPermissionDebugToken = Enum(
    value='Permission',
    names=[
        ('Disabled', 0),
        ('Enabled', 1),
        ('Permanently Disabled', 2),
        ('Allowed', 0),
        ('None', 0),
    ]
)

ApPermissionOpenRMAToken = Enum(
    value='Permission',
    names=[
        ('Disabled', 2),
        ('Enabled', 1),
        ('None', 0),
    ]
)

CpuControlType = Enum(
    value='CpuControlType',
    names=[
        ('Firmware', 0),
        ('Certificate', 1),
        ('Open', 2),
        ('None', 2),
    ]
)

MMIOPart = Enum(
    value='Region',
    names=[
        ('All MMIO registers', 0),
        ('Boot Status', 1),
        ('RAM app only', 2),
        ('No MMIO access', 3),
        ('None', 0),
    ]
)

ListenWindow = Enum(
    value='Time',
    names=[
        ('100 ms', 0),
        ('20 ms', 1),
        ('2 ms', 2),
        ('0 ms', 3),
        ('None', 0),
    ]
)

KeyAlgorithm = Enum(
    value='Algorithm',
    names=[
        ('ECDSA', PsaKeyAlgorithms.ECDSA),
        ('RSA', PsaKeyAlgorithms.RSA_PKCS1),
        ('AES-CTR', PsaKeyAlgorithms.CTR),
        ('AES-CFB', PsaKeyAlgorithms.CBF),
        ('AES-OFB', PsaKeyAlgorithms.OFB),
        ('AES-CBC', PsaKeyAlgorithms.CBC_NO_PADDING),
        ('AES-ECB', PsaKeyAlgorithms.ECB_NO_PADDING),
        ('ECDH', PsaKeyAlgorithms.ECDH),
        ('HKDF_ALG_SHA_256', PsaKeyAlgorithms.HKDF_ALG_SHA_256),
        ('IFX_SE_ALG_KDF_AES_CMAC', PsaKeyAlgorithms.IFX_SE_ALG_KDF_AES_CMAC),
        ('NONE', PsaKeyAlgorithms.NONE)
    ]
)

KeyUsage = Enum(
    value='Usage',
    names=[
        ('EXPORT', PsaKeyUsage.EXPORT),
        ('COPY', PsaKeyUsage.COPY),
        ('CACHE', PsaKeyUsage.CACHE),
        ('ENCRYPT', PsaKeyUsage.ENCRYPT),
        ('DECRYPT', PsaKeyUsage.DECRYPT),
        ('SIGN_MESSAGE', PsaKeyUsage.SIGN_MESSAGE),
        ('VERIFY_MESSAGE', PsaKeyUsage.VERIFY_MESSAGE),
        ('SIGN_HASH', PsaKeyUsage.SIGN_HASH),
        ('VERIFY_HASH', PsaKeyUsage.VERIFY_HASH),
        ('DERIVE', PsaKeyUsage.DERIVE),
        ('VERIFY_DERIVATION', PsaKeyUsage.VERIFY_DERIVATION),
        ('ALLOW_PC0', 0x01000000),
        ('ALLOW_PC1', 0x02000000),
        ('ALLOW_PC2', 0x04000000),
        ('ALLOW_PC3', 0x08000000),
        ('ALLOW_PC4', 0x10000000),
        ('ALLOW_PC5', 0x20000000),
        ('ALLOW_PC6', 0x40000000),
        ('ALLOW_PC7', 0x80000000),

    ]
)

IfxKeyRevocation = {
    'IFX_ROT_KEY': 0x01,
    'IFX_FW_INTEGRITY_KEY': 0x02,
    'IFX_RTS_INTEGRITY_KEY': 0x02,
    'IFX_FW_ENCRYPTION_KEY': 0x04,
    'IFX_RTS_ENCRYPTION_KEY': 0x04,
    'IFX_RMA_MASTER_KEY': 0x08,
    'IFX_APP_INTEGRITY_KEY': 0x10,
    'IFX_APP_ENCRYPTION_KEY': 0x20,
    'IFX_WIFISS_INTEGRITY_KEY': 0x40,
    'IFX_WIFISS_ENCRYPTION_KEY': 0x80,
    'IFX_BTSS_INTEGRITY_KEY': 0x100,
    'IFX_BTSS_ENCRYPTION_KEY': 0x200,
}

SmifMode = Enum(
    value='Mode',
    names=[
        ('AUTO', 0),
        ('SDR', 1)
    ]
)

HashLocking = Enum(
    value='Hash_Locking',
    names=[
        ('Off', 0),
        ('FastBoot', 1),
        ('Lock', 2),
    ]
)

WarmBoot = Enum(
    value='Warm_Boot',
    names=[
        ('Disabled', 0),
        ('FastL2Boot', 1),
        ('InstantL2Boot', 2),
        ('InstantBoot', 3),
        ('None', 0),
    ]
)

SDIOVersion = Enum(
    value='SDIO_Version',
    names=[
        ('2.0', 2),
        ('3.0', 3),
    ]
)

SDIOMaxF2BlockSize = Enum(
    value='SDIO_Max_F2_Block_Size',
    names=[
        ('512', 0),
        ('256', 1),
        ('128', 2),
        ('64', 3),
    ]
)

SDIOMaxSpeedCoding = Enum(
    value='SDIO_Max_Speed_Coding',
    names=[
        ('reserved', 0),
        ('1.0', 1),
        ('1.2', 2),
        ('1.3', 3),
        ('1.5', 4),
        ('2.0', 5),
        ('2.5', 6),
        ('3.0', 7),
        ('3.5', 8),
        ('4.0', 9),
        ('4.5', 10),
        ('5.0', 11),
        ('5.5', 12),
        ('6.0', 13),
        ('7.0', 14),
        ('8.0', 15),
    ]
)

SDIODriveStrength = Enum(
    value='SDIO_Drive_Strength',
    names=[
        ('B', 0),
        ('A', 1),
        ('C', 2),
        ('D', 3),
    ]
)

SDIOMaxSpeedScale = Enum(
    value='SDIO_Max_Speed_Scale',
    names=[
        ('100 kbps', 0),
        ('1 Mbps', 1),
        ('10 Mbps', 2),
        ('25 Mbps', 3),
    ]
)

