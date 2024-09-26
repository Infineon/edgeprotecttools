"""
Copyright 2024 Cypress Semiconductor Corporation (an Infineon company)
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
import json
import logging
import os

from cbor import cbor

from .asset_enums import DeviceIntegrity
from .key_validator_mxs40sv2 import KeyValidatorMXS40sv2
from ....core.cose import Cose
from ....core.strategy_context.cert_strategy_ctx import CertificateStrategy

logger = logging.getLogger(__name__)


class CertificateStrategyMXS40Sv2(CertificateStrategy):
    """Create certificates for MXS40Sv2 platform"""

    def __init__(self):
        self.key_validator = KeyValidatorMXS40sv2()

    def default_certificate_data(self, tool, target, probe_id):
        raise NotImplementedError("N/A for MXS40SV2 platform")

    def verify_certificate(self, cert_path, root_cert_path=None, key_path=None):
        raise NotImplementedError("N/A for MXS40SV2 platform")

    def create_csr(self, output, key_path, **kwargs):
        raise NotImplementedError("N/A for MXS40SV2 platform")

    def create_certificate(self, filename, encoding, overwrite, **kwargs):
        """Creates certificate in CBOR or x509 format"""
        private_key = kwargs.get('key')
        if private_key:
            self.key_validator.validate_private_key(private_key)
        cert_format = kwargs.get('cert_format').lower()
        if cert_format == 'cbor':
            dev_cert = kwargs.get('dev_cert').lower()
            if dev_cert == 'device_integrity':
                return self._device_integrity_cert(output=filename, **kwargs)
            raise ValueError(f"Invalid type of ifx cbor certificate "
                             f"'{dev_cert}'")
        raise ValueError(
            f"Invalid type of the certificate format '{cert_format}'")

    @staticmethod
    def _device_integrity_cert(output=None, **kwargs):
        """
        Creates IFX Device Integrity certificate
        @param output:Path where to save the created
                      certificate
        @param kwargs:
            :template: Template path
            :key: Private key path to sign certificate
            :algorithm: Signature algorithm type
            @return: Certificate object
        """
        with open(kwargs.get('template'), 'r', encoding='utf-8') as f:
            template = json.load(f)
        if not template.get('regions'):
            raise KeyError(
                f"Field 'regions' not found in '{kwargs.get('template')}'")
        cert_path = kwargs.get('cert')
        if cert_path:
            with open(os.path.abspath(cert_path), 'rb') as f:
                cert = f.read()
            CertificateStrategyMXS40Sv2.save_integrity_json_cert(
                cert, output, template)
            return cert
        regions = CertificateStrategyMXS40Sv2._process_regions(template)
        cert_data = {DeviceIntegrity.REGIONS: regions}
        cert = cbor.dumps(cert_data)
        key = kwargs.get('key')
        algorithm = kwargs.get('algorithm')
        if key:
            cert = Cose.cose_sign1(cert, key)
            if output and output.endswith('.json'):
                CertificateStrategyMXS40Sv2.save_integrity_json_cert(
                    cert, output, template)
                return cert
        elif algorithm:
            cert = Cose.prepare_hsm_sign1(cert, algorithm)
        if output:
            CertificateStrategyMXS40Sv2._save_cbor(
                cert, output, 'IFX Device Integrity certificate')
        return cert

    @staticmethod
    def save_integrity_json_cert(cert, output, template):
        """Creates device_integrity_exam JSON cert"""
        output = os.path.abspath(output)
        if not output.endswith('.json'):
            logger.warning("Invalid JSON file extension used '%s'", output)
        template['certificate'] = cert.hex()
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(template, f, indent=2)
        logger.info("Created device integrity exam certificate '%s'", output)

    @staticmethod
    def _process_regions(template):
        """Creates regions certificate structure"""
        regions = []
        for fields in template['regions']:
            section = {}
            for itm, itm_val in fields.items():
                if itm == 'description':
                    continue
                elif itm == 'hash':
                    if isinstance(itm_val, list):
                        section[itm] = CertificateStrategyMXS40Sv2._region_hash(
                            fields
                        )
                    else:
                        section[itm] = bytes.fromhex(itm_val)
                elif itm == 'region':
                    section[itm] = CertificateStrategyMXS40Sv2._region_data(
                        fields
                    )
                else:
                    section[itm] = itm_val
            regions.append(section)
        return regions

    @staticmethod
    def _region_data(fields):
        """Update the region list"""
        reg_items = [
            [int(str(data), 0) for data in itm] for itm in fields['region']
        ]
        return reg_items

    @staticmethod
    def _region_hash(hash_data):
        """Update the list of region hashes"""
        hash_itms = []
        for hash_itm in hash_data['hash']:
            hash_fields = {}
            for reg, reg_val in hash_itm.items():
                if reg == 'description':
                    continue
                elif reg == 'hash':
                    hash_fields[reg] = bytes.fromhex(reg_val)
                else:
                    hash_fields[reg] = reg_val
            hash_itms.append(hash_fields)
        return hash_itms

    @staticmethod
    def _save_cbor(payload, save_path, info_msg):
        """Saves CBOR data to a file"""
        Cose.dump(payload, save_path)
        logger.info("Created %s '%s'", info_msg, os.path.abspath(save_path))
