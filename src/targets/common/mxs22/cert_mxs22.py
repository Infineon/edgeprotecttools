"""
Copyright 2023-2025 Cypress Semiconductor Corporation (an Infineon company)
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
import datetime

import jsonschema
from cbor import cbor
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, SECP256R1, SECP384R1
)
from cwt import COSE, COSEKey

from .cert_validator_mxs22 import CertTemplateValidatorMXS22
from .enums import DeviceResponse, DeviceIntegrity
from .key_validator_mxs22 import KeyValidatorMXS22
from ....core.cose import Cose
from ....core.key_handlers import load_public_key
from ....core.key_handlers.ec_handler import ECHandler
from ....core.strategy_context.cert_strategy_ctx import CertificateStrategy

logger = logging.getLogger(__name__)


class CertificateStrategyMXS22(CertificateStrategy):
    """Create certificates for MXS22 platform"""

    def __init__(self):
        self.key_validator = KeyValidatorMXS22()
        self.template_filename = None

    def default_certificate_data(self, tool, target, probe_id):
        raise NotImplementedError

    def verify_certificate(self, cert_path, root_cert_path, key_path):
        raise NotImplementedError

    def create_certificate(self, filename, encoding, overwrite, **kwargs):
        """Creates certificate in CBOR format"""
        private_keys = kwargs.get('key_path')
        if private_keys and all(private_keys):
            if not isinstance(private_keys, tuple):
                private_keys = (private_keys,)
            for key in private_keys:
                self.key_validator.validate_private_key(key)

        if not kwargs.get('template'):
            raise ValueError("Missing certificate template")
        return self.create_certificate_from_template(filename, **kwargs)

    def create_certificate_from_template(self, filename, **kwargs):
        """Creates certificate from template"""
        self.template_filename = kwargs.get('template')
        csr = kwargs.get('csr')
        cert_data = self.load_cert_template(self.template_filename)

        data = CertTemplateValidatorMXS22().validate(cert_data, csr)
        return self._create_cert_from_base_template(filename, data, **kwargs)

    @staticmethod
    def load_cert_template(template):
        """Loads certificate template from JSON file or dictionary"""
        if isinstance(template, dict):
            cert_data = template
        elif os.path.isfile(template):
            cert_template = os.path.abspath(template)
            logger.debug('Load certificate template: %s', cert_template)
            with open(cert_template, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
        else:
            raise ValueError('Certificate template not found')
        return cert_data

    def create_csr(self, output, key_path, **kwargs):
        raise NotImplementedError

    def _device_integrity_cert(self, output, **kwargs):
        """
        Creates IFX Device Integrity certificate
        @param output:Path where to save the created certificate
        @param kwargs:
            :template: Template path
            :key: Private key path to sign certificate
            :algorithm: Signature algorithm type
            @return: Certificate object
        """
        template_path = kwargs.get('template')
        template = self.load_json(template_path)
        if not template.get('regions'):
            raise KeyError(f"Field 'regions' not found in '{template_path}'")
        cert_path = kwargs.get('cert')
        if cert_path:
            cert = self.load_bin(cert_path)
            self.save_integrity_json_cert(cert, output, template)
            return cert

        self.validate_integrity_cert(template)

        regions = self._process_regions(template)
        device_info = template.get('device')
        device_id = int(str(device_info.get('si')), 0)
        family_id = int(str(device_info.get('family')), 0)
        revision_id = int(str(device_info.get('rev')), 0)
        cert_data = {
            'device': {
                'si': device_id.to_bytes(2, 'little'),
                'family': family_id.to_bytes(2, 'little'),
                'rev': revision_id.to_bytes(1, 'little')
            },
            DeviceIntegrity.REGIONS: regions
        }
        cert = cbor.dumps(cert_data)
        key = kwargs.get('key')
        algorithm = kwargs.get('algorithm')
        if key:
            cert = Cose.cose_sign1(cert, key)
            if output and output.endswith('.json'):
                self.save_integrity_json_cert(cert, output, template)
                return cert
        elif algorithm:
            cert = Cose.prepare_hsm_sign1(cert, algorithm)
        if output:
            self._save_cbor(cert, output, 'IFX Device Integrity certificate')
        return cert

    @staticmethod
    def validate_integrity_cert(template):
        """Validates integrity_exam certificate against JSON schema"""
        schema_path = os.path.join(
            os.path.dirname(__file__),
            'schemas', 'integrity_exam_cert_template.json_schema')
        schema = CertificateStrategyMXS22.load_json(schema_path)
        try:
            jsonschema.validate(template, schema)
            logger.debug('Validation against schema succeed')
        except (jsonschema.exceptions.ValidationError,
                jsonschema.exceptions.SchemaError) as exc:
            logger.error('Validation against schema failed')
            logger.error(exc.message)
            logger.debug(exc)

    def _process_regions(self, template):
        """Creates regions certificate structure"""
        regions = []
        for fields in template['regions']:
            section = {}
            for itm, itm_val in fields.items():
                if itm == 'hash':
                    if isinstance(itm_val, list):
                        hash_data = self._region_hash(fields)
                        section.update({itm: hash_data})
                    else:
                        section.update({itm: bytes.fromhex(itm_val)})
                elif itm == 'region':
                    reg_items = self._region_data(fields)
                    section.update({itm: reg_items})
                elif itm != 'description':
                    section.update({itm: itm_val})
            regions.append(section)
        return regions

    @staticmethod
    def _region_data(fields):
        """Update the region list"""
        return [[int(str(data), 0) for data in hash_itm]
                for hash_itm in fields['region']]

    @staticmethod
    def _region_hash(hash_data):
        """Update the list of region hashes"""
        hash_itms = []
        for hash_itm in hash_data['hash']:
            hash_fields = {}
            for reg, reg_val in hash_itm.items():
                if reg == 'hash':
                    val = {reg: bytes.fromhex(reg_val)}
                elif reg == 'description':
                    continue
                else:
                    val = {reg: reg_val}
                hash_fields.update(val)
            hash_itms.append(hash_fields)
        return hash_itms

    def _create_cert_from_base_template(self, output, base_data, **kwargs):
        """Creates CBOR certificate from base template data
        @param output: Path to save CSR
        @param base_data: Base template data updated with cert template
        @param kwargs:
            :csr: Path to the CSR
            :key_path: The private key path or tuple of key paths
            :json_cert: JSON cert path
        @return: CBOR certificate
        """
        csr_path = kwargs.get('csr')
        csr_data = None
        if csr_path:
            csr_data = self._load_csr(csr_path)
        cert = self._cert_fields(base_data, csr_data)
        return self._save_cert(cert, base_data, output, **kwargs)

    def _load_csr(self, csr_path):
        """Load CSR from CBOR or JSON"""
        csr, csr_payload = self.load_cert(csr_path)
        if isinstance(csr_payload, dict):
            logger.debug('Used RAM app out results')
            response = csr_payload.get(DeviceResponse.DEV_RSP)
            csr = response.get(DeviceResponse.DEV_ID_CERT)
            csr_payload = cbor.loads(csr)

        if not isinstance(csr_payload, cbor.Tag):
            raise ValueError(f"Invalid CSR data '{csr_path}'")

        logger.debug('CSR TAG: %s', csr_payload.tag)
        csr_data = self._validate_csr(csr, csr_payload)
        return csr_data

    def load_cert(self, cert):
        """Loads cert data from JSON or binary cert file"""
        if isinstance(cert, bytes):
            cert_data = cert
        else:
            csr_path = os.path.abspath(cert)
            try:
                json_data = self.load_json(csr_path)
                cert_data = bytes.fromhex(json_data.get('CERTIFICATE'))
            except UnicodeDecodeError:
                cert_data = self.load_bin(csr_path)

        return cert_data, self._parse_cert(cert_data)

    def pubkey_from_cert(self, cert, kid) -> EllipticCurvePublicKey:
        """Retrieve public key from OEM certificate"""
        if int(kid) not in (0, 1):
            raise ValueError('The key ID must be either 0 or 1')

        _, cert_data = self.load_cert(cert)
        deserialized = cbor.loads(cert_data.value[2])
        pubkey = deserialized.get(f'PUBLIC_KEY_{kid}')
        if not pubkey:
            pubkey = deserialized.get(f'public_key_{kid}')
        if not pubkey:
            raise ValueError(f'Public key {kid} not found in certificate')
        pubkey = self.populate_public_key(pubkey)
        return pubkey

    @staticmethod
    def populate_public_key(key: bytes):
        """ Creates an EC public key from the public numbers """
        if len(key) == 65:
            curve = SECP256R1()
        elif len(key) == 97:
            curve = SECP384R1()
        else:
            raise ValueError('Invalid public key format')
        pubkey = EllipticCurvePublicKey.from_encoded_point(curve, key)
        return pubkey

    @staticmethod
    def _parse_cert(cert):
        """Parses certificate with leading 4 bytes of size and without it"""
        # Parses CSR without leading 4 bytes of size
        payload = CertificateStrategyMXS22.cert_payload(cert)

        # Parse CSR with leading 4 bytes of size
        if int.from_bytes(cert[:4], byteorder='little') == len(cert[4:]):
            payload = CertificateStrategyMXS22.cert_payload(cert[4:])

        if not payload:
            raise ValueError('Certificate is in wrong format')

        return payload

    @staticmethod
    def cert_payload(certificate):
        """Loads cbor data and validates data type"""
        try:
            data = cbor.loads(certificate)
        except Exception:  # pylint: disable=broad-except
            return None

        if isinstance(data, dict) and data.get(DeviceResponse.DEV_RSP):
            return data

        if isinstance(data, cbor.Tag) and data.tag in (18, 98):
            if isinstance(data.value, list):
                return data
        return None

    @staticmethod
    def _validate_csr(csr, csr_payload):
        """Validate and decode data of the OEM_CSR and DEVICE_CSR"""
        cbor_data = None
        csr_data = cbor.loads(csr_payload.value[2])
        for key in (csr_data.get('PUBLIC_KEY_0'), csr_data.get('PUBLIC_KEY_1')):
            if key:
                pubkey = CertificateStrategyMXS22.populate_public_key(key)
                cbor_data = CertificateStrategyMXS22._decode_verify(csr, pubkey)
        csr_data = cbor.loads(cbor_data)
        return csr_data

    @staticmethod
    def display_cert(cert, cert_data):
        """Displays generated certificate data and"""
        json_data = {}
        for field, val in cert.items():
            if cert_data[field].get('type') == 'INT':
                value = hex(int.from_bytes(val, 'little'))
            else:
                value = val.hex().upper() if isinstance(val, bytes) else val
            logger.info('%s: %s', field, value)
            json_data.update({field: value})
        return json_data

    def _cert_fields(self, template, csr):
        """Composes cert field based on template and CSR data"""
        cert_type_info = template.get('TEMPLATE_TYPE')
        cert_type = cert_type_info.get('value')
        mandatory = {}
        optional = {}
        for itm in template:
            used = template[itm].get('used')
            present = template[itm].get('present')
            is_mandatory = template[itm].get('mandatory')
            if used and cert_type in used:
                data = None
                data_type = template[itm].get('type')

                if data_type in ('STRING', 'ENUM'):
                    data = {itm: template[itm].get('value')}
                elif data_type == 'HEX':
                    value = template[itm].get('value').replace('0x', '')
                    value = value.zfill(len(value) + len(value) % 2)
                    try:
                        data = {itm: bytes.fromhex(value)}
                    except ValueError as e:
                        raise ValueError(f"Non-hexadecimal number specified: "
                                         f"'{value}'") from e
                elif data_type == 'KEY':
                    data = {itm: self._template_key(itm, template)}
                elif data_type == 'DATE':
                    data = {itm: self._template_date(itm, template)}

                if is_mandatory:
                    mandatory.update(data)
                else:
                    optional.update(data)
            elif is_mandatory or cert_type in present:
                if is_mandatory:
                    mandatory.update({itm: csr.get(itm, '') if csr else ''})
                else:
                    optional.update({itm: csr.get(itm, '') if csr else ''})
        mandatory.update(optional)
        return mandatory

    def _template_key(self, key_name, template):
        """Gets public key data from the template field"""
        key_value = template.get(key_name).get('value')

        if isinstance(self.template_filename, str):
            template_dir = os.path.dirname(self.template_filename)
        else:
            template_dir = ''

        if os.path.isabs(key_value):
            key_path = key_value
        else:
            key_path = os.path.abspath(os.path.join(template_dir, key_value))

        if os.path.isfile(key_path):
            self.key_validator.validate_public_key(key_path)
            key = load_public_key(key_path)
            key_data = self._public_x962_encoded(key)
        else:
            try:
                key_data = bytes.fromhex(key_value)
            except ValueError as exc:
                raise ValueError(
                    "Neither an existing file nor a valid hexadecimal string "
                    f"specified: '{key_value}'") from exc
        return key_data

    def _template_date(self, date_name, template):
        """Gets date from the template field or generates current date"""
        date_val = template[date_name].get('value')
        if date_val:
            date = datetime.datetime.strptime(date_val, "%Y-%m-%d %H:%M:%S")
        else:
            date = self.utcnow()
        return date.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def _public_x962_encoded(public_key):
        """Encode public key to mbedTLS binary format"""
        out_data = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return out_data

    @staticmethod
    def load_bin(path):
        """ Loads data from binary file """
        with open(os.path.abspath(path), 'rb') as file:
            return file.read()

    @staticmethod
    def load_json(path):
        """ Loads data from JSON file """
        with open(os.path.abspath(path), 'r', encoding='utf-8') as file:
            return json.load(file)

    @staticmethod
    def _decode_verify(cbor_data, public_key):
        """Verifies and decodes cbor data"""
        ctx = COSE.new()
        json_key = ECHandler.public_jwk(public_key, None)
        cose_key = COSEKey.from_jwk(json_key)
        return ctx.decode(cbor_data, cose_key)

    @staticmethod
    def _save_cbor(payload, save_path, info_msg):
        """Saves CBOR data to a file"""
        Cose.dump(payload, save_path)
        logger.info("Created %s '%s'", info_msg, os.path.abspath(save_path))

    def _save_cert(self, cert_data, base_data, output, **kwargs):
        """Saves CBOR certificate"""
        key_path = kwargs.get('key_path')
        json_cert = kwargs.get('json_cert')
        json_data = self.display_cert(cert_data, base_data)
        cert = cbor.dumps(cert_data)
        algorithm = cert_data.get('ALGORITHM')
        cert_type = cert_data.get('TEMPLATE_TYPE')
        csr_pub_key_0 = cert_data.get('PUBLIC_KEY_0')
        csr_pub_key_1 = cert_data.get('PUBLIC_KEY_1')
        if cert_type == 'OEM_CSR':
            algorithms = kwargs.get('algorithms')
            sig_alg = algorithm if algorithm else algorithms
            if isinstance(key_path, tuple) and any(key_path):
                if all(key_path) and all((csr_pub_key_0, csr_pub_key_1)):
                    cert = self._save_signed(cert, cert_type, json_cert,
                                             json_data, key_path)
                elif not csr_pub_key_1 and not key_path[1]:
                    cert = self._save_signed1(cert, cert_type, json_cert,
                                              json_data, key_path[0])
                else:
                    logger.debug('Public key 0: %s', csr_pub_key_0)
                    logger.debug('Public key 1: %s', csr_pub_key_1)
                    raise ValueError(
                        'Number of public and private keys does not match')
            elif isinstance(key_path, str):
                cert = self._save_signed1(cert, cert_type, json_cert, json_data,
                                          key_path)
            else:
                if all((csr_pub_key_0, csr_pub_key_1)):
                    cert = self._save_unsigned(sig_alg, cert, cert_type)
                elif csr_pub_key_0 and not csr_pub_key_1:
                    cert = self._save_unsigned1(sig_alg, cert, cert_type)
                else:
                    raise ValueError('Public key 0 is required for OEM CSR')
        elif isinstance(key_path, str):
            cert = self._save_signed1(cert, cert_type, json_cert, json_data,
                                      key_path)
        else:
            cert = self._save_unsigned1(algorithm, cert, cert_type)
        if output:
            self._save_cbor(cert, output, cert_type)
        return cert

    @staticmethod
    def _save_unsigned1(algorithm, cert, cert_type):
        """Creates cert as structure for signing on HSM"""
        cert = Cose.prepare_hsm_sign1(cert, algorithm)
        if cert_type:
            logger.info('Created %s cose_sign1 packet for HSM signing',
                        cert_type)
        return cert

    @staticmethod
    def _save_signed1(cert, cert_type, json_cert, json_data, key_path):
        """Creates cbor signed cert and cert in JSON format"""
        cert = Cose.cose_sign1(cert, key_path)
        if json_cert:
            CertificateStrategyMXS22.save_json_cert(json_data, cert, json_cert)
        if cert_type:
            logger.debug('The %s signed via cose_sign1', cert_type)
        return cert

    @staticmethod
    def _save_unsigned(algorithm, cert, cert_type):
        """Creates oem_csr as structure for signing on HSM"""
        hsm_cert = Cose.prepare_hsm_sign(cert, (algorithm, algorithm))
        cert = hsm_cert[-1]
        if cert_type:
            logger.info('Created %s cose_sign packet for HSM signing',
                         cert_type)
        return cert

    @staticmethod
    def _save_signed(cert, cert_type, json_cert, json_data, key_path):
        """Creates signed oem_csr and oem_csr in JSON format"""
        cert = Cose.cose_sign(cert, key_path)
        if json_cert:
            CertificateStrategyMXS22.save_json_cert(json_data, cert, json_cert)
        if cert_type:
            logger.debug('The %s signed via cose_sign', cert_type)
        return cert

    @staticmethod
    def save_integrity_json_cert(cert, output, template):
        """Creates device_integrity_exam JSON cert"""
        template['certificate'] = cert.hex()
        CertificateStrategyMXS22.save_json(
            template, output, info_msg='device integrity exam certificate'
        )

    @staticmethod
    def save_json_cert(json_data, cert, json_output):
        """Creates JSON certificate"""
        json_cert = {
            "TEMPLATE": json_data,
            "CERTIFICATE": cert.hex().upper()
        }
        CertificateStrategyMXS22.save_json(
            json_cert, json_output, info_msg='JSON certificate'
        )

    @staticmethod
    def save_json(data, path, info_msg=None):
        """Saves data to the JSON file"""
        output = os.path.abspath(path)
        if not output.endswith('.json'):
            logger.warning("Invalid JSON file extension used '%s'", output)
        with open(output, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2)
        if info_msg:
            logger.info("Created %s '%s'", info_msg, output)

    @staticmethod
    def utcnow():
        """ Gets UTC time"""
        return datetime.datetime.now(datetime.timezone.utc)
