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
import base64
import os.path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime

from ...core.key_handlers import load_public_key, load_private_key


class X509CertificateGenerator:
    """Class to generate X.509 certificates from a JSON configuration file"""

    def __init__(self, cert_data):
        """
        Initializes the X.509 certificate generator with the certificate data
        @param cert_data: Certificate data dictionary or a path to a JSON
        """
        if isinstance(cert_data, dict):
            self.data = cert_data
            self.cert_dir = None
        else:
            with open(cert_data, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            self.cert_dir = os.path.dirname(cert_data)
        self.certificate = None

    def validate_cert_config(self):
        """Validates the certificate configuration file"""
        raise NotImplementedError

    @staticmethod
    def cert_issuer(issuer_data: dict) -> x509.Name:
        """Creates an issuer name object from the issuer data
        @param issuer_data: Dictionary with the issuer data
        """
        attributes = []
        if issuer_data.get('country'):
            attributes.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME,
                                   issuer_data['country']))
        if issuer_data.get('organization'):
            attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   issuer_data['organization']))
        if issuer_data.get('organizational_unit'):
            attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   issuer_data['organizational_unit']))
        if issuer_data.get('state_or_province_name'):
            attributes.append(
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                                   issuer_data['state_or_province_name']))
        if issuer_data.get('common_name'):
            attributes.append(
                x509.NameAttribute(NameOID.COMMON_NAME,
                                   issuer_data['common_name']))
        if issuer_data.get('serial_number'):
            attributes.append(
                x509.NameAttribute(NameOID.SERIAL_NUMBER,
                                   issuer_data['serial_number']))
        return x509.Name(attributes)

    @staticmethod
    def cert_subject(subject: str) -> x509.Name:
        """Creates a subject name object from the subject data
        @param subject: Subject name string
        """
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])

    @staticmethod
    def cert_validity_period(validity_period: dict) -> (datetime, datetime):
        """Creates a validity period object from the validity period data"""
        if validity_period.get('not_before') in (None, ''):
            not_before = datetime.now()
        else:
            not_before = datetime.strptime(validity_period['not_before'],
                                           '%Y-%m-%dT%H:%M:%S')

        not_after = datetime.strptime(validity_period["not_after"],
                                      '%Y-%m-%dT%H:%M:%S')
        return not_after, not_before

    def cert_subject_public_key(self, pubkey):
        """Creates a subject public key object from the key path"""
        if isinstance(pubkey, str):
            if not os.path.isabs(pubkey):
                pubkey = os.path.abspath(os.path.join(self.cert_dir, pubkey))
            return load_public_key(pubkey)
        return pubkey

    def add_cert_extensions(
            self,
            extensions_data: list,
            cert_builder: x509.CertificateBuilder
    ) -> x509.CertificateBuilder:
        """Adds extensions to the certificate builder"""
        for data in extensions_data:
            oid = data['oid']
            data_source = data.get('data_source', 'hex')

            if data_source == 'hex':
                ext_val = bytes.fromhex(data['value'])
            elif data_source == 'binary_file':
                filename = data['value']
                if not os.path.isabs(filename):
                    filename = os.path.join(self.cert_dir, filename)
                with open(filename, 'rb') as file:
                    ext_val = file.read()
            elif data_source == 'base64':
                ext_val = base64.b64decode(data['value'])
            else:
                raise ValueError(f'Unknown data source: {data_source}')

            extension = x509.UnrecognizedExtension(x509.ObjectIdentifier(oid),
                                                   ext_val)
            cert_builder = cert_builder.add_extension(
                extension, critical=data.get('critical', False))
        return cert_builder

    def generate(self, signing_key, password=None, rsa_padding=None):
        """Generates the X.509 certificate
        @param signing_key: Private key used to sign the certificate
        @param password: Password for the private key
        @param rsa_padding: Padding algorithm for RSA signature
        """
        issuer = self.cert_issuer(self.data.get('issuer'))
        subject = self.cert_subject(self.data.get('subject'))
        not_after, not_before = self.cert_validity_period(
            self.data.get('validity'))
        subject_public_key = self.cert_subject_public_key(
            self.data.get('subject_public_key'))
        serial_number = self.data.get('serial_number')

        if isinstance(signing_key, str):
            signing_key = load_private_key(signing_key, password=password)

        cert_builder = x509.CertificateBuilder().subject_name(subject)
        if issuer:
            cert_builder = cert_builder.issuer_name(issuer)
        if subject_public_key:
            cert_builder = cert_builder.public_key(subject_public_key)
        if serial_number:
            cert_builder = cert_builder.serial_number(int(str(serial_number)))
        cert_builder = cert_builder.not_valid_before(not_before)
        cert_builder = cert_builder.not_valid_after(not_after)
        cert_builder = self.add_cert_extensions(self.data['extensions'],
                                                cert_builder)
        self.certificate = cert_builder.sign(signing_key, hashes.SHA256(),
                                             rsa_padding=rsa_padding)
        return self.certificate

    def save_certificate(self, filename, encoding='pem'):
        """Saves the certificate to a file
        @param filename: Path to the file where the certificate will be saved
        @param encoding: Encoding format ('pem' or 'der')
        """
        if self.certificate is None:
            raise ValueError('Certificate not generated yet')

        if encoding.lower() == 'pem':
            encoding = serialization.Encoding.PEM
        elif encoding.lower() == 'der':
            encoding = serialization.Encoding.DER
        else:
            raise ValueError(f'Unknown encoding: {encoding}')

        with open(filename, 'wb') as f:
            f.write(self.certificate.public_bytes(encoding))
