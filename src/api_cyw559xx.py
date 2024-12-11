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
import os.path

from .api_common import CommonAPI
from .core.connect_helper import ConnectHelper
from .core.enums import ProvisioningStatus, ValidationStatus
from .core.strategy_context import ProvisioningContext
from .execute.ihex2hcd import hex2hcd
from .targets.cyw559xx.certs import (
    KeyCertificateGenerator, ContentCertificateGenerator, get_cert_config_parser
)
from .targets.cyw559xx.certs.validators import (
    CertConfigValidator, CertConfigAdvancedValidator
)
from .targets.cyw559xx.device_data import DeviceData
from .targets.cyw559xx.sign_tool import SignToolCYW559xx

logger = logging.getLogger(__name__)


class CYW559xxAPI(CommonAPI):
    """A class containing API for CYW559xx target"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def provision_device(self, probe_id=None, ap=None, **kwargs):
        """Executes device provisioning
        @param probe_id: N/A
        @param ap: N/A
        @return: True if success, otherwise False
        """
        status = ProvisioningStatus.FAIL
        if ConnectHelper.connect(self.tool, self.target):
            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.provision(self.tool, self.target)
        return status == ProvisioningStatus.OK

    def load_and_run_app(self, config):
        """Loads and runs application"""
        status = ProvisioningStatus.FAIL
        if ConnectHelper.connect(self.tool, self.target):
            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.provision(
                self.tool, self.target, config=config, existing_packet=True)
        return status == ProvisioningStatus.OK

    @staticmethod
    def secure_cert(config, output=None):
        """Generates secure Key or Content certificate
        @param config: Certificate configuration file
        @param output: Certificate output file
        @return: Certificate bytes
        """
        with open(config, 'r', encoding='utf-8') as file:
            try:
                cert_type = json.load(file)['certificate']['type']
            except (json.JSONDecodeError, KeyError) as e:
                logger.error("Invalid certificate configuration file '%s'",
                             os.path.abspath(config))
                logger.error(e.args[0])
                return None

        config_parser = get_cert_config_parser(cert_type, config)
        validator = CertConfigValidator(
            parser=config_parser,
            advanced_validator=CertConfigAdvancedValidator)
        is_config_valid = validator.validate(cert_type)
        if is_config_valid != ValidationStatus.OK:
            return None

        if cert_type == 'KEY_CERT':
            generator = KeyCertificateGenerator(config)
            cert_name = 'Key'
        elif cert_type == 'CONTENT_CERT':
            generator = ContentCertificateGenerator(config)
            cert_name = 'Content'
        else:
            logger.error("Invalid certificate type '%s'", cert_type)
            return None

        certificate = generator.generate()
        if output:
            with open(output, 'wb') as file:
                file.write(certificate)
            logger.info(f"{cert_name} certificate saved to '%s'",
                        os.path.abspath(output))
        return certificate

    @staticmethod
    def secure_image(image, certs, **kwargs):
        """Merges application image with the key and content certificates
        @param image: Image to merge with the certificates
        @param certs: List of certificate paths in DER format
        @return: Merged image object
        """
        if not certs:
            logger.error('No certificates specified')
            return None

        if len(certs) != 3:
            logger.error('3 certificates are required in the following order: '
                         'first key certificate, second key certificate, '
                         'content certificate')
            return None

        signed = SignToolCYW559xx.sign(image, certs, **kwargs)

        if signed:
            if kwargs.get('output'):
                logger.info("Saved image to '%s'",
                            os.path.abspath(kwargs.get('output')))
            if kwargs.get('hcd'):
                if kwargs.get('ota'):
                    raise ValueError('HCD is NA for OTA images')
                try:
                    hex2hcd(kwargs.get('output'), kwargs.get('hcd'))
                except (FileNotFoundError, RuntimeError) as e:
                    logger.error(e)
                    return None
                logger.info("Saved HCD file to '%s'",
                            os.path.abspath(kwargs.get('hcd')))
        return signed

    def get_csr(self, output, csr_id='0'):
        """Gets CSR data from the device"""
        if ConnectHelper.connect(self.tool, self.target):
            info = DeviceData(self.tool)
            return info.create_csr(output, csr_id)
        return False

    def read_soc_id(self, output):
        """Gets SOC ID"""
        if ConnectHelper.connect(self.tool, self.target):
            info = DeviceData(self.tool)
            return info.read_soc_id(output)
        return False
