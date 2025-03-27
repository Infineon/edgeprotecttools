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
from os.path import isfile, join

import jsonschema

from ....core.enums import ValidationStatus

logger = logging.getLogger(__name__)


class CertTemplateValidatorMXS22:
    """Validates cert template fields via the base certificate template"""
    def __init__(self):
        self.template_dir = os.path.join(
            os.path.dirname(__file__), 'base_cert_template')
        self.base_templates = [f for f in os.listdir(
            self.template_dir) if isfile(join(self.template_dir, f))]
        self.schemas_dir = os.path.join(
            os.path.dirname(__file__), 'schemas')
        self.cert_schemas = [f for f in os.listdir(
            self.schemas_dir) if isfile(join(self.schemas_dir, f))]

    def validate(self, cert_data, csr):
        """Validate certificate template fields
        @param cert_data: Dictionary with the CSR or certificate data
        @param csr: The CSR path
        @return: Update base template data if success
        """
        if self.validate_by_schema(cert_data) == ValidationStatus.ERROR:
            raise ValueError(
                'Certificate template validation against schema failed')

        cert_type = cert_data.get('TEMPLATE_TYPE')
        if self.is_csr_required(cert_type) and not csr:
            raise ValueError(f"CSR must be provided to generate '{cert_type}'")
        base_data = self.validate_advanced(cert_data)

        if cert_type == 'OEM_CSR' and not cert_data['PUBLIC_KEY_0'].get(
                'value'):
            raise ValueError('Public key 0 is required for OEM CSR')

        return base_data

    @staticmethod
    def is_csr_required(cert_type):
        """Checks dependency on CSR usage"""
        if cert_type in ('OEM_CERT', 'DEVICE_CERT'):
            return True
        return False

    def validate_advanced(self, cert_data):
        """Validates certificate template fields against cert_base_template
        and updates cert_base_template data
        """
        version = cert_data.get('VERSION')
        base_data = self.find_base_template(version)
        template_type = cert_data.get('TEMPLATE_TYPE')
        for key, val in cert_data.items():
            try:
                if template_type in base_data[key]['used']:
                    if isinstance(val, dict):
                        base_data[key]['value'] = val.get('value')
                    else:
                        base_data[key]['value'] = val
                else:
                    raise KeyError(
                        f"Unexpected key '{template_type}' in '{key}'")
            except KeyError as ex:
                raise KeyError(
                    f'Unexpected certificate key name: {key}') from ex
        return base_data

    def find_base_template(self, version):
        """Finds cert_base_template by the cert template version"""
        for name in self.base_templates:
            base_path = os.path.abspath(os.path.join(self.template_dir, name))
            with open(base_path, 'r', encoding='utf-8') as f:
                base_data = json.load(f)
            base_version = base_data.get('VERSION')
            if version == base_version.get('value'):
                logger.debug('Load base certificate template: %s', base_path)
                break
        else:
            raise ValueError('Incompatible certificate template version')
        return base_data

    def validate_by_schema(self, template_data):
        """Validates certificate template against JSON schema"""
        cert_type = template_data.get('TEMPLATE_TYPE')

        for schema_name in self.cert_schemas:
            schema_path = os.path.abspath(
                os.path.join(self.schemas_dir, schema_name))
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
            if schema.get('title') == cert_type:
                logger.debug('Used schema %s', schema_path)
                break
        else:
            raise ValueError(f"Failed to load schema for '{cert_type}'")

        status = ValidationStatus.OK
        logger.debug("Validate template against schema '%s'", schema_path)

        try:
            jsonschema.validate(template_data, schema)
            logger.debug('Validation against schema succeed')
        except (jsonschema.exceptions.ValidationError,
                jsonschema.exceptions.SchemaError) as e:
            logger.error('Validation against schema failed')
            logger.error(e.message)
            logger.debug(e)
            status = ValidationStatus.ERROR
        return status
