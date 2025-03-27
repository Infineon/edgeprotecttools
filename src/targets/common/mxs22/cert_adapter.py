"""
Copyright 2025 Cypress Semiconductor Corporation (an Infineon company)
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

from .cert_validator_mxs22 import CertTemplateValidatorMXS22

logger = logging.getLogger(__name__)


class CertAdapter:
    """Adapter class to convert CLI arguments to certificate attributes"""

    def __init__(self, cert_version='1'):
        base_cert_info = CertTemplateValidatorMXS22()
        self.cert_base = base_cert_info.find_base_template(cert_version)

    def oem_csr(self, **kwargs):
        """Creates OEM CSR template"""
        return self.create_template('OEM_CSR', **kwargs)

    def oem_cert(self, **kwargs):
        """Creates OEM certificate template"""
        return self.create_template('OEM_CERT', **kwargs)

    def attr_map(self, template_type, **kwargs):
        """Map CSR or certificate attributes to the keyword arguments"""
        attrmap = {}
        for key, val in self.cert_base.items():
            if template_type in val.get('used', []):
                if key == 'TYPE' and kwargs.get('cert_type', ''):
                    attrmap[key] = 'cert_type'
                elif key == 'ID' and kwargs.get('cert_id', ''):
                    attrmap[key] = 'cert_id'
                else:
                    attrmap[key] = key.lower()
        return attrmap

    def create_template(self, template_type, **kwargs):
        """Creates CSR or certificate template"""
        template = {}
        attrmap = self.attr_map(template_type, **kwargs)

        for key, arg in attrmap.items():
            if arg in kwargs:
                value = kwargs.get(arg) if kwargs.get(arg) else ''
            else:
                value = self.cert_base[key].get('value', '')

            if 'ENUM' == self.cert_base[key].get('type'):
                value = value.upper()

            if 'description' in self.cert_base[key]:
                template[key] = {
                    'description': self.cert_base[key]['description'],
                    'value': value
                }
            else:
                template[key] = value
        template['TEMPLATE_TYPE'] = template_type

        logger.debug('Certificate template: %s', json.dumps(template, indent=2))

        return template
