"""
Copyright 2019-2025 Cypress Semiconductor Corporation (an Infineon company)
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
from .cyprov_entity import Entity
from .cyprov_crypto import Crypto


class CustomerEntity(Entity):
    def __init__(self, state_name, audit_name):
        Entity.__init__(self, state_name, audit_name)

    def create_entity(self, kid):
        """
        Creates the Customer entity.
        Creates the Customer main key-pair and returns nothing.
        """
        customer_priv_key, customer_pub_key = Crypto.create_jwk()
        customer_priv_key["kid"] = str(kid)
        customer_pub_key["kid"] = str(kid)
        self.state["custom_priv_key"] = customer_priv_key
        self.state["custom_pub_key"] = customer_pub_key
        self.state_loaded = True
    
    def get_pub_key(self):
        if "custom_pub_key" not in self.state:
            key = dict(self.state["custom_priv_key"])
            del key["d"]
        else:
            key = self.state["custom_pub_key"]
        return key
