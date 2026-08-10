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
import logging
import os
import sys

import click

from .cli import main, process_handler
from . import cli_psoc_c3

logger = logging.getLogger(__name__)


cmd_init = cli_psoc_c3.cmd_init
"""The 'init' command. Initializes a new project"""


@main.command('dfu', help='Device Firmware Update')
@click.option('-p', '--policy', type=click.Path(),
              help='Provisioning policy')
@click.option('-i', '--image', type=click.Path(),
              help='Firmware image', required=True)
@click.option('--key', '--key-path', type=click.Path(),
              help='OEM private key used to sign the DLM package')
@click.option('--probe-id', 'probe_id', type=click.STRING,
              default=None, help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_dfu(ctx, policy, image, key, probe_id, existing_packet,
                    testapps, testapps_si):
    """Executes provisioning packet generation and device provisioning"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        if policy:
            ctx.obj['TOOL'].policy = policy
        validate_args()
        validate_tool()
        testapps_type = test_pkg_type(testapps, testapps_si)

        result = True

        if not existing_packet:
            policy_type = ctx.obj['TOOL'].policy_parser.policy_type()
            if 'dfu' not in policy_type:
                logger.error('Invalid policy type "%s". '
                             '"dfu" policy is expected',
                             policy_type)
                return False
            result = ctx.obj['TOOL'].create_provisioning_packet(
                key=key, testapps=testapps_type
            )
            if result:
                result = ctx.obj['TOOL'].build_ramapp_package(
                    None, None, key=key, testapps=testapps_type
                )

        if result:
            result = ctx.obj['TOOL'].provision_device(
                probe_id=probe_id, ap='sysap', image=image,
                testapps=test_pkg_type(testapps, testapps_si))

        return result

    def validate_args():
        if not ctx.obj['TOOL'].policy:
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)
        validate_testapps_args(testapps, testapps_si)

    def validate_tool():
        if ctx.obj['TOOL'].tool.name != 'serial':
            sys.stderr.write("Error: DFU is available "
                             "through the serial interface only.\n")
            sys.exit(2)

    return process


@main.command('debug-token',
              help='Creates debug or RMA token based on template',
              short_help='Creates debug or RMA token based on template')
@click.option('-T', '--template', type=click.Path(), required=True,
              help='Path to the token template')
@click.option('--key', '--key-path', 'key', type=click.Path(),
              help='Private key path for signing the token')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The file where to save the token')
@click.pass_context
def cmd_debug_token(ctx, template, key, output):
    """Creates debug or RMA token based on template"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        result = ctx.obj['TOOL'].debug_certificate(template,
                                                   os.path.abspath(output),
                                                   key_path=key,
                                                   key_id=None,
                                                   non_signed=not bool(key))
        if result:
            logger.info("Debug token created in '%s'", os.path.abspath(output))
        return result is not None

    return process


@main.command('extract-iak',
              help='Creates Initial Attestation Key (IAK) '
                   'from RAM app response',
              short_help='Creates Initial Attestation Key')
@click.option('-i', '--input', 'infile', type=click.Path(), required=True,
              help='Input file')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The file where to save the key')
@click.pass_context
def cmd_extract_iak(ctx, infile, output):
    """Creates Initial Attestation Key"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        result = ctx.obj['TOOL'].extract_iak(infile, output)

        return result is not None

    return process


@main.command('integrity-cert', hidden=True,
              help='Creates integrity certificate')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The certificate path')
@click.option('-t', '--template', type=click.Path(), required=True,
              help='The path to device integrity template')
@click.option('--key', '--key-path', 'key', type=click.Path(),
              help='The key to sign the certificate')
@click.option('--algorithm', type=click.Choice(['ES512'], case_sensitive=False),
              help='The signature algorithm')
@click.option('--cert', type=click.Path(), hidden=True,
              help='The path to integrity certificate')
@click.pass_context
def cmd_integrity_cert(ctx, output, template, key, algorithm, cert):
    """Creates Integrity certificate"""
    @process_handler()
    def process():
        validate()
        if 'TOOL' not in ctx.obj:
            return False

        result = ctx.obj['TOOL'].integrity_cert(
            output, template=template, key=key, algorithm=algorithm, cert=cert)
        return result

    def validate():
        if key and algorithm:
            sys.stderr.write("Error: The '--key' and '--algorithm' options "
                             "are mutually exclusive.\n")
            sys.exit(2)
        if not (key or algorithm or cert):
            sys.stderr.write("Error: The '--key' or '--algorithm' option "
                             "must be specified .\n")
            sys.exit(2)

    return process


@main.command('create-provisioning-packet',
              help='Creates binary or CBOR packet for device provisioning')
@click.option('-p', '--policy', type=click.Path(), help='Provisioning policy')
@click.option('--key', '--key-path', type=click.Path(),
              help='The key used to sign the packet')
@click.option('--kid', help='The ID of the key used to verify the packet')
@click.option('--signature', type=click.Path(),
              help='Signature path to add to the message')
@click.option('--algorithm', type=click.Choice(['ES256', 'ES384', 'ES512'],
              case_sensitive=False), help='Signature algorithm')
@click.option('-o', '--output', help='The packet output path')
@click.option('--integrity-cert', type=click.Path(), hidden=True,
              help='The path to integrity exam certificate')
@click.option('--ifx-oem-cert', type=click.Path(),
              help='The path to OEM certificate')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_create_provisioning_packet(ctx, policy, key, kid,
                                   signature, algorithm, output,
                                   integrity_cert, ifx_oem_cert,
                                   testapps, testapps_si):
    """Creates provisioning packet (an input parameters for RAM applications"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        if policy:
            ctx.obj['TOOL'].policy = policy

        validate_args()

        if not integrity_cert:
            policy_type = ctx.obj['TOOL'].policy_parser.policy_type()
            if ((key or signature or algorithm) and
                    policy_type not in ('oem_provisioning', 'prot_fw_policy')):
                logger.error('Creating signed provisioning packet '
                             'is supported for '
                             '"oem_provisioning", "prot_fw_policy" only')
                return False
            if (not (key or signature or algorithm) and
                    policy_type == 'oem_provisioning'):
                logger.error('Signing provisioning packet is required for '
                             '"oem_provisioning" policy')
                return False

        return ctx.obj['TOOL'].create_provisioning_packet(
            key=key,
            kid=kid,
            algorithm=algorithm,
            signature=signature,
            output=output,
            testapps=test_pkg_type(testapps, testapps_si),
            integrity_cert=integrity_cert,
            ifx_oem_cert=ifx_oem_cert
        )

    def validate_args():
        if key and signature:
            sys.stderr.write("Error: The '--key-path' and '--signature' "
                             "options are mutually exclusive.\n")
            sys.exit(2)

        if key and algorithm:
            sys.stderr.write("Error: The '--algorithm' and '--key-path' "
                             "options are mutually exclusive.\n")
            sys.exit(2)

        if signature and not algorithm:
            sys.stderr.write("Error: The '--algorithm' must be specified when "
                             " '--signature' is provided.\n")
            sys.exit(2)

        if not (ctx.obj['TOOL'].policy or integrity_cert):
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)

        validate_testapps_args(testapps, testapps_si)

    return process


@main.command('provision-device', help='Executes device provisioning')
@click.option('-p', '--policy', type=click.Path(), help='Provisioning policy')
@click.option('--key', '--key-path', type=click.Path(),
              help='OEM private key used to sign the provisioning packet')
@click.option('--probe-id', 'probe_id', type=click.STRING, default=None,
              help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing')
@click.option('--ifx-oem-cert', type=click.Path(),
              help='The path to OEM certificate')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_provision_device(ctx, policy, key, probe_id,
                         existing_packet, ifx_oem_cert, testapps, testapps_si):
    """Executes provisioning packet generation and device provisioning"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        if policy:
            ctx.obj['TOOL'].policy = policy
        validate_args()
        testapps_type = test_pkg_type(testapps, testapps_si)

        result = True
        if not existing_packet:
            validate_key_and_policy_type()
            result = ctx.obj['TOOL'].create_provisioning_packet(
                key=key, testapps=testapps_type, ifx_oem_cert=ifx_oem_cert
            )
            if result:
                result = ctx.obj['TOOL'].build_ramapp_package(
                    None, None, key=key, testapps=testapps_type
                )

        if result:
            result = ctx.obj['TOOL'].provision_device(
                probe_id=probe_id, ap='sysap', testapps=testapps_type)

        return result

    def validate_args():
        if not ctx.obj['TOOL'].policy:
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)
        validate_testapps_args(testapps, testapps_si)

    def validate_key_and_policy_type():
        policy_type = ctx.obj['TOOL'].policy_parser.policy_type()
        if key and policy_type not in ('oem_provisioning', 'prot_fw_policy'):
            sys.stderr.write('Error: Signing provisioning packet is supported '
                             'for "oem_provisioning", "prot_fw_policy" only')
            sys.exit(2)

        if not key and policy_type == 'oem_provisioning':
            sys.stderr.write('Error: Missing option "--key". '
                             'Signing provisioning packet is required for ' 
                             '"oem_provisioning" policy')
            sys.exit(2)

    return process


test_pkg_type = cli_psoc_c3.test_pkg_type
"""Gets test package type based on a specified testapps flag"""


validate_testapps_args = cli_psoc_c3.validate_testapps_args
"""Validates testapps options"""
