"""
Copyright 2023-2024 Cypress Semiconductor Corporation (an Infineon company)
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
import logging
import os
import sys

import click

from .cli import main, process_handler
from . import cli_mxs40sv2

logger = logging.getLogger(__name__)


cmd_init = cli_mxs40sv2.cmd_init
"""The 'init' command. Initializes a new project"""

cmd_load_and_run_app = cli_mxs40sv2.cmd_load_and_run_app
"""The 'load-and-run-app' command. Loads and runs RAM application"""


@main.command('integrity-cert', hidden=True,
              help='Creates integrity certificate')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The certificate path')
@click.option('-t', '--template', type=click.Path(), required=True,
              help='The path to device integrity template')
@click.option('--key', '--key-path', 'key', type=click.Path(),
              help='The key to sign the certificate')
@click.option('--algorithm', type=click.Choice(['ES256'], case_sensitive=False),
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


@main.command('integrity-exam', help='Executes device integrity check')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing')
@click.option('--cert', type=click.Path(), required=True,
              help='The path to integrity certificate')
@click.option('--custom-regions', type=click.Path(),
              help='The path to integrity custom regions template')
@click.option('--key', '--key-path', 'key', type=click.Path(),
              help='The key to sign the DLM package')
@click.option('--probe-id', 'probe_id', help='Probe serial number')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_integrity_exam(ctx, existing_packet, cert, custom_regions,
                       probe_id, key, testapps, testapps_si):
    """Executes Device Integrity Exam"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        return ctx.obj['TOOL'].integrity_exam(
            probe_id, existing_packet=existing_packet, key=key,
            integrity_cert=cert, custom_regions=custom_regions,
            testapps=test_pkg_type(testapps, testapps_si))

    return process


@main.command('integrity-verify-response', hidden=True,
              help='Verify integrity exam app response')
@click.option('--cert', type=click.Path(), required=True,
              help='The path to integrity certificate')
@click.option('--custom-regions', type=click.Path(),
              help='The path to integrity custom regions template')
@click.option('--in-params', type=click.Path(), required=True,
              help='The path to integrity exam app in params data')
@click.option('--out-results', type=click.Path(), required=True,
              help='The path to integrity exam app response data')
@click.pass_context
def cmd_verify_integrity_response(ctx, cert, custom_regions,
                                  in_params, out_results):
    """Integrity exam app response verification"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        return ctx.obj['TOOL'].integrity_verify_response(
            cert, in_params, out_results, custom_regions=custom_regions
        )

    return process


@main.command('create-provisioning-packet',
              help='Creates binary packet for device provisioning')
@click.option('-p', '--policy', type=click.Path(), help='Provisioning policy')
@click.option('--key', '--key-path', type=click.Path(),
              help='The key used to sign the packet')
@click.option('-o', '--output', help='The packet output path')
@click.option('--integrity-cert', type=click.Path(), hidden=True,
              help='The path to integrity exam certificate')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_create_provisioning_packet(ctx, policy, key, output,
                                   integrity_cert, testapps, testapps_si):
    """Creates provisioning packet (an input parameters for
    RAM applications
    """
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        if policy:
            ctx.obj['TOOL'].policy = policy

        validate_args()

        return ctx.obj['TOOL'].create_provisioning_packet(
            key=key,
            output=output,
            testapps=test_pkg_type(testapps, testapps_si),
            integrity_cert=integrity_cert
        )

    def validate_args():
        if not (ctx.obj['TOOL'].policy or integrity_cert):
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)

        validate_testapps_args(testapps, testapps_si)

    return process


@main.command('prot-fw-dfu', help='Executes prot-fw flow')
@click.option('-p', '--policy', type=click.Path(),
              help='Provisioning policy')
@click.option('-i', '--image', type=click.Path(),
              help='Protected FW image', required=True)
@click.option('--key', '--key-path', type=click.Path(),
              help='OEM private key used to sign the DLM package')
@click.option('--probe-id', 'probe_id', type=click.STRING,
              default=None, help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_prot_fw_dfu(ctx, policy, image, key, probe_id, existing_packet,
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
            if 'prot_fw_dfu' not in policy_type:
                logger.error('Invalid policy type "%s". '
                             '"prot_fw_dfu" policy is expected',
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
            sys.stderr.write("Error: Protected FW update is available "
                             "through the serial interface only.\n")
            sys.exit(2)

    return process


@main.command('provision-device', help='Executes device provisioning')
@click.option('-p', '--policy', type=click.Path(), help='Provisioning policy')
@click.option('--key', '--key-path', type=click.Path(),
              help='OEM private key used to sign the provisioning packet')
@click.option('--probe-id', 'probe_id', type=click.STRING, default=None,
              help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_provision_device(ctx, policy, key, probe_id,
                         existing_packet, testapps, testapps_si):
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
            policy_type = ctx.obj['TOOL'].policy_parser.policy_type()
            if 'reprovisioning' in policy_type:
                logger.error('Reprovisioning policy type specified for '
                             'the provisioning operation')
                return False

            if key and 'prot_fw_policy' not in policy_type:
                logger.error('Signing provisioning packet '
                             'is supported for "prot_fw_policy" only')
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
                probe_id=probe_id, ap='sysap', testapps=testapps_type)

        return result

    def validate_args():
        if not ctx.obj['TOOL'].policy:
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)
        validate_testapps_args(testapps, testapps_si)

    return process


@main.command('reprovision-device', help='Executes device reprovisioning')
@click.option('-p', '--policy', type=click.Path(), help='Provisioning policy')
@click.option('--key', '--key-path', type=click.Path(),
              help='OEM private key used to sign the reprovisioning packet')
@click.option('--probe-id', help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip reprovisioning packet creation and use the existing')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_re_provision_device(ctx, policy, key, probe_id,
                            existing_packet, testapps, testapps_si):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False

        if policy:
            ctx.obj['TOOL'].policy = policy

        validate_args()
        validate_policy_type()
        testapps_type = test_pkg_type(testapps, testapps_si)

        result = True
        if not existing_packet:
            result = ctx.obj['TOOL'].create_provisioning_packet(
                key=key, testapps=testapps_type)
            if result:
                result = ctx.obj['TOOL'].build_ramapp_package(
                    None, None, key=key, testapps=testapps_type)

        if result:
            result = ctx.obj['TOOL'].re_provision_device(
                probe_id, testapps=testapps_type)
        return result

    def validate_args():
        if not ctx.obj['TOOL'].policy:
            sys.stderr.write("Error: Missing option '--policy'.\n")
            sys.exit(2)
        if not existing_packet and not key:
            sys.stderr.write("Error: Missing option '--key'.\n")
            sys.exit(2)

        validate_testapps_args(testapps, testapps_si)

    def validate_policy_type():
        policy_type = ctx.obj['TOOL'].policy_parser.policy_type()
        if 'reprovisioning' not in policy_type:
            sys.stderr.write('Error: Provisioning policy type specified for '
                             'the reprovisioning operation\n')
            sys.exit(2)

    return process


@main.command('debug-token',
              help='Creates debug or RMA token based on template',
              short_help='Creates debug or RMA token based on template')
@click.option('-T', '--template', type=click.Path(), required=True,
              help='Path to the token template')
@click.option('--key', '--key-path', 'key', type=click.Path(), required=True,
              help='Either a private key path for signing the token '
                   'or a public key to be added to the token')
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
                                                   non_signed=False)
        if result:
            logger.info("Debug token created in '%s'", os.path.abspath(output))
        return result is not None

    return process


@main.command('transit-to-rma', help='Transition device to RMA lifecycle stage')
@click.option('-c', '--cert', '--token', 'cert', type=click.Path(),
              required=True, help='Token for transition into RMA LCS')
@click.option('--key', '--key-path', type=click.Path(), required=True,
              help='OEM private key used to sign the DLM package')
@click.option('--probe-id', default=None, help='Probe serial number')
@click.option('--testapps', is_flag=True, hidden=True)
@click.option('--testapps-si', is_flag=True, hidden=True)
@click.pass_context
def cmd_convert_to_rma(ctx, cert, key, probe_id, testapps, testapps_si):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        validate_testapps_args(testapps, testapps_si)
        testapps_type = test_pkg_type(testapps, testapps_si)

        result = ctx.obj['TOOL'].build_ramapp_package(
            None, None, key=key, flow_name='rma', testapps=testapps_type,
            input_params=cert)

        if result:
            return ctx.obj['TOOL'].transit_to_rma(
                cert=cert, probe_id=probe_id,
                testapps=test_pkg_type(testapps, testapps_si))

    return process


test_pkg_type = cli_mxs40sv2.test_pkg_type
"""Gets test package type based on a specified testapps flag"""


validate_testapps_args = cli_mxs40sv2.validate_testapps_args
"""Validates testapps options"""

