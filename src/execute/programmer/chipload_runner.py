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
import os
import subprocess
import logging
import platform

import serial

from ...execute.programmer.hci_commands import OPCode, OPResponse

logger = logging.getLogger(__name__)


class ChipLoadRunner:
    """The class is responsible for running the ChipLoad application.
    Based on the user configuration it provides input parameters for
    the serial interface protocols. Also parses the application output
    and provides the output consistent with the package
    """

    executable = 'ChipLoad'

    def __init__(self, settings):
        self.tool_path = settings.ocd_path
        self.serial_config = settings.serial_config()
        self.serial_port = self.serial_config.get('hwid')

        if self.serial_port is None:
            raise ValueError('Serial port not specified')

        if platform.system() not in ['Windows', 'Linux', 'Darwin']:
            raise ValueError(f'Unsupported OS platform: {platform.system()}')

        self.serial = None

    def run(self, image, launch_addr, **kwargs):
        """Executes the ChipLoad application
        @param image: List of arguments
        @param launch_addr: Indicates whether to add the
            arguments for the currently selected protocol
        @return: True if success or False
        """
        if os.path.isdir(self.tool_path):
            os_name = platform.system()

            if os_name not in ['Windows', 'Linux', 'Darwin']:
                raise ValueError(f'Unsupported OS platform: {os_name}')

            if os_name == 'Windows':
                f_name = self.executable + '.exe'
            else:
                f_name = self.executable

            exec_path = os.path.abspath(os.path.join(self.tool_path, f_name))
        else:
            exec_path = os.path.abspath(self.tool_path)

        self.init_serial()

        status = False
        if self.check_connected():
            if self.device_in_dm_state():
                status = self.init_load_session()
            else:
                logger.error('Failed to check device state')
        self.serial.close()

        if status:
            btp_config = kwargs.get('btp_config')
            command = self.create_command(exec_path, image, launch_addr,
                                          btp_config)
            command_line = ' '.join(command)
            logger.debug('Execute command: %s', command_line)
            result = subprocess.run(command, capture_output=True, check=False)
            if result.returncode != 0:
                self.check_result_and_log(result.stdout, None)
                self.check_result_and_log(result.stderr, None)
            else:
                status = self.check_result_and_log(
                    result.stdout, 'Current state: Completed successfully')
        if status:
            self.init_serial()
            status = self.is_app_executed()
            self.serial.close()
        return status

    def check_connected(self, attempts=5):
        """Check connection by the reset response"""
        attempt = 0
        while attempt < attempts:
            res = self.send_receive(bytes.fromhex(OPCode.RESET), size=7)
            if res == bytes.fromhex(OPResponse.RESET):
                return True
            attempt += 1
            logger.debug('Attempt to receive to HCI reset response failed')
        logger.error(
            'The maximum number of connection attempts has been reached')
        logger.info('Make sure that the device is in HCI mode')
        return False

    def device_in_dm_state(self):
        """Checks if device is in DM state"""
        commands = [
            (OPCode.READ_SUPPORTED_VCS, OPResponse.READ_SUPPORTED_VCS)
        ]
        return self.run_commands(commands)

    def init_load_session(self):
        """Switching the device into download mode"""
        commands = [
            (OPCode.RESET, OPResponse.RESET),
            (OPCode.ENTER_DOWNLOAD_MODE, OPResponse.ENTER_DOWNLOAD_MODE),
            (OPCode.RESET, OPResponse.RESET),
            OPCode.READ_LOCAL_NAME
        ]
        return self.run_commands(commands)

    def is_app_executed(self):
        """Checks if MiniDriver app executed successfully"""
        commands = [
            (OPCode.RESET, OPResponse.DOWNLOAD_MINIDRIVER)
        ]
        return self.run_commands(commands)

    def run_commands(self, commands):
        """Sends HCI commands to device and checks responses"""
        for command in commands:
            if isinstance(command, tuple):
                res = self.send_receive(
                    bytes.fromhex(command[0]), bytes.fromhex(command[1]))
                if not res:
                    return False
            else:
                self.send_receive(bytes.fromhex(command))
        return True

    def send_receive(
            self, message: bytes, exp_result=None, timeout=1, size=1000):
        """Sends data to serial and returns response data"""
        self.serial.timeout = timeout
        self.serial.write(message)
        logger.debug('Send: %s', message.hex())
        received = self.serial.read(size)
        if received:
            logger.debug('Response: %s', received.hex())
        if exp_result and received != exp_result:
            self.serial.close()
            logger.error('Unexpected HCI response')
            logger.error('Unknown device state')
            return False
        return received

    def init_serial(self):
        """Creates serial port communication"""
        comm = self.comm_args()
        if self.serial:
            self.serial.close()
        self.serial = serial.Serial(
            comm.get('port_name'), comm.get('baudrate'), timeout=1)

    @staticmethod
    def check_result_and_log(info_data, find_msg=None, print_output=True):
        """Logs the messages from info_data and displays
        find_msg if it matches with the data in the line
        """
        status = False
        info = info_data.decode()
        if info:
            lines = info.splitlines()
            for line in lines:
                if find_msg and find_msg in line and print_output:
                    logger.info(find_msg)
                    status = True
                logger.debug(line)
        return status

    def create_command(self, exec_path, image, launch_addr, btp):
        """Create ChipLoad protocol arguments"""
        comm = self.comm_args()
        command = [exec_path]
        no_val_opts = [
            '-BLUETOOLMODE',
            '-NODLMINIDRIVER',
            '-NOERASE',
            '-NOVERIFY'
        ]
        command.extend(no_val_opts)
        val_opts = {
            '-CONFIG': image,
            '-BTP': btp,
            '-LAUNCHADDRESS': hex(launch_addr),
            '-PORT': comm.get('port_name'),
            '-BAUDRATE': comm.get('baudrate')
        }
        for itm, val in val_opts.items():
            if val:
                command.extend([itm, str(val)])
        return command

    def comm_args(self):
        """Gets arguments for communication protocol"""
        uart = self.serial_config.get('uart')
        if uart:
            comm_settings = {
                'port_name': self.serial_config.get('hwid'),
                'baudrate': uart.get('baudrate')
            }
            return comm_settings
        raise ValueError('UART configuration not defined')

    def hci_run(self, command, timeout):
        """Executes HCI commands and returns received data"""
        data = None
        self.init_serial()
        status = self.check_connected()
        if status:
            data = self.send_receive(command, timeout=timeout)
        self.serial.close()
        return data
