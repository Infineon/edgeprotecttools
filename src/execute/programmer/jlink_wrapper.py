# (c) 2026, Infineon Technologies AG, or an affiliate of Infineon
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
"""Segger J-Link programmer wrapper.

Implements :class:`ProgrammerBase` on top of ``pylink-square``,
providing direct communication with a J-Link probe through the
``JLinkARM`` shared library.
"""

import json
import logging
import os
import time
from enum import IntEnum, IntFlag
from typing import Optional

import pylink as _pylink
from intelhex import IntelHex
from pylink.errors import JLinkException

from .base import AP, Interface, ProgrammerBase, ResetType
from ...core.progress_bar import update_progress

TARGET_MAP = os.path.join(os.path.dirname(__file__), 'jlink_target_map.json')
logger = logging.getLogger(__name__)


def _jlink_log_handler(msg: str) -> None:
    """Handle log messages from the J-Link DLL.

    Redirects J-Link DLL output to our logger at debug level instead of
    printing to stdout. This suppresses verbose messages like
    'Device "PSC3P6F" selected.' from appearing in normal output.
    """
    if msg:
        # Strip trailing newline if present
        msg = msg.rstrip('\n')
        if msg:
            logger.debug('J-Link DLL: %s', msg)


# -----------------------------------------------------------------------------
# CoreSight DAP constants (APv2 / SoC-600 architecture)
# -----------------------------------------------------------------------------


class APIndex(IntEnum):
    """Access Port indices for PSoC C3x6.

    SYS (0): System Access Port
    CM33 (1): Cortex-M33 Access Port
    """

    SYS = 0
    CM33 = 1


class APv2Reg(IntEnum):
    """APv2 register offsets.

    CSW (0xD00): Control/Status Word
    TAR (0xD04): Transfer Address Register
    DRW (0xD0C): Data Read/Write
    """

    CSW = 0xD00
    TAR = 0xD04
    DRW = 0xD0C


class DPReg(IntEnum):
    """DP register indices (for JLINKARM_CORESIGHT_*DAP functions)."""

    ABORT = 0
    CTRL_STAT = 1
    SELECT = 2
    RDBUFF = 3


class DPCtrl(IntFlag):
    """DP.CTRL/STAT bits."""

    CSYSPWRUPREQ = 1 << 30
    CDBGPWRUPREQ = 1 << 28
    POWER_UP = CSYSPWRUPREQ | CDBGPWRUPREQ


class DPAbort(IntFlag):
    """DP.ABORT bits."""

    ORUNERRCLR = 1 << 4
    WDERRCLR = 1 << 3
    STKERRCLR = 1 << 2
    STKCMPCLR = 1 << 1
    CLEAR_ALL = ORUNERRCLR | WDERRCLR | STKERRCLR | STKCMPCLR


class APCsw(IntFlag):
    """AP.CSW bits."""

    PROT_SECURE = 0x0B << 24
    PROT_NONSECURE = 0x4B << 24
    SDEVICE_EN = 1 << 23
    ADDRINC_OFF = 0 << 4
    ADDRINC_SINGLE = 1 << 4
    SIZE_WORD = 2


class APAddr(IntEnum):
    """Access Port base addresses (APv2 architecture)."""

    SYS = 0xF0000000
    CM33 = 0xF0002000

# DP.SELECT mask
DP_SELECT_MASK = 0xFFFFFFF0


class AddrMask(IntEnum):
    """TrustZone address masks (bit 28 aliasing)."""

    SECURE = 0x10000000
    NON_SECURE = 0xEFFFFFFF


class DomainTestAddr(IntEnum):
    """Domain detection addresses (SRSS BOOT_STATUS - accessible via SysAP).

    Used to determine security domain by probing memory access.
    """

    SECURE = 0x52400418
    NON_SECURE = SECURE & AddrMask.NON_SECURE


class DomainCheckRange(IntEnum):
    """Address range where TrustZone S/NS aliasing applies (peripheral space).

    0x40000000-0x4FFFFFFF = Non-secure peripheral alias
    0x50000000-0x5FFFFFFF = Secure peripheral alias
    """

    MIN = 0x40000000
    MAX = 0x5FFFFFFF


class Jlink(ProgrammerBase):
    """J-Link wrapper using pylink-square.

    Communicates directly with the JLinkARM shared library via
    pylink-square, bypassing OpenOCD entirely.
    """

    def __init__(self, name: str, settings) -> None:
        """Initialize the wrapper."""
        super().__init__(name, path=None, require_path=False)
        speed = settings.adapter_speed_khz if settings else None
        self.speed_khz: int = int(speed) if speed is not None else 1000
        self.probe_id = None
        self._jlink = None
        self.current_ap: AP = AP.SYS
        self._device_name: Optional[str] = None
        # DAP state tracking
        self._dp_select_last: int = 0xFFFFFFFF
        self._current_ap_index: int = APIndex.SYS
        # Track if device has been configured with J-Link
        # (to avoid redundant messages)
        self._device_configured: bool = False
        # Reconnect timing parameters
        self.reconnect_wait_ms: int = 50
        self.reconnect_timeout_ms: int = 3000

        # Domain security checking for TrustZone-enabled devices (e.g., PSE84)
        # When enabled, addresses are adjusted based on CPU's current domain
        # Set automatically based on target map during connect()
        self.check_domain_security: bool = False
        self._domain_secure: Optional[bool] = None
        # Tracks if domain detection failed
        self._domain_detect_failed: bool = False

    def connect(
        self,
        target_name: Optional[str] = None,
        interface: Optional[Interface] = None,
        probe_id: Optional[str] = None,
        ap: str = 'sysap',
        acquire: bool = True,
        power: Optional[str] = None,
        voltage: Optional[int] = None,
        rev: Optional[str] = None,
    ) -> bool:
        """Connect to the target via J-Link.

        Connects to the device and initializes direct SysAP access via
        CoreSight. InitTarget() may run and fail if CM33 AP is closed,
        but the connection continues using SysAP for register access.

        @param target_name: Target name; looked up in
            ``jlink_target_map.json``.
        @param interface: Accepted for API compatibility; not used.
            Only SWD is supported.
        @param probe_id: J-Link probe ID.  When ``None`` the
            first detected probe is used.
        @param ap: Accepted for API compatibility; not used.
            Always uses SysAP for register access.
        @param acquire: Run device acquisition sequence.
        @param power: Accepted for API compatibility; not used.
        @param voltage: Accepted for API compatibility; not used.
        @param rev: Optional silicon revision suffix.
        @return: ``True`` on success.
        @raises ImportError: When ``pylink-square`` is not installed.
        @raises ValueError: When ``target_name`` is missing or not
            found in the J-Link target map.
        """
        if _pylink is None:
            raise ImportError(
                'pylink-square is required for J-Link support. '
                'Install it with: pip install pylink-square'
            )
        if target_name is None:
            raise ValueError("Parameter 'target_name' is required")

        full_name = f'{target_name}_{rev}' if rev else target_name
        if not self._device_name:
            config = (
                self._lookup_target_config(full_name)
                or self._lookup_target_config(target_name)
            )
            if config:
                self._device_name = config.get('device')
                # Enable domain security checking if specified in target map
                if config.get('check_domain_security'):
                    self.check_domain_security = True
                    logger.info('Domain security checking enabled for %s',
                                target_name)
        if not self._device_name:
            raise ValueError(
                f"Target '{target_name}' not found in J-Link target"
                f' map ({TARGET_MAP}).  Add an entry to'
                ' jlink_target_map.json'
            )

        self.current_ap = AP.SYS
        iface = Interface.SWD
        speed_khz = self.speed_khz

        self._jlink = _pylink.JLink(log=_jlink_log_handler)
        self._open_probe(probe_id)
        self.probe_id = probe_id
        self._configure_interface(iface, speed_khz)

        # Connect to the device. InitTarget() will run but may fail if
        # CM33 AP is closed. We catch the failure and continue with
        # direct SysAP access via CoreSight.
        logger.info('Connecting to device via J-Link')
        if not self._connect_sysap_only(timeout_ms=5000):
            raise RuntimeError(
                'Failed to connect to SysAP. '
                'Check that the device is powered and connected'
            )
        self._patch_target_connected()

        if acquire:
            self._acquire()

        logger.info(
            "J-Link connected to '%s' (device: %s, interface: %s,"
            ' speed: %d kHz, probe: %s)',
            target_name, self._device_name, iface.name,
            speed_khz, probe_id or 'auto',
        )
        return True

    def disconnect(self) -> None:
        """Close the active J-Link connection."""
        if self._jlink is None:
            return
        try:
            self._jlink.close()
        finally:
            self._jlink = None
            self._device_configured = False

    def halt(self) -> None:
        """Halt the CPU core (CM33 AP only, not supported via SysAP).

        @raises NotImplementedError: Always, as CPU control requires
            CM33 AP access which is not available in SysAP-only mode.
        """
        raise NotImplementedError('CPU halt requires CM33 AP (not available)')

    def resume(self) -> None:
        """Resume CPU execution (CM33 AP only, no-op via SysAP).

        In SysAP-only mode, the app starts automatically when
        TST_DEBUG_CTL is cleared, so this is a no-op.
        """
        logger.debug('resume: no-op (app starts via TST_DEBUG_CTL)')

    def reset_and_halt(
        self, reset_type: ResetType = ResetType.SW
    ) -> None:
        """N/A for JLink"""
        raise NotImplementedError

    def reset(
            self, reset_type: ResetType = ResetType.HW, delay_ms: int = 100
    ) -> bool:
        """Perform a hardware reset via the J-Link reset pin.

        After reset, attempts to reconnect. If reconnection fails (e.g.
        debug AP disabled after provisioning), the reset is still
        considered successful.

        @param delay_ms: Time to hold reset pin low in milliseconds.
        @return: True on successful reset, False only if pin control fails.
        """
        logger.info('Performing hardware reset via J-Link reset pin')

        # Invalidate DAP state before reset
        self._dp_select_last = 0xFFFFFFFF
        self._current_ap_index = -1
        self._domain_secure = None
        self._domain_detect_failed = False

        try:
            # Assert reset (drive nRESET low)
            self._jlink.set_reset_pin_low()
            logger.debug('Reset pin asserted (low)')

            # Hold reset for specified duration
            time.sleep(delay_ms / 1000.0)

            # Deassert reset (release nRESET high)
            self._jlink.set_reset_pin_high()
            logger.debug('Reset pin deasserted (high)')

        except JLinkException as exc:
            logger.error('Hardware reset pin control failed: %s', exc)
            raise RuntimeError(f'Hardware reset failed: {exc}') from exc

        # Wait for device to stabilize after hardware reset
        time.sleep(self.reconnect_wait_ms / 1000.0)

        # Try to reconnect (best effort - failure is OK)
        if self._try_reconnect_after_reset():
            return True

        # Reconnection failed - device may have debug AP disabled
        # This is expected after some provisioning flows
        logger.info('Hardware reset complete (device not accessible via debug)')
        return True

    def _try_reconnect_after_reset(self) -> bool:
        """Attempt to reconnect after hardware reset.

        @return: True if reconnected successfully, False otherwise.
        """
        logger.debug('Attempting to reconnect after hardware reset...')

        self._patch_target_connected()

        # Run acquisition sequence if defined for this target
        self._acquire()

        # Perform SWD line reset
        self._swd_line_reset()

        # Ensure device is configured
        self._ensure_device_configured()

        # Configure CoreSight
        if not self._configure_coresight():
            return False

        # Try to reconnect - use full reconnect timeout since hardware reset
        # may require longer recovery time than software reset
        start = time.time()
        timeout_s = self.reconnect_timeout_ms / 1000.0

        while (time.time() - start) < timeout_s:
            try:
                # Clear sticky errors
                try:
                    self._jlink.coresight_write(
                        DPReg.ABORT, DPAbort.CLEAR_ALL, ap=False)
                except JLinkException:
                    pass

                # Power up DAP
                self._jlink.coresight_write(
                    DPReg.CTRL_STAT, DPCtrl.POWER_UP, ap=False)

                # Invalidate SELECT cache
                self._dp_select_last = 0xFFFFFFFF

                # Try to read SysAP CSW to verify access
                csw = self._read_apv2(APIndex.SYS, APv2Reg.CSW)
                if csw is not None:
                    prot = self._get_csw_prot(csw)
                    csw_val = prot | APCsw.ADDRINC_OFF | APCsw.SIZE_WORD
                    if self._write_apv2(APIndex.SYS, APv2Reg.CSW, csw_val) >= 0:
                        self._current_ap_index = APIndex.SYS
                        self._domain_secure = None
                        logger.info(
                            'Hardware reset complete, reconnected '
                            '(CSW=0x%08X)', csw_val)
                        return True

            except JLinkException as exc:
                logger.debug('Reconnect attempt failed: %s', exc)

            time.sleep(0.010)

        return False


    def set_frequency(self, value_khz: int) -> None:
        """Set the probe communication speed.

        @param value_khz: Speed in kHz.
        """
        logger.debug('set_frequency (%d kHz)', value_khz)
        self._jlink.set_speed(value_khz)

    def get_ap(self) -> AP:
        """Return the currently selected access port."""
        return self.current_ap

    def set_ap(self, ap: AP) -> None:
        """Set the active access port.

        Only SysAP is supported. Other AP values are accepted for API
        compatibility but will log a warning.

        @param ap: Target access port.
        """
        if ap != AP.SYS:
            logger.warning(
                'J-Link wrapper only supports SysAP; ignoring ap=%s', ap
            )
        # Always use SysAP
        if self._current_ap_index != APIndex.SYS:
            logger.debug('Initializing SysAP')
            self.init_sysap()
        self.current_ap = AP.SYS

    def read32(self, address: int) -> int:
        """Read a 32-bit value from memory via SysAP.

        @param address: 4-byte-aligned memory address.
        @return: Integer value.
        @raises ValueError: When *address* is not 4-byte aligned.
        """
        if address & 0x03:
            raise ValueError('Address not aligned')

        # Adjust address for security domain if checking is enabled
        adjusted_addr = self._adjust_address_for_domain(address)

        value = self.sysap_read32(adjusted_addr)
        if value is None:
            # Try to reconnect (may have been a soft reset)
            logger.debug('SysAP read failed, attempting reconnect...')
            if self.reconnect():
                value = self.sysap_read32(adjusted_addr)
            if value is None:
                raise RuntimeError(f'SysAP read failed at 0x{adjusted_addr:08X}')
        return value

    def read(self, address: int, length: int) -> list:
        """Read a block of bytes via SysAP.

        @param address: Start address.
        @param length: Number of bytes to read.
        @return: List of byte values.
        """
        data = self._read_block_via_sysap(address, length)
        return list(data)

    def read8(self, address: int) -> int:
        """N/A for JLink"""
        raise NotImplementedError

    def read16(self, address: int) -> int:
        """N/A for JLink"""
        raise NotImplementedError

    def write8(self, address: int, value: int) -> None:
        """N/A for JLink"""
        raise NotImplementedError

    def write16(self, address: int, value: int) -> None:
        """N/A for JLink"""
        raise NotImplementedError

    def write32(self, address: int, value: int) -> None:
        """Write a 32-bit value to memory via SysAP.

        @param address: 4-byte-aligned memory address.
        @param value: 32-bit value.
        @raises ValueError: When *address* is not 4-byte aligned.
        """
        if address & 0x03:
            raise ValueError('Address not aligned')

        # Adjust address for security domain if checking is enabled
        adjusted_addr = self._adjust_address_for_domain(address)

        if not self.sysap_write32(adjusted_addr, value):
            # Try to reconnect (may have been a soft reset)
            logger.debug('SysAP write failed, attempting reconnect...')
            if self.reconnect():
                if not self.sysap_write32(adjusted_addr, value):
                    raise RuntimeError(
                        f'SysAP write failed at 0x{adjusted_addr:08X}')
            else:
                raise RuntimeError(
                    f'SysAP write failed at 0x{adjusted_addr:08X}')

    def write(self, address: int, data) -> None:
        """Write a block of bytes via SysAP.

        @param address: Start address.
        @param data: Iterable of byte values.
        """
        self._write_block_via_sysap(address, bytes(data))

    def read_reg(self, reg_name: str) -> int:
        """Read a core register (not supported in SysAP-only mode).

        @param reg_name: Register name (unused).
        @raises NotImplementedError: Always, as CPU register access
            requires CM33 AP which is not available.
        """
        raise NotImplementedError(
            'CPU register read not supported in SysAP-only mode')

    def write_reg(self, reg_name: str, value: int) -> None:
        """Write a core register (not supported in SysAP-only mode).

        @param reg_name: Register name (unused).
        @param value: Value to write (unused).
        @raises NotImplementedError: Always, as CPU register access
            requires CM33 AP which is not available.
        """
        raise NotImplementedError(
            'CPU register write not supported in SysAP-only mode')

    def erase(self, address: int, size: int) -> None:
        """Erase flash sectors (not supported in SysAP-only mode).

        @param address: Start address (unused).
        @param size: Region size in bytes (unused).
        @raises NotImplementedError: Always, as flash erase is not
            supported in SysAP-only mode.
        """
        raise NotImplementedError(
            'Flash erase not supported in SysAP-only mode')

    def program(
        self,
        filename: str,
        file_format: Optional[str] = None,
        address: Optional[int] = None,
        **kwargs,
    ) -> None:
        """Program a file into flash (not supported in SysAP-only mode).

        @param filename: Path to file (unused).
        @param file_format: Format hint (unused).
        @param address: Base address (unused).
        @raises NotImplementedError: Always, as flash programming
            requires CM33 AP which is not available.
            Use :meth:`program_ram` for RAM loading via SysAP.
        """
        raise NotImplementedError(
            'Flash programming not supported in SysAP-only mode. '
            'Use program_ram() for RAM loading')

    def program_ram(
        self,
        filename: str,
        _file_format: Optional[str] = None,
        address: Optional[int] = None,
    ) -> None:
        """Load a file into RAM via SysAP (no flash programming).

        @param filename: Path to the file.
        @param address: Load address; required for raw binary files.
        """
        logger.debug("Loading '%s' into RAM via SysAP", filename)
        self._program_ram_via_sysap(filename, address)

    def _program_ram_via_sysap(
        self, filename: str, address: Optional[int] = None
    ) -> None:
        """Load a file into RAM using SysAP word-by-word writes.

        This is slower than flash_file but works when CM33 AP is closed.

        @param filename: Path to the file (Intel HEX or binary).
        @param address: Load address for binary files.
        """
        logger.info('Loading file via SysAP...')

        if filename.lower().endswith('.hex'):
            ihex = IntelHex(filename)
            segments = ihex.segments()
            for start, end in segments:
                data = ihex.tobinarray(start=start, end=end - 1)
                self._write_block_via_sysap(start, bytes(data))
        else:
            if address is None:
                raise ValueError(
                    'Load address required for binary files in SysAP mode'
                )
            with open(filename, 'rb') as f:
                data = f.read()
            self._write_block_via_sysap(address, data)

        logger.debug('SysAP load complete')

    def _write_block_via_sysap(self, address: int, data: bytes) -> None:
        """Write a block of data via SysAP using optimized bulk transfer.

        Uses CSW AddrInc=Single mode for fast block writes. Sets TAR once
        per chunk, then writes all words directly to DRW without per-word
        overhead. The address auto-increments after each DRW write.

        @param address: Start address (must be 4-byte aligned).
        @param data: Data to write.
        """
        # Ensure address is aligned
        if address & 0x03:
            raise ValueError(f'Address 0x{address:08X} not 4-byte aligned')

        # Pad data to 4-byte boundary
        padding = (4 - (len(data) % 4)) % 4
        if padding:
            data = data + bytes(padding)

        total_words = len(data) // 4
        logger.debug(
            'SysAP block write: %d bytes (%d words) to 0x%08X',
            len(data), total_words, address
        )

        # Reinitialize DAP to ensure clean state
        if not self.dap_init(APIndex.SYS):
            raise RuntimeError(
                'Failed to reinitialize DAP for SysAP block write')

        # Configure CSW for word access with address auto-increment
        csw = self._read_apv2(APIndex.SYS, APv2Reg.CSW)
        if csw is None:
            raise RuntimeError('Failed to read CSW for block write')

        # Set CSW with AddrInc=Single (auto-increment after each transfer)
        prot = self._get_csw_prot(csw)
        csw_val = prot | APCsw.ADDRINC_SINGLE | APCsw.SIZE_WORD
        if self._write_apv2(APIndex.SYS, APv2Reg.CSW, csw_val) < 0:
            raise RuntimeError('Failed to configure CSW for auto-increment')

        # Pre-calculate the DRW register address for DP.SELECT
        drw_addr = APAddr.SYS + APv2Reg.DRW
        drw_select = drw_addr & DP_SELECT_MASK
        drw_reg_idx = (drw_addr >> 2) & 0x03

        # Set DP.SELECT for DRW access (will stay the same for all writes)
        if drw_select != self._dp_select_last:
            self._coresight_write_dp(DPReg.SELECT, drw_select)
            self._coresight_read_dp(DPReg.RDBUFF)
            self._dp_select_last = drw_select

        # Write in chunks to handle TAR auto-increment rollover.
        # APv2 TAR auto-increment typically works within 1KB boundaries
        # (TARINC=10 bits). Using 1KB chunks ensures we don't overflow.
        CHUNK_SIZE = 256
        start_time = time.time()
        last_progress = -1

        for chunk_start in range(0, total_words, CHUNK_SIZE):
            chunk_end = min(chunk_start + CHUNK_SIZE, total_words)
            chunk_words = chunk_end - chunk_start
            chunk_addr = address + (chunk_start * 4)

            # Set TAR to chunk start address
            if self._write_apv2(APIndex.SYS, APv2Reg.TAR, chunk_addr) < 0:
                raise RuntimeError(f'TAR write failed at 0x{chunk_addr:08X}')

            # Ensure TAR write completes before streaming DRW writes
            self._coresight_read_dp(DPReg.RDBUFF)

            # Stream all words to DRW using direct coresight_write
            # This bypasses _write_apv2 overhead since DP.SELECT is already set
            for i in range(chunk_words):
                word_idx = chunk_start + i
                offset = word_idx * 4
                word = int.from_bytes(data[offset:offset + 4], 'little')

                # Direct coresight_write to AP - much faster than _write_apv2
                self._jlink.coresight_write(drw_reg_idx, word, ap=True)

            # Sync only at end of chunk to ensure posted writes complete
            self._coresight_read_dp(DPReg.RDBUFF)

            # Update progress bar
            pct = (chunk_end * 100) // total_words
            if pct != last_progress:
                update_progress(pct)
                last_progress = pct

            # Log detailed progress every 10 chunks
            chunks_done = chunk_start // CHUNK_SIZE
            if chunk_end == total_words or chunks_done % 10 == 0:
                elapsed = time.time() - start_time
                rate = (chunk_end * 4) / elapsed if elapsed > 0 else 0
                logger.debug(
                    'SysAP write: %d%% (%d/%d words, %.1f KB/s)',
                    pct, chunk_end, total_words, rate / 1024
                )

        # Clear any sticky errors and fully reinitialize DAP for subsequent
        # single-word operations. The direct coresight_write calls may have
        # left errors or the DAP in an inconsistent state.
        self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

        # Reconfigure CoreSight and reinitialize DAP
        self._configure_coresight(critical=False)

        if not self.dap_init(APIndex.SYS):
            logger.warning('Failed to reinitialize DAP after block write')

        elapsed = time.time() - start_time
        rate = len(data) / elapsed if elapsed > 0 else 0
        logger.info(
            'SysAP block write complete: %d bytes in %.1fs (%.1f KB/s)',
            len(data), elapsed, rate / 1024
        )

    def get_probe_list(self) -> list:
        """Return a list of detected J-Link probes.

        @return: List of serial-number strings, or empty list when no
            probes are connected.
        """
        if _pylink is None:
            return []
        try:
            jlink = _pylink.JLink(log=_jlink_log_handler)
            emulators = jlink.connected_emulators()
            return [str(emu.SerialNumber) for emu in emulators]
        except JLinkException as exc:
            logger.warning('Failed to enumerate J-Link probes: %s', exc)
            return []

    def get_voltage(self) -> float:
        """Read the target reference voltage.

        @return: Voltage in volts.
        @raise NotImplementedError: Voltage reading is not supported.
        """
        raise NotImplementedError(
            'Target voltage reading is not supported by J-Link wrapper'
        )

    def dump_image(
        self, filename: str, addr: int, size: int, **kwargs
    ) -> None:
        """Dump a memory region to a binary file via SysAP.

        @param filename: Output file path.
        @param addr: Region start address.
        @param size: Region size in bytes.
        """

        data = self._read_block_via_sysap(addr, size)
        with open(filename, 'wb') as f:
            f.write(data)

    def _read_block_via_sysap(self, address: int, size: int) -> bytes:
        """Read a block of data via SysAP.

        Uses word-aligned reads for efficiency.

        @param address: Start address.
        @param size: Number of bytes to read.
        @return: Bytes read.
        """
        result = bytearray()

        # Handle unaligned start
        start_offset = address & 0x03
        if start_offset:
            aligned_addr = address & ~0x03
            word = self.sysap_read32(aligned_addr)
            if word is None:
                raise RuntimeError(
                    f'SysAP read failed at 0x{aligned_addr:08X}')
            word_bytes = word.to_bytes(4, 'little')
            bytes_to_copy = min(4 - start_offset, size)
            end_offset = start_offset + bytes_to_copy
            result.extend(word_bytes[start_offset:end_offset])
            address += bytes_to_copy
            size -= bytes_to_copy

        # Read aligned words
        while size >= 4:
            word = self.sysap_read32(address)
            if word is None:
                raise RuntimeError(f'SysAP read failed at 0x{address:08X}')
            result.extend(word.to_bytes(4, 'little'))
            address += 4
            size -= 4

        # Handle remaining bytes
        if size > 0:
            word = self.sysap_read32(address)
            if word is None:
                raise RuntimeError(f'SysAP read failed at 0x{address:08X}')
            result.extend(word.to_bytes(4, 'little')[:size])

        return bytes(result)


    def _open_probe(self, probe_id: Optional[str]) -> None:
        """Open the connection to the J-Link probe.

        @param probe_id: Probe ID (integer), or ``None`` for auto-select.
        @raises ValueError: When *probe_id* is not a valid integer.
        """
        if probe_id is not None:
            try:
                serial_no = int(probe_id)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid probe ID '{probe_id}'. "
                    "J-Link probe ID must be an integer"
                ) from exc
            if serial_no < 0:
                raise ValueError(
                    f"Invalid probe ID '{probe_id}'. "
                    "J-Link probe ID must be a positive integer"
                )
            self._jlink.open(serial_no=serial_no)
        else:
            self._jlink.open()

    def _configure_interface(
        self, iface: Interface, speed_khz: int
    ) -> None:
        """Select the debug interface and set communication speed.

        @param iface: SWD or JTAG.
        @param speed_khz: Speed in kHz.
        """
        if iface == Interface.JTAG:
            self._jlink.set_tif(_pylink.JLinkInterfaces.JTAG)
        else:
            self._jlink.set_tif(_pylink.JLinkInterfaces.SWD)
        self._jlink.set_speed(speed_khz)

    def _ensure_device_configured(self) -> None:
        """Ensure the device is configured with J-Link (only once).

        This sets the device name and CORESIGHT_IndexAHBAPToUse via
        exec_command. It only runs once to avoid redundant 'Device selected'
        messages from the J-Link DLL.
        """
        if self._device_configured or not self._device_name:
            return
        try:
            self._jlink.exec_command(f'device = {self._device_name}')
            self._jlink.exec_command('CORESIGHT_IndexAHBAPToUse = 0')
            self._device_configured = True
            logger.debug('Device configured: %s', self._device_name)
        except JLinkException as exc:
            logger.debug('exec_command during device config: %s', exc)

    def _lookup_target_config(self, target_key: str) -> Optional[dict]:
        """Return the target configuration for *target_key*.

        @param target_key: Target name as used in the project.
        @return: Target config dict from ``jlink_target_map.json``, or
            ``None`` when the entry is not present.
        """
        if not os.path.exists(TARGET_MAP):
            return None
        with open(TARGET_MAP, encoding='utf-8') as f:
            data = json.load(f)
        return data.get(target_key.lower().strip())


    def _acquire(self) -> None:
        """Run the device acquisition sequence when defined.

        The default implementation calls :meth:`_acquire_sequence`
        which returns an empty list for a no-op.  Family-specific
        subclasses override the sequence method to drive the SWD
        pins through Infineon's Test Mode pattern.
        """
        sequence = self._acquire_sequence()
        if not sequence:
            logger.debug(
                'No acquisition sequence defined for device %s;'
                ' assuming the debug port is already accessible',
                self._device_name,
            )
            return
        logger.debug(
            'Running acquisition sequence for %s', self._device_name
        )
        for bit_pattern, clock_cycles in sequence:
            self._jlink.swd_write(0, bit_pattern, clock_cycles)

    def _acquire_sequence(self) -> list:
        """Return the device-specific SWD acquisition sequence.

        Override in a family-specific subclass to return an iterable
        of ``(bit_pattern, clock_cycles)`` tuples; the default
        empty list means "no acquisition needed".

        @return: Empty list (no-op) by default.
        """
        return []

    # -------------------------------------------------------------------------
    # Low-level DAP / CoreSight access methods
    # -------------------------------------------------------------------------

    def _configure_coresight(self, critical: bool = True) -> bool:
        """Configure CoreSight for SWD access.

        @param critical: If True, log error on failure; if False, log warning.
        @return: True on success, False on error.
        """
        try:
            self._jlink.coresight_configure()
            return True
        except JLinkException as exc:
            if critical:
                logger.error('coresight_configure failed: %s', exc)
            else:
                logger.warning('coresight_configure failed: %s', exc)
            return False

    def _patch_target_connected(self) -> None:
        """Patch target_connected() to bypass stale IsConnected flag.

        The J-Link DLL's JLINKARM_IsConnected() may return False after
        a device reset even though the probe is still connected. This
        patches the pylink target_connected() method to return True
        whenever the probe itself is open.
        """
        if not self._jlink.target_connected():
            logger.debug(
                'Patching target_connected() to bypass stale '
                'JLINKARM_IsConnected() flag'
            )
            jlink_ref = self._jlink
            self._jlink.target_connected = lambda: jlink_ref.connected

    @staticmethod
    def _get_csw_prot(csw: int) -> APCsw:
        """Determine CSW protection bits based on secure device enable flag.

        @param csw: Current CSW register value.
        @return: APCsw.PROT_SECURE if secure debug enabled, else PROT_NONSECURE.
        """
        if csw & APCsw.SDEVICE_EN:
            return APCsw.PROT_SECURE
        return APCsw.PROT_NONSECURE

    def _detect_security_domain(self) -> Optional[bool]:
        """Determine current security domain by probing memory access.

        Determines the domain by attempting to read from secure and
        non-secure memory aliases:
        - If DomainTestAddr.SECURE is readable -> secure domain
        - If only DomainTestAddr.NON_SECURE is readable -> non-secure

        @return: True if secure domain, False if non-secure.
        """
        # Skip if we already know domain detection failed
        if self._domain_detect_failed:
            return False

        try:

            # Try reading from secure address first
            secure_val = self.sysap_read32(DomainTestAddr.SECURE)
            if secure_val is not None:
                logger.debug(
                    'Domain detection: secure read OK (0x%08X=0x%08X) -> secure',
                    DomainTestAddr.SECURE, secure_val)
                return True

            # Clear sticky errors after failed secure read before trying NS
            self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

            # Secure failed, try non-secure
            ns_val = self.sysap_read32(DomainTestAddr.NON_SECURE)
            if ns_val is not None:
                logger.debug(
                    'Domain detection: non-secure read OK (0x%08X=0x%08X) -> non-secure',
                    DomainTestAddr.NON_SECURE, ns_val)
                return False

            # Both failed
            if not self._domain_detect_failed:
                logger.warning(
                    'Domain detection failed (neither S nor NS readable), '
                    'assuming non-secure')
                self._domain_detect_failed = True
            return False

        except (RuntimeError, JLinkException) as exc:
            if not self._domain_detect_failed:
                logger.warning('Domain detection failed: %s', exc)
                self._domain_detect_failed = True
            return False

    def _adjust_address_for_domain(self, address: int) -> int:
        """Adjust address based on current security domain.

        When domain checking is enabled, this method adjusts the address
        to match the CPU's current TrustZone domain. For non-secure domain,
        bit 28 is cleared to access the non-secure alias of the address.

        Only applies to peripheral address space (DomainCheckRange.MIN to
        DomainCheckRange.MAX) where TrustZone secure/non-secure aliasing
        is used.

        @param address: Original memory address.
        @return: Adjusted address based on current domain.
        """
        if not self.check_domain_security:
            return address

        # Only adjust addresses in peripheral space with S/NS aliasing
        if not (DomainCheckRange.MIN <= address <= DomainCheckRange.MAX):
            return address


        # Read domain state if not cached
        if self._domain_secure is None and not self._domain_detect_failed:
            self._domain_secure = self._detect_security_domain()

        # If DSCSR unavailable or non-secure domain, clear bit 28
        if self._domain_detect_failed or not self._domain_secure:
            adjusted = address & AddrMask.NON_SECURE
            if adjusted != address:
                logger.debug('Address adjusted: 0x%08X -> 0x%08X (non-secure)',
                             address, adjusted)
            return adjusted

        # In secure domain - set secure bit (bit 28)
        adjusted = address | AddrMask.SECURE
        if adjusted != address:
            logger.debug('Address adjusted: 0x%08X -> 0x%08X (secure)',
                         address, adjusted)
        return adjusted

    def invalidate_domain_cache(self) -> None:
        """Invalidate cached domain security state.

        Call this after any operation that may change the CPU's security
        domain (e.g., reset, entering/exiting secure code).
        Also invalidates DP.SELECT cache to ensure fresh DAP state.
        """
        self._domain_secure = None
        self._domain_detect_failed = False
        # Force DP.SELECT refresh
        self._dp_select_last = 0xFFFFFFFF

    def _coresight_write_dp(self, reg_index: int, value: int) -> int:
        """Write to a Debug Port register.

        @param reg_index: DP register index (0-3).
        @param value: Value to write.
        @return: 0 on success, negative on error.
        """
        start = time.time()
        while (time.time() - start) < self.reconnect_timeout_ms / 1000:
            try:
                self._jlink.coresight_write(reg_index, value, ap=False)
                return 0
            except JLinkException as exc:
                logger.debug('coresight_write(DP) failed: %s, retrying', exc)
                time.sleep(0.01)
                continue
        logger.error('coresight_write(DP) failed: timeout after %d ms',
                     self.reconnect_timeout_ms)
        return -1

    def _coresight_read_dp(self, reg_index: int) -> Optional[int]:
        """Read from a Debug Port register.

        @param reg_index: DP register index (0-3).
        @return: Value read, or None on error.
        """
        try:
            return self._jlink.coresight_read(reg_index, ap=False)
        except JLinkException as exc:
            logger.debug('coresight_read(DP) failed: %s', exc)
            return None

    def _coresight_write_ap(self, reg_index: int, value: int) -> int:
        """Write to an Access Port register (low-level).

        @param reg_index: Bits[3:2] of the AP register address.
        @param value: Value to write.
        @return: 0 on success, negative on error.
        """
        try:
            self._jlink.coresight_write(reg_index, value, ap=True)
            return 0
        except JLinkException as exc:
            logger.error('coresight_write(AP) failed: %s', exc)
            return -1

    def _coresight_read_ap(self, reg_index: int) -> Optional[int]:
        """Read from an Access Port register (low-level).

        @param reg_index: Bits[3:2] of the AP register address.
        @return: Value read, or None on error.
        """
        try:
            return self._jlink.coresight_read(reg_index, ap=True)
        except JLinkException as exc:
            logger.debug('coresight_read(AP) failed: %s', exc)
            return None

    def _write_apv2(self, ap_num: int, reg_offset: int, value: int) -> int:
        """Write to an APv2 (CoreSight SoC-600) register.

        Handles DP.SELECT update to access the correct AP and register bank.

        @param ap_num: Access Port index (APIndex.SYS=0, APIndex.CM33=1).
        @param reg_offset: Register offset within the AP.
        @param value: Value to write.
        @return: 0 on success, negative on error.
        """
        reg_addr = APAddr[APIndex(ap_num).name] + reg_offset
        select_value = reg_addr & DP_SELECT_MASK
        reg_index = (reg_addr >> 2) & 0x03

        # Update DP.SELECT if needed
        if select_value != self._dp_select_last:
            result = self._coresight_write_dp(DPReg.SELECT, select_value)
            if result < 0:
                return result
            # Read RDBUFF to ensure DP.SELECT write completes before AP access
            self._coresight_read_dp(DPReg.RDBUFF)
            self._dp_select_last = select_value

        return self._coresight_write_ap(reg_index, value)

    def _read_apv2(self, ap_num: int, reg_offset: int) -> Optional[int]:
        """Read from an APv2 (CoreSight SoC-600) register.

        Handles DP.SELECT update to access the correct AP and register bank.

        @param ap_num: Access Port index (APIndex.SYS=0, APIndex.CM33=1).
        @param reg_offset: Register offset within the AP.
        @return: Value read, or None on error.
        """
        reg_addr = APAddr[APIndex(ap_num).name] + reg_offset
        select_value = reg_addr & DP_SELECT_MASK
        reg_index = (reg_addr >> 2) & 0x03

        # Update DP.SELECT if needed
        if select_value != self._dp_select_last:
            result = self._coresight_write_dp(DPReg.SELECT, select_value)
            if result < 0:
                return None
            # Read RDBUFF to ensure DP.SELECT write completes before AP access
            self._coresight_read_dp(DPReg.RDBUFF)
            self._dp_select_last = select_value

        return self._coresight_read_ap(reg_index)

    def dap_init(self, ap_num: int = APIndex.SYS) -> bool:
        """Initialize the Debug Access Port for the specified AP.

        Powers up the DAP, clears sticky errors, and configures the AP
        for memory access.

        @param ap_num: Access Port index (APIndex.SYS=0, APIndex.CM33=1).
        @return: True on success, False on error.
        """

        logger.debug('DAP init for AP%d', ap_num)

        # Send SWD line reset to ensure clean DAP state
        self._swd_line_reset()

        # Re-set device via exec_command to prevent InitTarget from running.
        # The J-Link DLL may try to reconnect (triggering InitTarget) when
        # coresight_configure() is called after a reset. Ensure device is
        # configured to prevent this.
        self._ensure_device_configured()

        # Configure CoreSight for SWD
        # (required before using coresight_read/write)
        if not self._configure_coresight():
            return False

        # Clear sticky errors via DP.ABORT
        self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

        # Power up DAP
        result = self._coresight_write_dp(DPReg.CTRL_STAT, DPCtrl.POWER_UP)
        if result < 0:
            logger.error('Failed to power up DAP')
            return False

        # Invalidate SELECT cache
        self._dp_select_last = 0xFFFFFFFF

        # Read CSW to determine secure/non-secure access
        csw = self._read_apv2(ap_num, APv2Reg.CSW)
        if csw is None:
            logger.error('Failed to read AP%d CSW', ap_num)
            return False

        logger.debug('AP%d CSW initial value: 0x%08X', ap_num, csw)

        # Configure CSW for word access with appropriate protection
        # and NO address auto-increment (critical for single-word access)
        prot = self._get_csw_prot(csw)
        csw_val = prot | APCsw.ADDRINC_OFF | APCsw.SIZE_WORD
        result = self._write_apv2(ap_num, APv2Reg.CSW, csw_val)
        if result < 0:
            logger.error('Failed to configure AP%d CSW', ap_num)
            return False

        # Read back CSW to verify configuration
        csw_verify = self._read_apv2(ap_num, APv2Reg.CSW)
        logger.debug('AP%d CSW configured: 0x%08X (readback: 0x%08X)',
                     ap_num, csw_val, csw_verify or 0)

        self._current_ap_index = ap_num
        return True

    def sysap_read32(self, address: int) -> Optional[int]:
        """Read a 32-bit value via the System Access Port.

        This bypasses the normal memory access path and reads directly
        through AP[0] (SysAP), allowing access to system registers even
        when the CM33 AP is closed.

        @param address: Memory address to read.
        @return: Value read, or None on error.
        """
        return self._sysap_read32_impl(address, retry=True)

    def _sysap_read32_impl(
            self, address: int, retry: bool = True
    ) -> Optional[int]:
        """Internal implementation of sysap_read32 with retry support."""

        # Ensure SysAP is initialized
        if self._current_ap_index != APIndex.SYS:
            if not self.init_sysap():
                return None

        # Clear sticky errors before read
        self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

        # Write address to TAR
        result = self._write_apv2(APIndex.SYS, APv2Reg.TAR, address)
        if result < 0:
            if retry:
                logger.debug(
                    'sysap_read32: TAR write failed for 0x%08X, '
                    'reinitializing DAP and retrying', address)
                # DAP may be in bad state - reinitialize
                time.sleep(0.050)
                # Force full reinit
                self._current_ap_index = -1
                self._dp_select_last = 0xFFFFFFFF
                if self.init_sysap():
                    return self._sysap_read32_impl(address, retry=False)
            logger.error('sysap_read32: TAR write failed for 0x%08X', address)
            return None

        # Read RDBUFF to ensure the TAR write is complete before reading DRW
        # Note: may fail in certain DAP states but we continue
        sync = self._coresight_read_dp(DPReg.RDBUFF)
        if sync is None:
            logger.debug('sysap_read32: TAR sync read failed (continuing)')

        # Read from DRW
        value = self._read_apv2(APIndex.SYS, APv2Reg.DRW)
        if value is None and retry:
            logger.debug(
                'sysap_read32: DRW read failed for 0x%08X, '
                'reinitializing DAP and retrying', address)
            time.sleep(0.050)
            self._current_ap_index = -1
            self._dp_select_last = 0xFFFFFFFF
            if self.init_sysap():
                return self._sysap_read32_impl(address, retry=False)

        if value is not None:
            logger.debug('sysap_read32(0x%08X) = 0x%08X', address, value)
        return value

    def sysap_write32(self, address: int, value: int) -> bool:
        """Write a 32-bit value via the System Access Port.

        This bypasses the normal memory access path and writes directly
        through AP[0] (SysAP), allowing access to system registers even
        when the CM33 AP is closed.

        For addresses in peripheral space (DomainCheckRange.MIN to
        DomainCheckRange.MAX), the domain is re-detected and address
        adjusted to match current security state, as the domain may
        change during provisioning.

        @param address: Memory address to write.
        @param value: Value to write.
        @return: True on success, False on error.
        """
        return self._sysap_write32_impl(address, value, retry=True)

    def _sysap_write32_impl(
            self, address: int, value: int, retry: bool = True
    ) -> bool:
        """Internal implementation of sysap_write32 with retry support."""

        # Ensure SysAP is initialized
        if self._current_ap_index != APIndex.SYS:
            logger.debug('sysap_write32: reinitializing SysAP')
            if not self.init_sysap():
                return False

        # For peripheral space, invalidate cache and re-detect domain
        # Domain may change during provisioning
        if DomainCheckRange.MIN <= address <= DomainCheckRange.MAX:
            self.invalidate_domain_cache()
            adjusted_addr = self._adjust_address_for_domain(address)
            # Delay after domain detection to let DAP settle
            time.sleep(0.010)
        else:
            adjusted_addr = address

        # Clear any sticky errors before write
        self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

        # Write address to TAR
        result = self._write_apv2(APIndex.SYS, APv2Reg.TAR, adjusted_addr)
        if result < 0:
            if retry:
                logger.debug(
                    'sysap_write32: TAR write failed for 0x%08X, '
                    'reinitializing DAP and retrying', adjusted_addr)
                time.sleep(0.050)
                self._current_ap_index = -1
                self._dp_select_last = 0xFFFFFFFF
                if self.init_sysap():
                    return self._sysap_write32_impl(address, value, retry=False)
            logger.error('sysap_write32: TAR write failed for 0x%08X', adjusted_addr)
            return False

        # IMPORTANT: Read RDBUFF to ensure the TAR write is complete
        # before writing to DRW. AP writes are posted (asynchronous),
        # and without this synchronization, the DRW write may execute
        # before TAR is updated, causing incorrect memory access.
        # Note: RDBUFF read may fail in certain states but the write
        # may still succeed - we log a warning but continue.
        sync = self._coresight_read_dp(DPReg.RDBUFF)
        if sync is None:
            logger.debug('sysap_write32: TAR sync read failed (continuing)')

        # Write to DRW
        result = self._write_apv2(APIndex.SYS, APv2Reg.DRW, value)
        if result < 0:
            if retry:
                logger.debug(
                    'sysap_write32: DRW write failed for 0x%08X, '
                    'reinitializing DAP and retrying', adjusted_addr)
                time.sleep(0.050)
                self._current_ap_index = -1
                self._dp_select_last = 0xFFFFFFFF
                if self.init_sysap():
                    return self._sysap_write32_impl(address, value, retry=False)
            logger.error('sysap_write32: DRW write failed for 0x%08X', adjusted_addr)
            return False

        # Read RDBUFF again to ensure the DRW write completes.
        # This read may fail after operations that reset the DAP
        # (e.g., writing to RES_SOFT_CTL), which is expected.
        sync = self._coresight_read_dp(DPReg.RDBUFF)
        if sync is None:
            logger.debug(
                'sysap_write32: DRW sync read failed '
                '(write may have succeeded)'
            )

        logger.debug('sysap_write32(0x%08X) = 0x%08X OK', adjusted_addr, value)
        return True


    def init_sysap(self) -> bool:
        """Initialize direct SysAP access.

        Call this after connect() to switch from the default CM33 AP
        to SysAP. This allows accessing system registers even when
        CM33 AP becomes closed (e.g., after soft reset).

        @return: True on success, False on error.
        """

        logger.debug('Initializing SysAP for direct access')

        self._patch_target_connected()

        # Ensure device is configured to prevent InitTarget from running
        self._ensure_device_configured()

        # Configure CoreSight for DAP access
        if not self._configure_coresight():
            return False

        # Initialize DAP for SysAP
        return self.dap_init(APIndex.SYS)

    def reconnect(self) -> bool:
        """Reconnect to the target after a connection-breaking event.

        Implements ProgrammerBase.reconnect() for J-Link. Called after
        operations that reset the debug port (e.g., writing to RES_SOFT_CTL).

        A software reset via peripheral register resets the SWD Debug Port.
        This method re-initializes the DAP directly via CoreSight without
        calling JLINKARM_Connect() (which would trigger InitTarget() and
        potentially fail if CM33 AP is closed).

        Uses self.reconnect_wait_ms and self.reconnect_timeout_ms attributes.

        @return: True on success, False on failure.
        """
        wait_ms = self.reconnect_wait_ms
        timeout_ms = self.reconnect_timeout_ms

        time.sleep(wait_ms / 1000.0)
        logger.debug('Reconnecting after soft reset (SysAP only)...')

        self._patch_target_connected()

        # Perform SWD line reset to reinitialize the Debug Port
        self._swd_line_reset()

        # Ensure device is configured to prevent InitTarget from running
        self._ensure_device_configured()

        # Configure CoreSight for direct DAP access (bypasses InitTarget)
        if not self._configure_coresight():
            return False

        # Wait for DAP to become accessible with retries
        start = time.time()
        timeout_s = timeout_ms / 1000.0

        while (time.time() - start) < timeout_s:
            try:
                # Clear sticky errors
                self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL)

                # Power up DAP
                if self._coresight_write_dp(DPReg.CTRL_STAT, DPCtrl.POWER_UP) < 0:
                    time.sleep(0.010)
                    continue

                # Invalidate SELECT cache
                self._dp_select_last = 0xFFFFFFFF

                # Try to read SysAP CSW to verify access
                csw = self._read_apv2(APIndex.SYS, APv2Reg.CSW)
                if csw is not None:
                    # Configure CSW for word access with NO address increment
                    prot = self._get_csw_prot(csw)
                    csw_val = prot | APCsw.ADDRINC_OFF | APCsw.SIZE_WORD
                    if self._write_apv2(APIndex.SYS, APv2Reg.CSW, csw_val) >= 0:
                        self._current_ap_index = APIndex.SYS
                        # Invalidate domain cache after reconnect
                        self._domain_secure = None
                        logger.debug(
                            'Reconnect via SysAP successful (CSW=0x%08X)',
                            csw_val
                        )
                        return True

            except JLinkException as exc:
                logger.debug('Reconnect attempt failed: %s', exc)

            time.sleep(0.010)

        logger.error('Reconnect timeout after %d ms', timeout_ms)
        return False

    def _swd_line_reset(self) -> None:
        """Send SWD line reset sequence to reinitialize the Debug Port.

        Sends at least 50 clock cycles with SWDIO high followed by
        idle cycles, which resets the SWD state machine in the target.
        """
        logger.debug('Sending SWD line reset sequence')
        try:
            # Send 56 bits of all 1s (SWDIO high) to reset the line
            # Using two 32-bit writes to avoid 64-bit integer issues
            # Parameters: (trn_after_data, data, num_bits)
            self._jlink.swd_write(0, 0xFFFFFFFF, 32)
            self._jlink.swd_write(0, 0x00FFFFFF, 24)
            # Send idle cycles (SWDIO low) - at least 2 cycles
            self._jlink.swd_write(0, 0x00, 8)
            # Sync the SWD operations
            self._jlink.swd_sync()
        except JLinkException as exc:
            logger.debug('SWD line reset: %s', exc)

    def _connect_sysap_only(self, timeout_ms: int = 5000) -> bool:
        """Connect directly to SysAP without using CM33 at all.

        This method bypasses J-Link's InitTarget() entirely by using
        exec_command to set the device without triggering the connect
        sequence. Then it configures CoreSight directly and initializes
        SysAP for register access.

        This avoids any CM33 AP involvement during the initial connection,
        which is critical for provisioning devices in NORMAL_PROVISIONED
        lifecycle where CM33 may be closed.

        @param timeout_ms: Timeout for handshake in milliseconds.
        @return: True on success, False on failure.
        """
        logger.debug(
            '_connect_sysap_only: starting pure SysAP connection (no CM33)')

        # Set device via exec_command to avoid triggering InitTarget().
        # This registers the device with J-Link without running the
        # JLinkScript's InitTarget() which would try to use CM33.
        if self._device_name and not self._device_configured:
            logger.debug(
                'Setting device via exec_command: %s', self._device_name)
            try:
                # First set device name - this does NOT trigger InitTarget
                self._jlink.exec_command(f'device = {self._device_name}')
                self._jlink.exec_command('CORESIGHT_IndexAHBAPToUse = 0')
                self._device_configured = True
                logger.debug('Device configured: %s', self._device_name)
            except JLinkException as exc:
                logger.debug('exec_command device failed: %s', exc)

        # Configure CoreSight APs manually (equivalent to ConfigTargetSettings)
        # These commands configure the AP addresses without triggering
        # InitTarget
        try:
            # Configure SysAP (AP[0]) - this is the only AP we need
            # for provisioning
            self._jlink.exec_command(
                'CORESIGHT_AddAP = Index=0 Type=AHB-AP BaseAddr=0xF0000000'
            )
            logger.debug('Configured SysAP (AP[0]) at 0xF0000000')
            # Configure CM33 AP (AP[1]) for completeness,
            # though we won't use it
            self._jlink.exec_command(
                'CORESIGHT_AddAP = Index=1 Type=AHB-AP BaseAddr=0xF0002000'
            )
            logger.debug('Configured CM33 AP (AP[1]) at 0xF0002000')
        except JLinkException as exc:
            # Some J-Link firmware versions don't support
            # CORESIGHT_AddAP command
            # This is expected - we fall back to direct CoreSight operations
            logger.debug('CoreSight AP configuration skipped: %s', exc)

        # Now initialize SysAP directly via CoreSight
        # This works regardless of whether InitTarget succeeded or failed

        # Perform SWD line reset to ensure clean DAP state
        self._swd_line_reset()

        # Configure CoreSight for SWD access
        # (required before coresight_read/write)
        if not self._configure_coresight():
            return False

        # Handshake: wait for IDCODE to be readable
        # Similar to _Handshake() in JLinkScript
        start = time.time()
        timeout_s = timeout_ms / 1000.0
        idcode_ok = False

        while (time.time() - start) < timeout_s:
            try:
                # Try to read IDCODE via DP (reg 0)
                # In SWD, IDCODE is accessible after line reset
                idcode = self._jlink.coresight_read(0, ap=False)
                if idcode is not None and idcode != 0 and idcode != 0xFFFFFFFF:
                    # Expected IDCODE for PSoC C3x6: 0x4C013477
                    logger.debug('Handshake OK, IDCODE=0x%08X', idcode)
                    idcode_ok = True
                    break
            except JLinkException as exc:
                logger.debug('IDCODE read attempt failed: %s', exc)
                # Try SWD line reset and reconfigure
                self._swd_line_reset()
                try:
                    self._jlink.coresight_configure()
                except JLinkException:
                    pass
            time.sleep(0.010)

        if not idcode_ok:
            logger.error(
                'Handshake failed: IDCODE not readable within %d ms',
                timeout_ms
            )
            return False

        # Invalidate DP.SELECT cache
        self._dp_select_last = 0xFFFFFFFF

        # Clear sticky errors via DP.ABORT
        # Similar to _DAP_Init() in JLinkScript
        if self._coresight_write_dp(DPReg.ABORT, DPAbort.CLEAR_ALL) < 0:
            logger.error('Failed to clear sticky errors')
            return False

        # Power up DAP via DP.CTRL/STAT
        if self._coresight_write_dp(DPReg.CTRL_STAT, DPCtrl.POWER_UP) < 0:
            logger.error('Failed to power up DAP')
            return False

        # Read SysAP CSW to determine secure/non-secure access
        csw = self._read_apv2(APIndex.SYS, APv2Reg.CSW)
        if csw is None:
            logger.error('Failed to read SysAP CSW')
            return False

        logger.debug('SysAP CSW initial value: 0x%08X', csw)

        # Configure CSW for word access with appropriate protection
        # and NO address auto-increment
        prot = self._get_csw_prot(csw)
        csw_val = prot | APCsw.ADDRINC_OFF | APCsw.SIZE_WORD
        if self._write_apv2(APIndex.SYS, APv2Reg.CSW, csw_val) < 0:
            logger.error('Failed to configure SysAP CSW')
            return False

        # Read back CSW to verify
        csw_verify = self._read_apv2(APIndex.SYS, APv2Reg.CSW)
        logger.debug(
            'SysAP CSW configured: 0x%08X (readback: 0x%08X)',
            csw_val, csw_verify or 0
        )

        self._current_ap_index = APIndex.SYS
        logger.debug('Direct SysAP connection established successfully')
        return True
