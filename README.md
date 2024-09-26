This package contains security tools for creating keys, creating certificates, signing user applications, and provisioning Cypress/Infineon MCUs.

# Table of Contents
- [HW/SW compatibility](#hwsw-compatibility)
- [Prerequisites](#prerequisites)
- [Documentation](#documentation)
- [Standalone Executable](#standalone-executable)
- [Installing From Sources](#installing-from-sources)
- [Supported Devices](#supported-devices)
- [Interface and Usage](#interface-and-usage)
- [Logging](#logging)
- [Known Issues](#known-issues)
- [Error Handling](#error-handling)
- [License and Contributions](#license-and-contributions)

# HW/SW compatibility
## PSoC 64
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>Secure FlashBoot Version</td>
      <td>CyBootloader Version</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="6" style="text-align: center;">512K</td>
    </tr>
    <tr>
      <td>
        cyb06xx5<br>
        cy8cproto&#8209;064b0s3
      </td>
      <td>0xE70D, 0x12, 0x105</td>
      <td>4.0.2.1842</td>
      <td>2.0.1.6441</td>
    </tr>
    <tr>
      <td colspan="6" style="text-align: center;">2M</td>
    </tr>
    <tr>
      <td>
        cyb06xxa<br>
        cy8ckit&#8209;064b0s2&#8209;4343w
      </td>
      <td>0xE470, 0x12, 0x102</td>
      <td>4.0.3.2319</td>
      <td>2.0.2.8102</td>
    </tr>
    <tr>
      <td>
        cys06xxa<br>
        cy8ckit&#8209;064s0s2&#8209;4343w
      </td>
      <td>0xE4A0, 0x12, 0x02</td>
      <td>4.0.3.2319</td>
      <td>2.0.2.8102</td>
    </tr>
    <tr>
      <td colspan="6" style="text-align: center;">1M</td>
    </tr>
    <tr>
      <td>
        cyb06xx7<br>
        cy8cproto&#8209;064s1&#8209;sb<br>
        cy8cproto&#8209;064b0s1&#8209;ble<br>
        cy8cproto&#8209;064b0s1&#8209;ssa
      </td>
      <td>
        0xE262, 0x24, 0x100
        0xE261, 0x24, 0x100
      </td>
      <td>4.0.2.1842</td>
      <td>2.0.0.4041</td>
    </tr>
  </tbody>
</table>

## CYW20829 / CYW89829
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>ROM Boot Version</td>
      <td>RAM Applications Version</td>
    </tr>
  </thead>
  <tbody>
  <tr>
    <td>cyw20829</td>
    <td>0xEB43, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  <tr>
    <td>cyw89829</td>
    <td>0xEB47, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  </tbody>
</table>

# Prerequisites
* Python 3.8 - 3.12
* [Installed Infineon OpenOCD](https://github.com/Infineon/openocd/releases)
* Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**


# Documentation
* [PSoC64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)
* [Changelog](https://github.com/Infineon/edgeprotecttools/blob/master/CHANGELOG.md)

# Standalone Executable
Edge Protect Tools can be used as a standalone application. The executable can be found in the `tools/edgeprotecttools/bin` directory of the Early Access Pack installation or Edge Protect Security Suite.

# Installing From Sources
Alternatively Edge Protect Tools can be installed from the sources as a Python package. The source code is located in the `tools/edgeprotecttools/src` directory of the Early Access Pack installation or Edge Protect Security Suite.

Install Python 3.12 on your computer. You can download it from https://www.python.org/downloads/. Set up the appropriate environment variable(s) for your operating system.

## Installing Package
Make sure that you have the latest version of pip installed, use
the following command.
```bash
$ python -m pip install --upgrade pip
```
Run the following command, from the Early Access Pack or Edge Protect Security Suite directory.
```bash
$ python -m pip install tools/edgeprotecttools/src
```

## Updating Package
To update the already installed package, run the following command from the Early Access Pack or Edge Protect Security Suite directory.
```bash
$ python -m pip install --upgrade --force-reinstall tools/edgeprotecttools/src
```

*Note*: There may be some pip dependency resolver errors. In most cases, these can be safely ignored.

*Note*: You can use the following command to show the path to the installed package
`$ python -m pip show edgeprotecttools`.


# Supported Devices
Use `device-list` command for output of the supported devices list.
```bash
$ edgeprotecttools device-list
```


# Interface and Usage
For instructions how to use common commands, see [README_GENERAL.md](https://github.com/Infineon/edgeprotecttools/blob/master/docs/README_GENERAL.md).

For instructions how to use target-specific commands, see the corresponding readme file in the [docs](https://github.com/Infineon/edgeprotecttools/blob/master/docs) directory.


# Logging
Every time the tool is invoked, a new log file is created in the _logs_ directory of the project. By default, the console output has INFO logging severity. The log file contains the DEBUG logging severity.


# Known Issues
- Using the policy from CySecureTools 4.0.0 in projects created by CySecureTools 4.1.0 causes the CY_FB_INVALID_IMG_JWT_SIGNATURE error during re-provisioning on PSoC64-2M devices:
```
  ...
  ERROR : SFB status: CY_FB_INVALID_IMG_JWT_SIGNATURE: Invalid image certificate signature. Check the log for details
```
_Workaround_:
1. Open the policy file.
2. Navigate to section 1 of the `boot_upgrade/firmware`.
3. Set `boot_auth` and `bootloader_keys` as follows:
```
"boot_auth": [
    3
],
"bootloader_keys": [
    {
        "kid": 3,
        "key": "../keys/cy_pub_key.json"
    }
]
```
- During the installation of the package via _pip_ on Mac OS Big Sur, the following exception is raised:
```
  ...
  distutils.errors.DistutilsError: Setup script exited with error: SandboxViolation:
  mkdir('/private/var/root/Library/Caches/com.apple.python/private/tmp/easy_install-y8c1npmz', 511) {}

  The package setup script has attempted to modify files on your system
  that are not within the EasyInstall build area, and has been aborted.

  This package cannot be safely installed by EasyInstall, and may not
  support alternate installation locations even if you run its setup
  script by hand.  Please inform the package's author and the EasyInstall
  maintainers to find out if a fix or workaround is available.
```
_Solution:_ Upgrade the `pip` package running the following command from the terminal: `python3 -m pip install --upgrade pip`.

# Error Handling
Refer to the guidelines on how to [resolve errors](https://github.com/Infineon/edgeprotecttools/blob/master/docs/README_ERRORS.md).

# License and Contributions
The software is provided under the Apache-2.0 license. Contributions to this project are accepted under the same license.
This project contains code from other projects. The original license text is included in those source files.
