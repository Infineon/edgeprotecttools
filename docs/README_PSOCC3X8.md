# Table of Contents
- [Main features](#main-features)
- [Quick start](#quick-start)
- [Command-line interface](#command-line-interface)
    - [Tool help](#tool-help)
    - [Common options](#common-options)
    - [Create project](#create-project)
    - [Device Integrity Exam](#device-integrity-exam)
    - [Provision device](#provision-device)
    - [Create provisioning packet](#create-provisioning-packet)
    - [Create DLM package](#create-dlm-package)
    - [Create debug token](#create-debug-token)
    - [Extract Initial Attestation Key](#extract-initial-attestation-key)
    - [Read die ID](#read-die-id)
    - [Get firmware version](#get-firmware-version)
    - [Get device info](#get-device-info)
- [Provisioning process](#provisioning-process)
- [Using package together with HSM](#using-package-together-with-hsm)
    - [Signing application with HSM](#signing-application-with-hsm)
    - [Creation and signing a debug token with HSM](#creation-and-signing-a-debug-token-with-hsm)
    - [Creation and signing an RMA token with HSM](#creation-and-signing-an-rma-token-with-hsm)
- [Return Merchandise Authorization (RMA)](#return-merchandise-authorization-rma)
    - [RMA token](#rma-token)
    - [Transition to RMA](#transition-to-rma)
- [Protected Firmware Update](#protected-firmware-update)
    - [Provisioning device with Protected FW policy](#provisioning-device-with-protected-fw-policy)
    - [Protected FW download](#protected-fw-download)


# Main features
* Keys creation - Creates a private-public key pair.
* Integrity exam - Passing an integrity exam before provisioning a device is an option to ensure that the device is a genuine Infineon device and it is in a known state.
* Provisioning - Provisioning is the act of configuring a device with an authorized set of keys, policies, and optionally certificates. Supports SWD and serial interface.
* Signing user applications - Signs a user application with a private key locally or using a Hardware Security Module.
* Debug token - The debug token is used to enable CM33 and/or the system access port when it is temporarily disabled.


# Quick start
## 1. Set a path to the On-Chip debugger
```bash
$ edgeprotecttools set-ocd --name openocd --path <PATH_TO_OPENOCD_ROOT_DIRECTORY>
```
Ensure that you provide the path to the root directory of OpenOCD (NOT _bin_ directory).
Specifying the path is not mandatory if you have ModusToolbox™ installed on your machine. OpenOCD from the ModusToolbox™ directory is used by default.

_Example:_
```bash
$ edgeprotecttools set-ocd --name openocd --path /Users/username/tools/openocd
```

## 2. Define a target
Run the following command and find the name of your target in the list of supported targets.
```bash
$ edgeprotecttools device-list
```
This target name will be used as a `-t` option value with each command.

_Example_:
```bash
$ edgeprotecttools -t psoc_c3x8 <COMMAND> [OPTIONS]
```

## 3. Create a new project
This copies the list of files required to start using the tool to the current working directory.
```bash
$ edgeprotecttools -t psoc_c3x8 init
```

## 4. Create keys
Create private/public key pairs.
```bash
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/oem_rot_priv_key_0.pem keys/oem_rot_pub_key_0.pem
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/oem_rot_priv_key_1.pem keys/oem_rot_pub_key_1.pem
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/oem_debug_priv_key.pem keys/oem_debug_pub_key.pem
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/oem_dev_priv_key.pem keys/oem_dev_pub_key.pem
$ edgeprotecttools create-key --key-type AES256 --output keys/oem_enc_key.bin

$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/prot_fw_rot_priv_key_0.pem keys/prot_fw_rot_pub_key_0.pem
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/prot_fw_rot_priv_key_1.pem keys/prot_fw_rot_pub_key_1.pem
$ edgeprotecttools create-key --key-type ECDSA-P521 --output keys/prot_fw_debug_priv_key.pem keys/prot_fw_debug_pub_key.pem
$ edgeprotecttools create-key --key-type AES256 --output keys/prot_fw_enc_key.bin
```

## 5. Get a development certificate
Create CSR with public keys and provide it to [Infineon Edge Protect Signing Service](https://osts.infineon.com/epss/home) to generate a certificate, which action authorizes the keys.
```bash
$ edgeprotecttools -t psoc_c3x8 oem-csr --public-key-0 keys/oem_dev_pub_key.pem --public-key-1 keys/oem_dev_pub_key.pem --sign-key-0 keys/oem_dev_priv_key.pem --sign-key-1 keys/oem_dev_priv_key.pem --oem "Company Name" --project "Project Name" --project-number 12345678 --cert-type development --output oem_csr.bin
```

## 6. Provision the device
In the DEVELOPMENT LCS, the `--ifx-oem-cert` option is required and must always be provided. Specify the path to the development certificate received from Infineon.
```bash
$ edgeprotecttools -t psoc_c3x8 provision-device -p policy/policy_oem_provisioning.json --key keys/oem_dev_priv_key.pem --ifx-oem-cert oem_cert.bin 
```

## 7. Sign the image
```bash
$ edgeprotecttools sign-image --image image.bin --output image_signed.bin --key keys/oem_dev_priv_key.pem
```


# Command-line interface
This section contains the main CLI commands. More commands can be found in the tool help.

## Tool help
To see the list of commands supported for PSOC™ C3P8:
```bash
$ edgeprotecttools -t psoc_c3x8 --help
```
To see the list of options for a specific command:
```bash
$ edgeprotecttools -t psoc_c3x8 <COMMAND> --help
```

## Common options
The interface provides common options. These options are common for all commands and must precede them:

| Name            | Description                                  |
|-----------------|----------------------------------------------|
| -t, --target    | Device name or family                        |
| -v, --verbose   | Provides debug-level log                     |
| -q, --quiet     | Quiet display option                         |
| --logfile-off   | Disabling logging to a file                  |
| --timestamps    | Enable displaying timestamps in log messages |


## Create project
Creates a new project for PSOC™ C3P8.
### Command: `init`
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 init
```


## Device Integrity Exam
The device integrity exam ensures that this is a genuine Infineon device and it is in a known state.
The integrity exam is implemented as a combination of a RAM application collecting device measurements and a host component validating device measurements.
The tool gets the RAM application output and compares it with the device integrity certificate data. This acceptance test is recommended before the device OEM provisioning and determines that there are no modifications of fuses or flash bits.

### Command: `integrity-exam`
### Parameters
| Name              | Optional/Required | Description                                                |
|-------------------|:-----------------:|------------------------------------------------------------|
| --probe-id        |     optional      | Probe serial number.                                       |
| --cert            |     required      | Path to the integrity certificate.                         |
| --custom-regions  |     optional      | Path to a custom regions template for integrity check.     |
| --key             |     optional      | Key to sign the DLM package.                               |
| --existing-packet |     optional      | Skip provisioning packet creation and use an existing one. |

### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 integrity-exam --probe-id 061003B803260400 --cert packets/device_integrity_cert.json
```

## Provision device
Configuring a device with a set of keys and policies.
### Command: `provision-device`
### Parameters
| Name              | Optional/Required | Description                                                                                                                                                                        |
|-------------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -p, --policy      |     required      | The path to the provisioning policy.                                                                                                                                               |
| --key, --key-path |     optional      | The path to the key used to sign the provisioning packet. Applicable only for policy type "oem_provisioning", "prot_fw_policy". Required for policy type "oem_provisioning".       |
| --probe-id        |     optional      | Probe serial number.                                                                                                                                                               |
| --existing-packet |     optional      | Skip provisioning packet creation and use the existing packet. This may be useful when a packet already exists and the tool does not have to generate it again.                    |
| --ifx-oem-cert    |     optional      | Path to the OEM certificate. Used for the transfer of ownership and changing the LCS. In the DEVELOPMENT LCS, the `--ifx-oem-cert` option is required and must always be provided. |
### Usage example
```bash
# Transfer of ownership and OEM provisioning in DEVELOPMENT LCS
$ edgeprotecttools -t psoc_c3x8 provision-device -p policy/policy_oem_provisioning.json --ifx-oem-cert oem_cert_development.bin --key keys/oem_dev_priv_key.pem --probe-id 061003B803260400
# Transfer of ownership and OEM provisioning in PRODUCTION LCS
$ edgeprotecttools -t psoc_c3x8 provision-device -p policy/policy_oem_provisioning.json --ifx-oem-cert oem_cert_production.bin --key keys/oem_rot_priv_key_0.pem --probe-id 061003B803260400
# OEM provisioning in PRODUCTION LCS
$ edgeprotecttools -t psoc_c3x8 provision-device -p policy/policy_oem_provisioning.json --key keys/oem_rot_priv_key_0.pem --probe-id 061003B803260400
```


## Create provisioning packet
Creates a provisioning/reprovisioning data packet without starting the device provisioning process.
### Command: `create-provisioning-packet`
### Parameters
| Name              | Optional/Required | Description                                                                                                       |
|-------------------|:-----------------:|-------------------------------------------------------------------------------------------------------------------|
| -p, --policy      |     required      | The path to the provisioning policy.                                                                              |
| --key, --key-path |     optional      | The path to the key used to sign the reprovisioning packet. If not specified, an unsigned packet will be created. |
| -o, --output      |     optional      | The path where to save the packet.                                                                                |
| --integrity-cert  |     optional      | Path to the integrity certificate.                                                                                |
| --ifx-oem-cert    |     optional      | Path to the OEM certificate.                                                                                      |
### Usage example
#### Signed
```bash
$ edgeprotecttools -t psoc_c3x8 create-provisioning-packet -p policy/policy_oem_provisioning.json --key keys/oem_dev_priv_key.pem
```


## Create DLM package
Builds the RAM application and it's inputs into a single signed package.
### Command: `build-ramapp-package`
### Parameters
| Name              | Optional/Required | Description                                   |
|-------------------|:-----------------:|-----------------------------------------------|
| -a, --app         |     required      | The path to the RAM application binary.       |
| -o, --output      |     required      | The path to the DLM package output file.      |
| --inparams        |     optional      | The path to the application input parameters. |
| --key, --key-path |     optional      | Private key to sign the package.              |
| --hex-addr        |     optional      | Adjust address in hex output file.            |
| -S, --slot-size   |     optional      | Sets the maximum slot size.                   |
### Usage example
```bash
# Create signed DLM package (the --key option may be skipped for SIMPLE_APP)
$ edgeprotecttools -t psoc_c3x8 build-ramapp-package --app packets/apps/prov_oem/cyapp_prov_oem_signed_ifx0.bin --inparams packets/apps/prov_oem/in_params.bin --key keys/oem_rot_priv_key_0.pem --output packets/apps/prov_oem/prov_oem_dlm.hex
```


## Create debug token
Creates debug or RMA token based on template.

The debug token is used to enable CM33 or the system access port when it is temporarily disabled. Note that the token cannot enable an access port that is permanently disabled by the access restrictions. Also, the debug token can be used to enable/disable invasive or non-invasive debugging for CM33-AP.

The command creates a signed debug token binary based on the template. By default, the template is configured to be applicable for any die ID. See the [Read die id](#read-die-id) section to the find die ID of your device. See the [Get device info](#get-device-info) section to find the silicon ID, family ID, and revision ID needed to create a certificate.
### Command: `debug-token`
### Parameters
| Name              | Optional/Required | Description                                                                                                               |
|-------------------|:-----------------:|---------------------------------------------------------------------------------------------------------------------------|
| -T, --template    |     optional      | The path to the token template. The template can be found in the _packets_ directory of the project (_debug_token.json_). |
| --key, --key-path |     optional      | The path to the private key to sign the token. If the token to be signed by HSM, do not specify the option.               |
| -o, --output      |     required      | The file where to save the debug token.                                                                                   |
### Usage example
```bash
# Create debug token for OEM application
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json -o packets/debug_token.bin --key keys/oem_debug_priv_key.pem
# Create debug token for Protected FW 
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json -o packets/debug_token.bin --key keys/prot_fw_debug_priv_key.pem
```


## Extract Initial Attestation Key
This command extracts the Initial Attestation Key (IAK) from the RAM app response and saves it to a file.
If asymmetric keys is extracted, it is saved in PEM format. 
If symmetric key is extracted, it is saved in binary format.
If no key is found, an error message is displayed.

### Command: `extract-iak`
### Parameters
| Name          | Optional/Required | Description                                                |
|---------------|:-----------------:|------------------------------------------------------------|
| -i, --input   |     required      | The path to the RAM app response binary file.              |
| -o, --output  |     required      | The path where to save the extracted IAK.                  |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 extract-iak -i out_results.bin -o pub_key.pem
```

## Read die ID
Reads the die ID from a device.
### Command: `read-die-id`
### Parameters
| Name           | Optional/Required | Description                                                                                                        |
|----------------|:-----------------:|--------------------------------------------------------------------------------------------------------------------|
| -o, --out-file |     optional      | The name of the file where to save the die ID. If not specified, the information will be displayed in the console. |
| --probe-id     |     optional      | Probe serial number.                                                                                               |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 read-die-id
```


## Get firmware version
Outputs version of ROM_BOOT, FLASH_BOOT.
### Command: `version`
### Parameters
| Name       | Optional/Required | Description          |
|------------|:-----------------:|----------------------|
| --probe-id |     optional      | Probe serial number. |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 version
```


## Get device info
Gets device information - silicon ID, silicon revision, and family ID.
### Command: `device-info`
### Parameters
| Name       | Optional/Required | Description                                                                              |
|------------|:-----------------:|------------------------------------------------------------------------------------------|
| --probe-id |     optional      | Probe serial number.                                                                     |
| --ap       |     optional      | The access port used to read the data - "cm33" or "sysap". The default value is "sysap". |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 device-info
```


# Multiple provisioning and reprovisioning
## Development flow
When the device is in the DEVELOPMENT LCS, its full configuration can be replaced as many times as needed. A development certificate must always be provided via the `--ifx-oem-cert` CLI option.

## Production flow
Once development is complete and you are ready to move to production, generate a new CSR and submit it to obtain a "production" type certificate.

To advance the device to the PRODUCTION LCS, provide the production certificate during provisioning. Once the device is in the PRODUCTION LCS, only the configuration fields permitted by the `reprovisioning` section of the policy can be updated.

Before reprovisioning, remove or leave empty the `--ifx-oem-cert` option.


# Provisioning process
This section describes what happens when the `provision-device` command is executed.
The provisioning process is performed by the _prov_oem_ RAM application located in the _packets/apps_ directory of the project. Before programming the RAM application onto the device, the tool generates an input parameters binary from the data provided in the policy file and signs it with the key specified in the `--key` argument.

The tool then merges the input parameters binary with the RAM application binary into a single package and signs it with the same key.

Once the package is ready, it is programmed onto the device and the provisioning process begins, configuring the device according to the selected policy.


# Using package together with HSM
All the above examples describe the flow when the private keys are available locally on the computer. However, to protect your private keys, the cryptographic operations can be delegated to a Hardware Security Module (HSM). The flow of using the package with an HSM is different from the standard flow because the image must be signed using a different tool provided by the HSM vendor. Data are signed in a few steps: generate unsigned data, provide the data to HSM, grab the signature, and merge the unsigned data with the signature. However, the data has different formats and must be processed by different flows.

## Signing application with HSM
Refer to the [Signing application with HSM](https://github.com/Infineon/edgeprotecttools/blob/master/docs/README_GENERAL.md#signing-application-with-HSM) section.

## Creation and signing a debug token with HSM
The flow:
1. Create a non-signed token.
2. Get the signature using HSM.
3. Add a signature returned by the HSM to the token.

### Step 1
Create a token but do not specify the `--key` option.
```bash
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json --output debug_token_unsigned.bin
```
### Step 2
Use the tools provided by your HSM provider to sign the extended image on the HSM machine. Save the signature returned by the HSM to a file.
### Step 3
Merge the unsigned token and the signature file created by the HSM.
```bash
$ edgeprotecttools merge-bin --image debug_token_unsigned.bin --image signature_hsm.bin --output debug_token_signed.bin
```


## Creation and signing an RMA token with HSM
The flow:
1. Create a non-signed token.
2. Get the signature using HSM.
3. Add a signature returned by the HSM to the token.

### Step 1
In the packets/debug_token.json change the "rma" property to `Enable`. Create a token but do not specify the `--key` option.
```bash
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json --output rma_token_unsigned.bin
```
### Step 2
Use the tools provided by your HSM provider to sign the extended image on the HSM machine. Save the signature returned by the HSM to a file.
### Step 3
Merge the unsigned token and the signature file created by the HSM.
```bash
$ edgeprotecttools merge-bin --image rma_token_unsigned.bin --image signature_hsm.bin --output rma_token_signed.bin
```


# Return Merchandise Authorization (RMA)

The flow for the transition device to the `RMA` lifecycle stage and open DAP.

## RMA token

For the transition of the device into the `RMA` lifecycle stage you need to create a token, which contains the device DIE_ID and is signed with the OEM private key.

For the device in `DEVELOPMENT` LCS, the token must be signed with OEM Development key. 

For the device in `PRODUCTION` LCS, the token must be signed with OEM RoT key. 

There are two types of RMA tokens - "Transit to RMA" and "Open RMA". The tokens can be created with the `debug-token` command and the enabled `rma` property in the token template.

The token template is located in the _packets_ directory of the project. _debug_token.json_ defines the DIE_ID of the devices the token can be applied to. The default template min and max values are applicable for all devices. Modify it for specific devices only if needed. Set "rma" property to `Enable`.

"Transit to RMA" token is used to transit the device to the `RMA` LCS.

### Command: `debug-token`
### Parameters
| Name              | Optional/Required | Description                                                                                                               |
|-------------------|:-----------------:|---------------------------------------------------------------------------------------------------------------------------|
| -T, --template    |     required      | The path to the token template. The template can be found in the _packets_ directory of the project (_debug_token.json_). |
| --key, --key-path |     optional      | The path to the private key to sign the token. If the token to be signed by HSM, do not specify the option.               |
| -o, --output      |     required      | The file where to save the token.                                                                                         |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json -o packets/rma_token.bin --key keys/oem_dev_priv_key.pem
$ edgeprotecttools -t psoc_c3x8 debug-token --template packets/debug_token.json -o packets/rma_token.bin --key keys/oem_rot_priv_key_0.pem
```

## Transition to RMA
The command advances the device lifecycle stage to `RMA`. The token must be signed with the OEM key. 

For the device in `DEVELOPMENT` LCS, the DLM package does not need to be signed, and specifying the `--key` option is unnecessary. 

For the device in `PRODUCTION` LCS, the DLM package must be signed with OEM RoT private key, and specifying the `--key` option is mandatory.

### Command: `transit-to-rma`
### Parameters
| Name              | Optional/Required | Description                                                  |
|-------------------|:-----------------:|--------------------------------------------------------------|
| --token           |     required      | Path to the "Transit to RMA" token.                          |
| --key, --key-path |     optional      | The path to the OEM RoT private key to sign the DLM package. |
| --probe-id        |     optional      | Probe serial number.                                         |

### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 transit-to-rma --token packets/rma_token.bin
$ edgeprotecttools -t psoc_c3x8 transit-to-rma --token packets/rma_token.bin --key keys/oem_rot_priv_key_0.pem
```


# Firmware Update

## Provisioning device with Protected FW policy

This process is intended to configure and deliver the Protected Firmware policy onto the device via a provisioning mechanism. The provisioning can be performed through either the SWD or DFU interface.

1. Update policy `policy_prot_fw.json`
2. From your project directory run the command
    ```bash
    $ edgeprotecttools -t psoc_c3x8 provision-device -p policy/policy_prot_fw.json
    ```

## Protected FW download

1. Make sure the Protected FW image is a binary (.bin, NOT .hex)
2. Sign and wrap the image into MCUBoot (see https://docs.mcuboot.com/) format:
    ```bash
    $ edgeprotecttools sign-image -i flash_app_simple.bin -o unencrypted.bin  --key keys/prot_fw_rot_priv_key_0.pem --public-key-format full --pubkey-encoding raw --signature-encoding raw
    ```
3. Encrypt image 
    ```bash
    $ edgeprotecttools encrypt-aes -i unencrypted.bin -o encrypted.bin --iv 0xd3926e567875c434e9e05ae2d726104c --key keys/prot_fw_enc_key.bin --cipher-mode CBC
    ```
4. Convert encrypted image into hex. Offset must correspond to field `prot_fw_addr` in `prot_fw_policy.json` that was previously programmed to the device
    ```bash
    $ edgeprotecttools bin2hex --image encrypted.bin -o encrypted.hex --offset 0x32000000 
    ```
5. Update policy `policy_prot_fw_dfu.json` with `IV`
    ```json
    {
      "policy": {
        "platform": "psoc_c3p8",
        "version": 1.0,
        "type": "dfu"
      },
      "iv": {
       "description": "IV for encryption",
       "value": "d3926e567875c434e9e05ae2d726104c"
      }
    }
    ```
6. Select the tool used to communicate through the serial interface
    ```bash
    $ edgeprotecttools set-ocd -n serial -p dfuh-tool
    ```
7. Configure serial interface
    ```bash
    $ edgeprotecttools serial-config --protocol uart --hwid COM12 --uart-baudrate 115200 --uart-databits 8 --uart-paritytype None --uart-stopbits 1
    ```
8. Download firmware
    ```bash
    $ edgeprotecttools -t psoc_c3x8 dfu -p policy/policy_prot_fw_dfu.json --image encrypted.hex
    ```

### Command `dfu`
### Parameters
| Name              | Optional/Required | Description                                                                                                                                                     |
|-------------------|:-----------------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -p, --policy      |     required      | The path to the provisioning policy.                                                                                                                            |
| --image           |     required      | Protected firmware image.                                                                                                                                       |
| --key             |     optional      | OEM private key used to sign the DLM package.                                                                                                                   |
| --existing-packet |     optional      | Skip provisioning packet creation and use the existing packet. This may be useful when a packet already exists and the tool does not have to generate it again. |
### Usage example
```bash
$ edgeprotecttools -t psoc_c3x8 dfu -p policy/policy_prot_fw_dfu.json --image encrypted.hex
```