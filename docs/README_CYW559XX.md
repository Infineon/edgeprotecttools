# Table of Contents
- [Secure Certificates](#secure-certificates)
  - [Key Certificate](#key-certificate)
  - [Content Certificate](#content-certificate)
  - [Generate Secure Certificates](#generate-secure-certificates)
- [Secure Image](#secure-image)
- [Encrypt Application](#encrypt-application)
- [OTA Image](#ota-image)
- [Read Device CSR](#read-device-csr)
- [Read Device SOC ID](#read-device-soc-id)

# Secure Certificates
Secure boot is based on certificate chain mechanisms using the RSA private and public key schemes.
The certificate structure consists of the following parts:
* Header, which includes information such as certificate type, version, size, owner, flags, and validity
period.
* Certificate data, which includes public key and other information that must be signed.
* Signature, which is calculated over the header and certificate data by using RSA PSS scheme.

The link between a certificate and its next certificate is that the certificate includes the hash of the public key
of the next certificate.
There are two different types of certificates:
* Key certificate
* Content certificate

The certificate chain is composed of three self-signed certificates. Self-signed means that the public key 
is included in the certificate and the certificate itself is signed with the corresponding private key. 
The chain consists of two key certificates and one content certificate.

## Key Certificate
The key certificate is used to validate the hash of the public key of next certificate in the chain.
### Configuration File Parameters
| Property         | Description                                                                                             |
|------------------|---------------------------------------------------------------------------------------------------------|
| cert_keypair     | Path to the private key used to sign the certificate. Must be the RSA key of the 3072-bit size.         |
| cert_keypair_pwd | Password for the certificate private key. Keep empty if the key is not encrypted by password.           |
| nv_counter       | The Non-Volatile counter value. A value between 0 and 96.                                               |
| next_cert_pubkey | Path to the public key of the next certificate in the chain. Must be the RSA key of the 3072-bit size.  |

## Content Certificate
The content certificate is used to load and validate software components.
### Configuration File Parameters
| Property           | Description                                                                                                                                                                                                                                                                                                                |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cert_keypair       | Path to the private key used to sign the certificate. Must be the RSA key of the 3072-bit size.                                                                                                                                                                                                                            |
| cert_keypair_pwd   | Password for the certificate private key. Keep empty if the key is not encrypted by password.                                                                                                                                                                                                                              |
| nv_counter         | The Non-Volatile counter value. A value between 0 and 96.                                                                                                                                                                                                                                                                  |
| load_verify_scheme | The scheme used to verify the software components. Applicable values: <br/>- RAM_LOAD_VERIFY - Load from flash to RAM and verify<br/>- FLASH_VERIFY - Full hash verification in flash without loading to RAM<br/>- RAM_VERIFY - Verify in RAM<br/>- RAM_LOAD - Load from flash into RAM                                    |
| encrypted          | Indicates whether the software components are encrypted.                                                                                                                                                                                                                                                                   |
| crypto_type        | Cryptographic verification and decryption mode. Applicable values:<br/>- PLAIN_IMAGE_HASH - Do hash on plain image<br/>- ENC_IMAGE_HASH - do hash on encrypted image                                                                                                                                                       |
| image_table        | Path to the `.tbl` file generated by ModusToolbox™. The file contains the list of authenticated SW images. The file is located in the project _build_ directory. Each line refers to a single image, with the following data: `<image_file_name> <mem_load addr> <flash_store_addr> <image_max_size> <is_encrypted_flag>`. |

## Generate Secure Certificates
Generates the key or content certificates.
### Command: `secure-cert`
### Parameters
| Name         | Optional/Required | Description                                                    |
|--------------|:-----------------:|----------------------------------------------------------------|
| -c, --config |     required      | The path to the key or content certificate configuration file. |
| -o, --output |     required      | The path to certificate output file.                           |
### Example
```bash
# Generate the key certificates
$ edgeprotecttools -t cyw559xx secure-cert --config certs/key_cert_config.json --output certs/first_key_cert.cer
$ edgeprotecttools -t cyw559xx secure-cert --config certs/key_cert_config.json --output certs/second_key_cert.cer

# Generate the content certificate
$ edgeprotecttools -t cyw559xx secure-cert --config certs/content_cert_config.json --output certs/content_cert.cer
```

# Secure Image
The secure image is a HEX file that contains the software components and the certificate chain.
The following command creates a secure image by merging key and content certificates to the application.
### Command: `secure-image`
### Parameters
| Name         | Optional/Required | Description                                                                                                                                                                                          |
|--------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --image      |     required      | The path to the application HEX file.                                                                                                                                                                |
| --cert       |     required      | Certificate in DER format. Specify the option multiple times to add multiple certificates. Make sure the order is the following: first key certificate, second key certificate, content certificate. |
| -o, --output |     required      | The path where to save the output HEX file.                                                                                                                                                          |
| --hcd        |     optional      | The path where to save the hardware configuration data (HCD) file. HCD format is required by the Chipload tool to program the device.                                                                |
### Example
```bash
# Create a secure image. The order of the certificates must be the following: first key certificate, second key certificate, content certificate.
$ edgeprotecttools -t cyw559xx secure-image --image mtb-example-threadx-hello-world_download.hex --cert certs/first_key_cert.cer --cert certs/second_key_cert.cer --cert certs/content_cert.cer --output mtb-example-threadx-hello-world_download_APPCERT.hex --hcd mtb-example-threadx-hello-world_download_APPCERT.hcd
```

# Encrypt Application
Encrypts the application.
### Command: `encrypt`
### Limitations
The encryption feature is intended solely for development purposes and should not be used in production. Note that the initialization vector for encryption is currently fixed to 01010101010101010000000000000001.
### Parameters
| Name         | Optional/Required | Description                                                  |
|--------------|:-----------------:|--------------------------------------------------------------|
| --image      |     required      | The path to the application HEX file.                        |
| --key        |     required      | The path to the AES-128 key used to encrypt the application. |
| -o, --output |     required      | The encrypted image output path.                             |
### Example
```bash
# Encrypt application
$ edgeprotecttools -t cyw559xx encrypt --image mtb-example-threadx-hello-world_download_APPCERT.hex --key kce_app.bin --iv 0102030405060708090A0B0C --output mtb-example-threadx-hello-world_download_APPCERT_ENCRYPTED.hex
```

# OTA Image
The OTA image is a BIN file that is intended to be run by the OTA driver.
### Command: `ota-image`
### Parameters
| Name         | Optional/Required | Description                                                                                                                                                                                          |
|--------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --image      |     required      | The path to the application HEX file.                                                                                                                                                                |
| -o, --output |     required      | The path where to save the output BIN file.                                                                                                                                                          |
### Example
```bash
# Create an OTA image
$ edgeprotecttools -t cyw559xx ota-image --image mtb-example-threadx-hello-world_download_APPCERT.hex --output mtb-example-threadx-empty-app_APP_CYW955913EVK-01_APPCERT.ota.bin
```

# Read Device CSR
Reads the device CSR from CYW559xx.
### Command: `get-csr`
### Parameters
| Name         | Optional/Required | Description                                                                     |
|--------------|:-----------------:|---------------------------------------------------------------------------------|
| -o, --output |     required      | The path where to save the output CSR file. The output file is in DER encoding. |
| --csr-id'    |     optional      | The CSR ID. The default value is 0.                                             |
### Example
```bash
# Read the device CSR from CYW559xx
$ edgeprotecttools -t cyw559xx get-csr --output csr.der
```

# Read Device SOC ID
Reads the device SOC ID from CYW559xx.
### Command: `read-soc-id`
### Parameters
| Name         | Optional/Required | Description                                                                     |
|--------------|:-----------------:|---------------------------------------------------------------------------------|
| -o, --output |     optional      | The path where to save the result.                                              |
### Example
```bash
# Read the device SOC ID from CYW559xx
$ edgeprotecttools -t cyw559xx read-soc-id
```
