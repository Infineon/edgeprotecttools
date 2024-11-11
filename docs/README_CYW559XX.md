# Table of Contents
- [Secure Certificates](#secure-certificates)
  - [Key Certificate](#key-certificate)
  - [Content Certificate](#content-certificate)
  - [Generate Secure Certificates](#generate-secure-certificates)
- [Secure Image](#secure-image)

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
| Property         | Description                                                                                            |
|------------------|--------------------------------------------------------------------------------------------------------|
| cert_keypair     | Path to the private key used to sign the certificate. Must be the RSA key, 3072 bits in length.        |
| cert_keypair_pwd | Password for the certificate private key. Keep empty if the key is not encrypted by password.          |
| nv_counter       | The Non-Volatile counter value. A value between 0 and 96.                                              |
| next_cert_pubkey | Path to the public key of the next certificate in the chain. Must be the RSA key, 3072 bits in length. |

## Content Certificate
The content certificate is used to load and validate software components.
### Configuration File Parameters
| Property           | Description                                                                                                                                                                                                                                                                                                                |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cert_keypair       | Path to the private key used to sign the certificate. Must be the RSA key, 3072 bits in length.                                                                                                                                                                                                                            |
| cert_keypair_pwd   | Password for the certificate private key. Keep empty if the key is not encrypted by password.                                                                                                                                                                                                                              |
| nv_counter         | The Non-Volatile counter value. A value between 0 and 96.                                                                                                                                                                                                                                                                  |
| load_verify_scheme | The scheme used to verify the software components. Applicable values: <br/>- RAM_LOAD_VERIFY - Load from flash to RAM and verify<br/>- FLASH_VERIFY - Full hash verification in flash without loading to RAM<br/>- RAM_VERIFY - Verify in RAM<br/>- RAM_LOAD - Load from flash into RAM                                    |
| encrypted          | Indicates whether the software components are encrypted.                                                                                                                                                                                                                                                                   |
| crypto_type        | Cryptographic verification and decryption mode. Applicable values:<br/>- PLAIN_IMAGE_HASH - Do hash on plain image<br/>- ENC_IMAGE_HASH - do hash on encrypted image                                                                                                                                                       |
| image_table        | Path to the `.tbl` file generated by ModusToolbox™. The file contains the list of authenticated SW images. The file is located in the project _build_ directory. Each line refers to a single image, with the following data: `<image_file_name> <mem_load addr> <flash_store_addr> <image_max_size> <is_encrypted_flag>`. |

## Generate Secure Certificates
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
The secure image is a hex file that contains the software components and the certificate chain.
The following command creates a secure image by merging key and content certificates to the application.
### Command: `secure-image`
### Parameters
| Name         | Optional/Required | Description                                                                                                                                                                                          |
|--------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --image      |     required      | The path to the application.                                                                                                                                                                         |
| --cert       |     required      | Certificate in DER format. Specify the option multiple times to add multiple certificates. Make sure the order is the following: first key certificate, second key certificate, content certificate. |
| -o, --output |     required      | The path where to save the output HEX file.                                                                                                                                                          |
| --hcd        |     optional      | The path where to save the hardware configuration data (HCD) file. HCD format is required by the Chipload tool to program the device.                                                                |
### Example
```bash
# Create a secure image. The order of the certificates must be the following: first key certificate, second key certificate, content certificate.
$ edgeprotecttools -t cyw559xx secure-image --image mtb-example-threadx-hello-world_download.hex --cert certs/first_key_cert.cer --cert certs/second_key_cert.cer --cert certs/content_cert.cer --output mtb-example-threadx-hello-world_download_APPCERT.hex --hcd mtb-example-threadx-hello-world_download_APPCERT.hcd
```
