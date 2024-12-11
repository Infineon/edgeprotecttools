# Table of Contents
- [Tool help](#tool-help)
- [Create key](#create-key)
- [Convert key](#convert-key)
- [Export public key](#export-public-key)
- [Sign image](#sign-image)
- [Add metadata to image](#add-metadata-to-image)
- [Extract image protected data](#extract-image-protected-data)
- [Add signature to image](#add-signature-to-image)
- [Create bin](#create-bin)
- [Convert bin to hex](#convert-bin-to-hex)
- [Convert hex to bin](#convert-hex-to-bin)
- [Convert hex to hcd](#convert-hex-to-hcd)
- [Image verification](#image-verification)
- [Merging hex images](#Merging-hex-images)
- [Merging bin images](#Merging-bin-images)
- [Create multi-image packets](#create-multi-image-packets)
- [Splitting images](#splitting-images)
- [Extracting data](#extracting-data)
- [Hash files](#hash-files)
- [Serial interface configuration](#serial-interface-configuration)
- [HSM](#hsm)
- [AES encryption](#aes-encryption)

This section describes a command line interface for general commands, which are not related to a specific target.

## Tool help
To see the list of general commands:
```bash
$ edgeprotecttools --help
```
To see the list of options for a specific command:
```bash
$ edgeprotecttools <COMMAND> --help
```

## Create key
Creates an asymmetric or a symmetric key.
### Command: `create-key`
### Parameters
| Name         | Optional/Required | Description                                                                                                                                                                                                                                                                                                                 |
|--------------|:-----------------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --key-type   |     required      | A key type. One of the following: ECDSA-P256, ECDSA-P384, RSA2048, RSA3072, RSA4096, AES128, AES256.                                                                                                                                                                                                                        |
| -o, --output |     required      | Private and public key paths or a single key path. For the asymmetric specify two paths separated by space `[private] [public]`. For the symmetric key specify one key path `[key]`.                                                                                                                                        |
| --template   |     optional      | A JSON file or binary file containing key public numbers. The template is typically located in the _keys_ or _packets_ directory of the project.  This option is useful for converting key public numbers exported from an HSM to a standard key file format. Note that the binary file is compatible only with ECDSA keys. |
| --format     |     optional      | A key format. One of the following: PEM, DER, JWK. The default value is "PEM".                                                                                                                                                                                                                                              |
| --kid        |     optional      | Key ID. Applicable to JWK only.                                                                                                                                                                                                                                                                                             |
| --byteorder  |     optional      | Input data byte order used to create EC private key from bytes. Available values: `big`, `little`. Default: `big`                                                                                                                                                                                                           |
### Usage example
```bash
# Create ECDSA-P256 key pair in PEM format
$ edgeprotecttools create-key --key-type ECDSA-P256 --output private.pem public.pem

# Create ECDSA-P256 key pair in JWK format and a specific key ID
$ edgeprotecttools create-key --key-type ECDSA-P256 --output private.json public.json --format JWK --kid 1

# Create symmetric key
$ edgeprotecttools create-key --key-type AES128 --output aes-128.bin

# Create ECDSA-P256 key from the template containing public numbers
$ edgeprotecttools create-key --key-type ECDSA-P256 --template keys/ec_key_tmpl.json -o public.pem

# Create ECDSA-P256 key from the binary file containing public numbers
$ edgeprotecttools create-key --key-type ECDSA-P256 --template ec_public_numbers.bin -o public.pem
```


## Convert key
Converts an asymmetric key to a different encoding or/and format.

| Encoding and format      |         Key type         | Description                                                                                                                                                                                                   |
|--------------------------|:------------------------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PEM`                    | `ECDSA`, `RSA`, `X25519` | `Base64` encoded key. The format is `TraditionalOpenSSL` for private keys and `SubjectPublicKeyInfo` for public keys.                                                                                         |
| `PEM-SUBJPUBKEYINFO`     | `ECDSA`, `RSA`, `X25519` | `Base64` encoded key in the `SubjectPublicKeyInfo` format for public keys.                                                                                                                                    |
| `PEM-PKCS1`              |     `RSA`, `X25519`      | `Base64` encoded key in the `PKCS1` format for public keys.                                                                                                                                                   |
| `PEM-OPENSSL`            | `ECDSA`, `RSA`, `X25519` | `Base64` encoded key in the `TraditionalOpenSSL` format for private keys.                                                                                                                                     |
| `PEM-PKCS8`              | `ECDSA`, `RSA`, `X25519` | `Base64` encoded key in the `PKCS8` format for private keys.                                                                                                                                                  |
| `DER`                    | `ECDSA`, `RSA`, `X25519` | `DER` encoded key. The format is `TraditionalOpenSSL` for private keys and `SubjectPublicKeyInfo` for public keys.                                                                                            |
| `DER-SUBJPUBKEYINFO`     | `ECDSA`, `RSA`, `X25519` | `DER` encoded key in the `SubjectPublicKeyInfo` format for public keys.                                                                                                                                       |
| `DER-PKCS1`              |     `RSA`, `X25519`      | `DER` encoded key in the `PKCS1` format for public keys.                                                                                                                                                      |
| `DER-OPENSSL`            | `ECDSA`, `RSA`, `X25519` | `DER` encoded key in the `TraditionalOpenSSL` format for private keys.                                                                                                                                        |
| `DER-PKCS8`              | `ECDSA`, `RSA`, `X25519` | `DER` encoded key in the `PKCS8` format for private keys.                                                                                                                                                     |
| `JWK`                    | `ECDSA`, `RSA`, `X25519` | JSON Web Key.                                                                                                                                                                                                 |
| `C_ARRAY`                | `ECDSA`, `RSA`, `X25519` | Saves `DER` encoded key bytes as a C-array.<br>For private keys the format is `PKCS8`.<br>For public keys the format is `SubjectPublicKeyInfo` except the `RSA` key. The `RSA` public keys format is `PKCS1`. |
| `C_ARRAY-SUBJPUBKEYINFO` | `ECDSA`, `RSA`, `X25519` | Saves `DER` encoded key bytes as a C-array. The format is `SubjectPublicKeyInfo` for public keys.                                                                                                             |
| `C_ARRAY-PKCS1`          |     `RSA`, `X25519`      | Saves `DER` encoded key bytes as a C-array. The format is `PKCS1` for public keys.                                                                                                                            |
| `C_ARRAY-OPENSSL`        | `ECDSA`, `RSA`, `X25519` | Saves `DER` encoded key bytes as a C-array. The format is `TraditionalOpenSSL` for private keys.                                                                                                              |
| `C_ARRAY-PKCS8`          | `ECDSA`, `RSA`, `X25519` | Saves `DER` encoded key bytes as a C-array. The format is `PKCS8` for private keys.                                                                                                                           |
| `SECURE_BOOT`            |          `RSA`           | Generates RSA public key modulus, exponent, and additional coefficients and formats it as Secure boot RSA public key format. Accepts only `RSA` public keys.                                                  |
| `X962`                   |         `ECDSA`          | Exports key public numbers to a binary file. Accepts only `ECDSA` public keys.                                                                                                                                |

### Command: `convert-key`
### Parameters
| Name                  | Optional/Required | Description                                                                                      |
|-----------------------|:-----------------:|--------------------------------------------------------------------------------------------------|
| -f, --fmt, --format   |     required      | Output key format. Available values: `PEM`, `DER`, `DER-PKCS8`, `JWK`, `C_ARRAY`, `SECURE_BOOT`. |
| -k, --key, --key-path |     required      | Input key path. Accepts keys in `PEM`, `DER`, `JWK` formats.                                     |
| -o, --output          |     required      | Output file.                                                                                     |
| --endian              |     optional      | Byte order. Available values: `big`, `little`. Default value: `little`                           |
| --password            |     optional      | Private key password.                                                                            |
| --var-name            |     optional      | Variable name in C array                                                                         |
### Usage example
```bash
# Convert PEM encoded public key to DER in PKCS1 format
$ edgeprotecttools convert-key --fmt DER-PKCS1 -k key.pem -o key.der

# Convert DER encoded private key to PEM in PKCS8 format
$ edgeprotecttools convert-key --fmt PEM-PKCS8 -k key.der -o key.pem

# Convert PEM encoded private key to C-array in PKCS8 format
$ edgeprotecttools convert-key --fmt C_ARRAY-PKCS8 -k privkey.pem -o privkey.h --var-name priv_key
```


## Export public key
Exports a public key from a private key.

| Output format |    Key type    | Description                                                                         |
|---------------|:--------------:|-------------------------------------------------------------------------------------|
| `PEM`         | `ECDSA`, `RSA` | PEM-encoded key conforming to the `SubjectPublicKeyInfo` structure for public keys. |
| `DER`         | `ECDSA`, `RSA` | DER-encoded key conforming to the `SubjectPublicKeyInfo` structure for public keys. |
| `JWK`         | `ECDSA`, `RSA` | JWK format.                                                                         |

### Command: `export-public-key`
### Parameters
| Name           | Optional/Required | Description                                                               |
|----------------|:-----------------:|---------------------------------------------------------------------------|
| -k, --key-path |     required      | Path to the private key of the `PEM`, `DER`,  or `JWK` format.            |
| -o, --output   |     required      | Output file.                                                              |
| -f, --format   |     optional      | Output key format. Available values: `PEM`, `DER`, `JWK`. Default: `PEM`. |
### Usage example
```bash
$ edgeprotecttools export-public-key --format PEM -k private_key.pem -o public_key.pem
```


## Sign image
Signs a user application with a key. Optionally encrypts the signed application.
### Command: `sign-image`
### Parameters
| Name                   | Optional/Required  | Description   |
| ---------------------- |:------------------:| ------------- |
| -i, --image            | required           | The user application file (bin or hex). |
| -o, --output           | required           | The signed image output file (bin or hex). |
| --key, --key-path      | required           | The path to the key used to sign the image. |
| -R, --erased-val       | optional           | The value, which is read back from erased flash - "0" or "0xff". The default value is "0". |
| -H, --header-size      | optional           | Sets the image header size. The default value is 0x400. The header will be padded to the specified size. |
| -S, --slot-size        | optional           | Sets the maximum slot size. The default value is 0x20000. |
| --min-erase-size       | optional           | Sets minimum erase size. The default 0x8000. |
| --image-version        | optional           | Sets the image version in the image header. The format is `<major>.<minor>.<revision>.<build>`. |
| -s, --security-counter | optional           | Specify the value of security counter. Use the `auto` keyword to automatically generate it from the image version. |
| --align                | optional           | Sets the flash alignment - 1, 2, 4, or 8. The default value is 8. |
| --public-key-format    | optional           | The public key format - full key or hash of the key. Applicable one of the following values: "hash", or "full". The default value is "hash". |
| --pubkey-encoding      | optional           | The public key encoding - "der" or "raw". The default value is "der". |
| --signature-encoding   | optional           | The signature encoding - ASN.1 or raw data. Applicable one of the following values: "asn1", or "raw". The default value is "asn1". |
| --pad                  | optional           | Adds padding to the image trailer. Pads the image from the end of the TLV area up to the slot size. _boot_magic_ is always at the very end after the padding. |
| --confirm              | optional           | Adds image OK status to the trailer. Pads the image from the end of the TLV area up to the slot size and sets the image OK byte to 0x01 (the eighth byte from the end). The padding is required for this feature and is always applied. _boot_magic_ is always at the very end after the padding. |
| --overwrite-only       | optional           | Use overwrite mode instead of swap. |
| --boot-record          | optional           | Creates CBOR-encoded boot record TLV. Represents the role of the software component (e.g. CoFM for coprocessor firmware). Used for measured boot and data sharing. Maximum length is 12 characters. |
| --hex-addr             | optional           | Adjusts the address in the hex output file. |
| -L, --load-addr        | optional           | Load address for image when it should run from RAM. |
| -F, --rom-fixed        | optional           | Set flash address the image is built for. |
| -M, --max-sectors      | optional           | When padding allow for this amount of sectors. The default value is 128. |
| --save-enctlv          | optional           | When upgrading, save encrypted key TLVs instead of plain keys. Enable when BOOT_SWAP_SAVE_ENCTLV config option was set. |
| -d, --dependencies     | optional           | Adds dependence on another image. The format: `(<image_ID>,<image_version>), ...`. |
| --encrypt              | optional           | The path to the public key used to encrypt the image. |
| --protected-tlv        | optional           | The custom TLV to be placed into a protected area (the signed part). Add the "0x" prefix for the value to be interpreted as an integer, otherwise it will be interpreted as a string. Specify the option multiple times to add multiple TLVs. The format is `[tag] [value]`. |
| --tlv                  | optional           | The custom TLV to be placed into a non-protected area. Add the "0x" prefix for the value to be interpreted as an integer, otherwise it will be interpreted as a string. Specify the option multiple times to add multiple TLVs. The format is `[tag] [value]`. |
| --remove-tlv           | optional           | Removes TLV with the specified ID. |
| --enckey               | optional           | Encryption key. |
| --encrypt_addr         | optional           | Starting address for data encryption. |
| --nonce_output         | optional           | The path where to save the nonce. |
### Usage example
```bash
# Sign binary and save to a binary
$ edgeprotecttools sign-image --image image.bin --output image_signed.bin --key private.pem

# Sign binary and save to hex with a specific address
$ edgeprotecttools sign-image --image image.bin --output image_signed.hex --key private.pem --hex-addr 0x10000000

# Sign image and store public key and signature as raw data
$ edgeprotecttools sign-image -i image.bin --key private.pem --public-key-format full --pubkey-encoding raw --signature-encoding raw --header-size 0x200 --output image_signed.bin --protected-tlv 0x0A 0x77777777 --protected-tlv 0x0B 0x33333333 --protected-tlv 0x0C 0x11111111
```


## Add metadata to image
Adds MCUboot metadata to a firmware image ([mcuboot header](https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md#image-format)), but does not sign the image. Usually, this command is useful for signing images with a Hardware Security Module.
### Command: `image-metadata`
### Parameters
| Name                   | Optional/Required  | Description   |
| ---------------------- |:------------------:| ------------- |
| -i, --image            | required           | The user application file (bin or hex). |
| -o, --output           | required           | The image with metadata output file (bin). |
| --decrypted            | optional           | The path where to save decrypted image payload (bin). Specify this option if the image is encrypted and provide the decrypted image to HSM because the signature is calculated on the unsigned data. |
| -R, --erased-val       | optional           | The value, which is read back from erased flash - "0" or "0xff". The default value is "0". |
| -H, --header-size      | optional           | Sets the image header size. The default value is 0x400. The header will be padded to the specified size. |
| -S, --slot-size        | optional           | Sets the maximum slot size. The default value is 0x20000. |
| --min-erase-size       | optional           | Sets minimum erase size. The default 0x8000. |
| --image-version        | optional           | Sets the image version in the image header. The format is `<major>.<minor>.<revision>.<build>`. |
| -s, --security-counter | optional           | Specify the value of security counter. Use the `auto` keyword to automatically generate it from the image version. |
| --align                | optional           | Sets the flash alignment - 1, 2, 4, or 8. The default value is 8. |
| --pubkey               | optional           | The public key to be added to the image. |
| --public-key-format    | optional           | The public key format - full key or hash of the key. Applicable one of the following values: "hash", or "full". The default value is "hash". |
| --pubkey-encoding      | optional           | The public key encoding - "der" or "raw". The default value is "der". |
| --pad                  | optional           | Adds padding to the image trailer. |
| --confirm              | optional           | Adds image OK status to the trailer. |
| --overwrite-only       | optional           | Use overwrite mode instead of swap. |
| --boot-record          | optional           | Creates CBOR-encoded boot record TLV. Represents the role of the software component (e.g. CoFM for coprocessor firmware). Maximum length is 12 characters. |
| --hex-addr             | optional           | Adjusts the address in the hex output file. |
| -L, --load-addr        | optional           | Load address for image when it should run from RAM. |
| -F, --rom-fixed        | optional           | Set flash address the image is built for. |
| -M, --max-sectors      | optional           | When padding allow for this amount of sectors. The default value is 128. |
| --save-enctlv          | optional           | When upgrading, save encrypted key TLVs instead of plain keys. Enable when BOOT_SWAP_SAVE_ENCTLV config option was set. |
| -d, --dependencies     | optional           | Adds dependence on another image. The format: `(<image_ID>,<image_version>), ...`. |
| --encrypt              | optional           | The path to the public key used to encrypt the image. |
| --protected-tlv        | optional           | The custom TLV to be placed into a protected area (the signed part). Add the "0x" prefix for the value to be interpreted as an integer, otherwise it will be interpreted as a string. Specify the option multiple times to add multiple TLVs. The format is `[tag] [value]`. |
| --tlv                  | optional           | The custom TLV to be placed into a non-protected area. Add the "0x" prefix for the value to be interpreted as an integer, otherwise it will be interpreted as a string. Specify the option multiple times to add multiple TLVs. The format is `[tag] [value]`. |
| --remove-tlv           | optional           | Removes TLV with the specified ID. |
| --enckey               | optional           | Encryption key. |
| --encrypt_addr         | optional           | Starting address for data encryption. |
| --nonce_output         | optional           | The path where to save the nonce. |
### Usage example
```bash
# Add MCUboot metadata with custom TLVs
$ edgeprotecttools image-metadata --image image.hex --output image_meta.bin --protected-tlv 0x0A 0x77777777 --protected-tlv 0x0B 0x33333333 --tlv 0x55 0x29

# Add MCUboot metadata and encrypt the image
$ edgeprotecttools sign-image --image image.bin --output image_meta.bin --encrypt pubkey.pem --decrypted image_meta.bin

# Sign image and store public key and signature as raw data
$ edgeprotecttools sign-image -i image.bin --key private.pem --public-key-format full --pubkey-encoding raw --signature-encoding raw --header-size 0x200 --output image_signed.bin --protected-tlv 0x0A 0x77777777 --protected-tlv 0x0B 0x33333333 --protected-tlv 0x0C 0x11111111
```
**IMPORTANT**: 
1. When preparing an image to be signed by HSM, the output format must always be binary. HSM must calculate the signature from the raw data, not from hex.
2. In case of using image encryption, provide the path where to save the decrypted payload. Then provide the decrypted data to HSM. Image signature is calculated based on decrypted data.


## Extract image protected data
The MCUboot formatted image consists of a header, a payload, a protected TLV area, and a non-protected TLV area. 
A header, a payload, and a protected TLV are the data that must be signed. 
A non-protected TLV area must not be included in a signature. 
This command extracts a part of an image to be signed.
### Command: `extract-payload`
### Parameters
| Name          | Optional/Required  | Description     |
| ------------- |:------------------:| --------------- |
| --image       | required           | The image with MCUboot metadata - the binary format only. |
| -o, --output  | required           | The path where to save the image to be signed - the binary format only. |
### Usage example
```bash
$ edgeprotecttools extract-payload --image image_meta.bin --output image_payload.bin
```


## Add signature to image
Adds a previously generated signature to an existing image of the MCUboot format.
### Command: `add-signature`
### Parameters
 | Name            | Optional/Required  | Description     |
| --------------- |:------------------:| --------------- |
| --image         | required           | The binary image with MCUboot metadata. |
| -s, --signature | required           | The binary file containing a digital signature. |
| --alg           | required           | The signature algorithm. One of the following values: "ECDSA-P256", "RSA2048", "RSA4096".
| -o, --output    | required           | The binary file where to save the signed image. |
### Usage example
```bash
$ edgeprotecttools add-signature --image image_meta.bin --signature signature.bin --output image_signed.bin
```


## Create bin
Dumps hex string to a binary file.
### Command: `bin-dump`
### Parameters
| Name         | Optional/Required | Description |
| ------------ |:-----------------:| ----------- |
| --data       | optional          | Hex string.|
| --random     | optional          | Generate random binary of specified length (e.g. `--random 12` generates a random 12-byte binary file).|
| -o, --output | required          | Output file.|
### Usage example
```bash
# Dump hex string to a binary file
$ edgeprotecttools bin-dump --data 0011223344556677AABBCCDDEEFF --output bindump.bin

# Dump random 12 bytes to a binary file
$ edgeprotecttools bin-dump --random 12 --output bindump.bin
```


## Convert bin to hex
Converts an image of the bin format to hex format.
### Command: `bin2hex`
### Parameters
| Name          | Optional/Required  | Description     |
| ------------- |:------------------:| --------------- |
| --image       | required           | Input bin file.  |
| -o, --output  | required           | Output hex file. |
| --offset      | optional           | Starting address offset for loading bin. |
### Usage example
```bash
$ edgeprotecttools bin2hex --image image.bin --output image.hex --offset 0x20000
```


## Convert hex to bin
Converts an image of the hex format to bin format.
### Command: `hex2bin`
### Parameters
| Name          | Optional/Required  | Description     |
| ------------- |:------------------:| --------------- |
| --image       | required           | Input hex file.  |
| -o, --output  | required           | Output bin file. |
| --start       | optional           | Start of address range. |
| --end         | optional           | End of address range. |
| --size        | optional           | Size of resulting file (in bytes). |
| --pad         | optional           | Padding byte. |
### Usage example
```bash
# Convert entire hex file
$ edgeprotecttools hex2bin --image image.hex --output image.bin

# Convert 1024 bytes starting from address 0x20000000
$ edgeprotecttools hex2bin --image image.hex --output image.bin --start 0x20000000 --size 1024
```


## Convert hex to hcd
Converts Intel HEX to Infineon HCD format. Hardware configuration data (HCD) format is required by the Chipload tool to program the device. 
### Command: `hex2hcd`
### Parameters
| Name         | Optional/Required | Description           |
|--------------|:-----------------:|-----------------------|
| --input      |     required      | Input Intel HEX file. |
| -o, --output |     required      | Output HCD file.      |
### Usage example
```bash
# Convert Intel HEX to Infineon HCD format
$ edgeprotecttools hex2hcd --input image.hex --output image.hcd
```


## Image verification
Verifies an image with a key.
### Command: `verify-image`
### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --image           | required           | The path to the image. |
| --key, --key-path | optional           | The path to the public key. |
### Usage example
```bash
$ edgeprotecttools verify-image --image image.bin --key public.pem
```


## Merging hex images
Merges two or more different hex files into one.
### Command: `merge-hex`
### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --image           | required           | The path to the hex file to merge. Specify the option multiple times for each image. |
| --output          | required           | The path to the merged image. |
| --overlap         | optional           | Action on the overlap of data or starting address. One of the following values: "error" - raises error; "ignore" - ignores other data and keeps current data in the overlapping region; "replace" - replaces data with other data in the overlapping region. The default value is "error. |
### Usage example
```bash
$ edgeprotecttools merge-hex --image image1.hex --image image2.hex --image image3.hex --output merged.hex --overlap ignore
```


## Merging bin images
Merges two or more different bin files into one.
### Command: `merge-bin`
### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --image           | required           | The path to the bin file to merge. Specify the option multiple times for each image. |
| --output          | required           | The path to the merged image. |
### Usage example
```bash
$ edgeprotecttools merge-bin --image image1.bin --image image2.bin --image image3.bin --output merged.bin
```

## Create multi-image packets
Create multi-image COSE packet from provided hex image.
### Command: `multi-image-cbor`
### Parameters
| Name              | Optional/Required | Description                                                                                                                                                                  |
|-------------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -i, --image       |     required      | Path to the hex image.                                                                                                                                                       |
| -o, --output      |     required      | Output path.                                                                                                                                                                 |
| --segment         |     optional      | Custom segments to specify segmentation of the file. Specify the option multiple times to add more segments. The format is `[address] [size]`. Minimum number of options: 2. |
| --key, --key-path |     optional      | Private key path to sign message.                                                                                                                                            |
| --algorithm       |     optional      | Signature algorithm. Available values: `ES256`, `ES384`, `RS256`, `RS384`.                                                                                                   |
| --signature       |     optional      | Signature path to add to the message.                                                                                                                                        |
| --erased-val      |     optional      | Value to fill the spaces between the segments. Default: `0`.                                                                                                                 |
### Usage example
```bash
$ edgeprotecttools multi-image-cbor -i image.hex -o multi_image.bin --segment 0x10000000 256 --segment 0x13400000 128 --key ec256.pem
```


## Splitting images
Extracts a segment from the hex file.
### Command: `hex-segment`
### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --image           | required           | The path to the hex file. |
| --addr            | required           | Address of the segment. |
| --output          | required           | The path to the hex file where to save the segment. |
### Usage example
```bash
$ edgeprotecttools hex-segment --image image.hex --addr 0x14000000 --output segment.hex
```

## Extracting data
Extracts data from the hex file.
### Command: `hex-dump`
### Parameters
| Name         | Optional/Required | Description                                                   |
|--------------|:-----------------:|---------------------------------------------------------------|
| -i, --image  |     required      | The path to the hex file.                                     |
| -o, --output |     required      | The bin file where to save the data.                          |
| --address    |     required      | Address of the data.                                          |
| --size       |     required      | Size of the data.                                             |
| --erased-val |     optional      | Value to fill the spaces between the segments. Default: `0`.  |

### Usage example
```bash
$ edgeprotecttools hex-dump --image image.hex --address 0x14000000 --size 0x2000 --output data.bin
```


## Hash files
Calculates the hash of the data in the file.
### Command: `hash`
### Parameters
| Name         | Optional/Required | Description                                               |
|--------------|:-----------------:|-----------------------------------------------------------|
| -i, --input  |     required      | Path to the input file.                                   |
| -a, --alg    |     required      | Hash algorithm. Available values: `SHA256`                |
| -o, --output |     optional      | The path to the output binary (.bin) or text (.txt) file. |
### Usage example
#### Print hash to stdout
```bash
$ edgeprotecttools hash -i file.bin -a SHA256
```
#### Save hash to file
```bash
$ edgeprotecttools hash -i file.bin -a SHA256 -o hash.txt
```


## Serial interface configuration
Configures serial interface connection.
### Command: `serial-config`
### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --protocol        | optional           | Serial communication protocol. Available values: "uart", "i2c", "spi".  |
| --hwid            | optional           | Specifies the ID of the hardware. If this option is skipped, the first appropriate device found will be used. |
| --uart-baudrate   | optional           | Sets the baud rate for the UART protocol. |
| --uart-databits   | optional           | Sets the number of data bits for the UART protocol. |
| --uart-paritytype | optional           | Sets the parity type for the UART protocol. Available values: "None", "Odd", "Even". |
| --uart-stopbits   | optional           | Sets the stop bits for the UART protocol. Available values: 1, 1.5, 2. |
| --i2c-address     | optional           | Sets the address for the I2C protocol. An integer value in the range 8 - 120. |
| --i2c-speed       | optional           | Sets the speed for the I2C protocol in kHz. Available values: 50, 100, 400, 1000. |
| --spi-clockspeed  | optional           | Sets the clock speed for the SPI protocol in MHz. |
| --spi-mode        | optional           | Sets the mode for the SPI protocol in binary. Available values: "00", "01", "10", "11". |
| --spi-lsb-first   | optional           | Specifies that the least-significant bit be sent first for the SPI protocol. Otherwise, the most-significant bit will be sent first. |
### Usage example
```bash
# UART configuration
$ edgeprotecttools serial-config --protocol uart --hwid COM3 --uart-baudrate 115200 --uart-databits 8 --uart-paritytype None --uart-stopbits 1
# I2C configuration
$ edgeprotecttools serial-config --protocol uart --hwid COM3 --i2c-address 12 --i2c-speed 400
# SPI configuration
$ edgeprotecttools serial-config --protocol uart --hwid COM3 --spi-clockspeed 1 --spi-mode 00
```

# HSM
## Signing application with HSM
The flow:
1. Add metadata to the image (header, protected and unprotected TLVs) to convert it into [MCUboot format](https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md#image-format).
2. Extract payload - extract a part of the image to be signed.
3. Sign the payload with HSM.
4. Add the signature returned by HSM to the image with metadata, created in the first step.

### Step 1
Add metadata to the image - [mcuboot header](https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md#image-format), protected TLV, and unprotected TLV.
```bash
$ edgeprotecttools image-metadata --image image.hex --output image_meta.bin
```
__IMPORTANT:__ in case of using image encryption, provide an output file for the decrypted payload. Image signature is calculated based on decrypted data.
```bash
$ edgeprotecttools image-metadata --image image.hex --output image_meta.bin --encrypt keys/public0.pem --decrypted image_meta_decrypted.bin
```
__NOTE:__ next steps manipulate with binary files only.
### Step 2
The MCUboot format image consists of the part to be signed, and the part not to be signed. To calculate the signature correctly, from the image with metadata extract a part to be signed.
```bash
$ edgeprotecttools extract-payload --image image_meta.bin --output image_payload.bin
```
__IMPORTANT:__ in case of using image encryption, make sure to specify the decrypted payload to HSM. Image signature is calculated based on decrypted data.
```bash
$ edgeprotecttools extract-payload --image image_decrypted.bin --output image_payload.bin
```
### Step 3
Use the tools provided by your HSM vendor to sign the payload. Save the signature returned by the HSM to a file. The format of the MCUboot signature is ASN.1 (binary decoded).
### Step 4
Run the _add-signature_ command and provide the signature file created by the HSM. As an input image, use the image with metadata created in  Step #1.
```bash
$ edgeprotecttools add-signature --image image_meta.bin --output image_signed.bin --signature signature_asn.bin
```

## Signing multi-image packet with HSM

The flow:
1. Generate a non-signed multi-image packet with data to be cryptographically protected.
2. Get the signature from HSM.
3. Generate a packet containing protected data and the signature.

### Step 1
Generate a non-signed multi-image packet. It is also required to provide signature algorithm at this point.
```bash
$ edgeprotecttools multi-image-cbor --image image.hex --output unsigned_packet.bin --algorithm ES256 --segment 0x10000000 256 --segment 0x13400000 128
```

### Step 2
Sign the unsigned packet created in the previous step using your HSM and save the signature to `signature.bin`

### Step 3
Generate signed packet

```bash
$ edgeprotecttools multi-image-cbor --image unsigned_packet.bin --output signed_packet.bin --algorithm ES256 --signature signature.bin
```

# AES encryption

Encrypts a binary file using AES.
Supports AES-128, AES-256 according to the key size.

### Command: `encrypt-aes`
### Parameters
| Name              | Optional/Required | Description                                                                                                                              |
|-------------------|:-----------------:|------------------------------------------------------------------------------------------------------------------------------------------|
| -i, --input       |     required      | Path to the bin file to encrypt.                                                                                                         |
| -o, --output      |     required      | Path to the output encrypted file.                                                                                                       |
| --key, --key-path |     required      | Path to the key used to encrypt the image.                                                                                               | 
| --cipher-mode     |     required      | Cipher mode for AES encryption. Available values: `CBC`, `CTR`.                                                                          |
| --iv              |     optional      | Initialization vector as a path to a binary file or as a hex string starting from `0x`. Use `auto` for auto-generation. Default: 'auto'. |
| --add-iv          |     optional      | Flag that indicates whether to add IV at the beginning of the output file.                                                               |
| --iv-output       |     optional      | Path to the output file for the generated IV.                                                                                            |
| --nonce           |     optional      | A hex string or a file containing nonce used for encryption.                                                                             |

### Usage example
```bash
# AES encryption with already chosen IV from bin file
$ edgeprotecttools encrypt-aes --image unencrypted.bin --output encrypted.bin --key key.bin --cipher-mode CBC --iv 0x00112233445566778899AABBCCDDEEFF

# AES encryption with already chosen IV from hex string
$ edgeprotecttools encrypt-aes --image unencrypted.bin --output encrypted.bin --key key.bin --cipher-mode CBC --iv input_iv.bin

# AES encryption with IV generation and saving IV to bin file
$ edgeprotecttools encrypt-aes --image unencrypted.bin --output encrypted.bin --key key.bin --cipher-mode CBC --iv auto --iv-output output_iv.bin

# AES encryption with IV generation and adding it to the beginning of the encrypted file
$ edgeprotecttools encrypt-aes --image unencrypted.bin --output encrypted.bin --key key.bin --cipher-mode CBC --iv auto --add-iv
```
