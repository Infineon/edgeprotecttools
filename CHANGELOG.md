# Changelog
All notable changes to this project will be documented in this file.

## 1.5.0
### Changed
- Dropped support for Python 3.8

### Added
- CYW559xx device erase command
- CYW559xx custom encryption IV
- CYW20829 encryption in NORMAL_NO_SECURE LCS

## 1.4.0
### Added
- Support for AIROC™ CYW20829 revision B1
- Application encryption for AIROC™ CYW559xx
- OTA image generation for AIROC™ CYW559xx

### Changed
- PSOC™ Control C3 integrity exam certificate
- Replaced lief package with pyelftools

## 1.3.0
### Added
- X.509 certificates generation and verification
- Device certificate generation for CYW559xx

## 1.2.0
### Added
- Support for PSOC C3 device
- Reading device CSR from CYW559xx

## 1.1.0
### Added
- Support for CYW559xx device

## 1.0.0
### Added
- Backward compatibility with the [CySecureTools 6.1.0](https://github.com/Infineon/cysecuretools) package
- Combiner/Signer tool
