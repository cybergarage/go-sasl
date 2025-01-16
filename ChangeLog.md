# Changelog

## v1.3.0 (2024-XX-XX)
- Support for the following SASL mechanisms:
  - SCRAM-SHA-1-PLUS
  - SCRAM-SHA-256-PLUS
  - SCRAM-SHA-512-PLUS

## v1.2.4 (2025-01-15)
- Updated Query interface:
  - Added setter methods for query parameters
  - Added the EncryptFunc method
- Updated Credential interface:
  - Updated password methods to accept any type
- Updated default CredAuthenticator:
  - Updated to compare credentials based on variable type

## v1.2.3 (2024-12-31)
- Updated CredentialAuthenticator interface

## v1.2.2 (2024-12-28)
- Updated Server::Mechanism() to set the credential store as the default option for the mechanism
- Updated CredentialStore interface 

## v1.2.1 (2024-09-12)
- Standardized error messages using RFC-compliant strings
- Extended mech.Context interface to allow flexible setting and retrieval of arbitrary values
- Extended cred.Authenticator interface to support customizable options

## v1.2.0 (2024-09-03)
- Updated SCRAM plugins to handle more startop options
- Fixed AuthMessage() to use bare client first message

## v1.1.2 (2024-08-18)
- Added mech.Response::Byte() and String() interfaces
- Fixed scram.SeverContext::Next() to parse the specified parameters in the first step

## v1.1.1 (2024-08-18)
- Added mech.Context::SetValue() and Value()

## v1.1.0 (2024-08-18)
- Updated mech.Response interface to add Byte() method
- Updated mech.Context interface to parse the specified parameters in the first step

## v1.0.0 (2024-08-03)
- Initial release  
- Supported for the following SASL mechanisms:
  - SCRAM-SHA-1
  - SCRAM-SHA-256
  - SCRAM-SHA-512
  - PLAIN
  - ANONYMOUS
