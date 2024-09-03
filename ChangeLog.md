# Changelog

## v1.2.0 (2024-XX-XX)
- Support for the following SASL mechanisms:
  - SCRAM-SHA-1-PLUS
  - SCRAM-SHA-256-PLUS
  - SCRAM-SHA-512-PLUS

## v1.1.3 (2024-09-02)
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
