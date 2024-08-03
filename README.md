# go-sasl

![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/cybergarage/go-sasl)
[![test](https://github.com/cybergarage/go-sasl/actions/workflows/make.yml/badge.svg)](https://github.com/cybergarage/go-sasl/actions/workflows/make.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergarage/go-sasl.svg)](https://pkg.go.dev/github.com/cybergarage/go-sasl)
 [![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/cybergarage/go-sasl) 
 [![codecov](https://codecov.io/gh/cybergarage/go-sasl/graph/badge.svg?token=OCU5V0H3OX)](https://codecov.io/gh/cybergarage/go-sasl)

The `go-sasl` is a client and server framework for implementing [Simple Authentication and Security Layer (SASL)](https://datatracker.ietf.org/doc/html/rfc4422) authentication in Go. 

[SASL](https://datatracker.ietf.org/doc/html/rfc4422) is a framework for authentication and data security in Internet protocols. It decouples authentication mechanisms from application protocols, allowing any authentication mechanism to be used with any protocol. SASL provides a structured interface for adding authentication support to connection-based protocols.　The framework provides a common [SASL](https://datatracker.ietf.org/doc/html/rfc4422) mechanism interface for the client and server as the following:


![](doc/img/framework.png)

SASL mechanisms are responsible for the authentication process, which can include steps such as exchanging credentials, verifying identities, and establishing secure communication channels. Each mechanism defines its own protocol for these steps, allowing for flexibility and extensibility. The framework provides the following mechanism plugins:

- [ANONYMOUS](https://datatracker.ietf.org/doc/html/rfc4505)
- [PLAIN](https://datatracker.ietf.org/doc/html/rfc4616)
- [SCRAM-SHA-1](https://datatracker.ietf.org/doc/html/rfc5802)
- [SCRAM-SHA-236](https://datatracker.ietf.org/doc/html/rfc7677)


## References

- [RFC 4422: Simple Authentication and Security Layer (SASL)](https://datatracker.ietf.org/doc/html/rfc4422)
  - [RFC 2743: Generic Security Service Application Program Interface Version 2, Update 1](https://datatracker.ietf.org/doc/html/rfc2743)
  - [RFC 2898: PKCS #5: Password-Based Cryptography Specification Version 2.0](https://datatracker.ietf.org/doc/html/rfc2898)
  - [RFC 4013: SASLprep: Stringprep Profile for User Names and Passwords](https://datatracker.ietf.org/doc/html/rfc4013)
  - [RFC 4086: Randomness Requirements for Security](https://datatracker.ietf.org/doc/html/rfc4086)

- [Simple Authentication and Security Layer (SASL) Mechanisms](https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml)
  - [RFC 4505: Anonymous Simple Authentication and Security Layer (SASL) Mechanism](https://www.rfc-editor.org/rfc/rfc4505.html)
  - [RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism](https://datatracker.ietf.org/doc/html/rfc4616)
  - [RFC 5801: Using Generic Security Service Application Program Interface (GSS-API) Mechanisms in Simple Authentication and Security Layer (SASL): The GS2 Mechanism Family](https://www.rfc-editor.org/rfc/rfc5801)
  - [RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms](https://datatracker.ietf.org/doc/html/rfc5802)
    - [RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms](https://datatracker.ietf.org/doc/html/rfc7677)
