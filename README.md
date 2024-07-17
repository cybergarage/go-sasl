# go-sasl

![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/cybergarage/go-sasl)
[![test](https://github.com/cybergarage/go-sasl/actions/workflows/make.yml/badge.svg)](https://github.com/cybergarage/go-sasl/actions/workflows/make.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergarage/go-sasl.svg)](https://pkg.go.dev/github.com/cybergarage/go-sasl)
 [![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/cybergarage/go-sasl) 
 [![codecov](https://codecov.io/gh/cybergarage/go-sasl/graph/badge.svg?token=OCU5V0H3OX)](https://codecov.io/gh/cybergarage/go-sasl)

`go-sasl` is a library for implementing [SASL](https://datatracker.ietf.org/doc/html/rfc4422) authentication in Go.

## References

- [RFC 4422 - Simple Authentication and Security Layer (SASL)](https://datatracker.ietf.org/doc/html/rfc4422)
  - [RFC 2743 - Generic Security Service Application Program Interface Version 2, Update 1](https://datatracker.ietf.org/doc/html/rfc2743)
  - [RFC 2898 - PKCS #5: Password-Based Cryptography Specification Version 2.0](https://datatracker.ietf.org/doc/html/rfc2898)
  - [RFC 4013 - SASLprep: Stringprep Profile for User Names and Passwords](https://datatracker.ietf.org/doc/html/rfc4013)
   - [RFC 4086 - Randomness Requirements for Security](https://datatracker.ietf.org/doc/html/rfc4086)
  - [RFC 5801: Using Generic Security Service Application Program Interface (GSS-API) Mechanisms in Simple Authentication and Security Layer (SASL): The GS2 Mechanism Family](https://www.rfc-editor.org/rfc/rfc5801)
  - [RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms](https://datatracker.ietf.org/doc/html/rfc5802)
  - [RFC 7677 - SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms](https://datatracker.ietf.org/doc/html/rfc7677)
- [Java SASL API](https://docs.oracle.com/javase/jp/8/docs/technotes/guides/security/sasl/sasl-refguide.html)
- [Cyrus SASL (libsasl)](https://www.cyrusimap.org/sasl/)
- [GNU SASL Library - Libgsasl - GNU Project - Free Software Foundation](https://www.gnu.org/software/gsasl/)
- [簡易認証セキュリティー層 (SASL) の紹介](https://docs.oracle.com/cd/E19253-01/819-0396/6n2qur9ug/index.html)
- [PostgreSQL: Documentation: 16: 55.3. SASL Authentication](https://www.postgresql.org/docs/current/sasl-authentication.html)