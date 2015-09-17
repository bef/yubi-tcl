This project implements a validation server for [Yubikey](https://developers.yubico.com/) One-Time-Passwords. It is written in Tcl as CGI in order to be used with any CGI capable webserver - such as boa or apache2. It comes with a client library, although [other client libraries](https://www.yubico.com/web-api-clients/) are supported.

The server implementation is minimal and acts as a centralized validation server for small environments.

Features include:

- mostly [Validation Protocol 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html) compliant
- file based user and yubikey management; does not require any DBMS
- arbitrary keyboard layout support - Dvorak, Neo2 and QWERTY-alike layouts are supported by default, others - e.g. Russian - are supported with CFGFLAG_SEND_REF enabled
- client library with example
