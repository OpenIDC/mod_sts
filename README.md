# mod_sts
A Security Token Service (STS) client for Apache HTTP Server 2.x which allows for exchange of arbitrary security tokens - among which OAuth 2.0 access tokens - by calling into an STS.

## Overview
This module allows for exchanging an incoming security token (e.g. an OAuth 2.0 access token) for another security token by calling into a Security Token Service (STS) and presenting the target token to backend services. This is useful in scenario's where an Apache server is put in front of a backend service as a Reverse Proxy/Gateway that handles tokens presented by *external* clients but needs to forward those requests using some internal security token format, acting as an *internal* client to the backend service.

## Rationale
The split between external tokens and internal tokens may be created for security reasons i.e. separating external requests from internal requests/tokens whilst keeping "on-behalf-of-a-user" semantics, or for legacy reasons i.e. when your backend only supports consuming a proprietary/legacy token format/protocol and you don't want to enforce support for that legacy onto your external clients.

## Tokens

##### Source
An source (or: incoming) token can be presented in a header (e.g. an `Authorization: bearer` header for OAuth 2.0 bearer access tokens), a query parameter or a cookie. Alternatively the token can be consumed from an environment variable set by a another Apache (authentication) module such as a validated access token set by [mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc) in OAuth 2.0 Resource Server mode.

Sample source - incoming/external - tokens:
- an OAuth 2.0 bearer access token presented by an external OAuth 2.0 Client
- a generic JWT not linked to an OAuth 2.0 Client
- a generic cookie
- a vendor specific token - e.g. an OpenToken produced by PingFederate - or a vendor specific cookie such an SSO cookie produced by CA SiteMinder or Oracle Access Manager

##### Target
A target (or: outgoing) token can be appended in a header (e.g. an `Authorization: bearer` header for OAuth 2.0 bearer access tokens), a query parameter or a cookie but the token can also be set as an environment variable so it can be consumed by another Apache module.

Sample target - outgoing/internal - tokens:
- an OAuth 2.0 bearer access token, scoped to an internal service security domain
- a generic JWT
- a generic cookie
- a vendor specific token - e.g. an OpenToken produced by PingFederate - or a vendor specific cookie such an SSO cookie produced by CA SiteMinder or Oracle Access Manager

## Token Exchange Protocols
This module supports a number of different protocols for interfacing with a Security Token Service:
- WS-Trust, see: [https://en.wikipedia.org/wiki/WS-Trust](https://en.wikipedia.org/wiki/WS-Trust)
- OAuth 2.0 Token Exchange, see: [https://www.ietf.org/id/draft-ietf-oauth-token-exchange](https://www.ietf.org/id/draft-ietf-oauth-token-exchange)
- OAuth 2.0 Resource Owner Password Credentials (ROPC) grant which is a workaround for communicating with servers that don't support any of the two options above but can be configured/programmed to validate a token presented in the `password` parameter of the ROPC grant and return an access token.

## Configuration
For an exhaustive description of all configuration options, see the file `sts.conf`
in this directory. This file can also serve as an include file for `httpd.conf`.

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/mod_sts/wiki](https://github.com/zmartzone/mod_sts/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
