# mod_sts
A Security Token Service (STS) client for Apache HTTP Server 2.x facilitating OAuth 2.0 Access Token Exchange.

## Overview

This module allows for exchanging an OAuth 2.0 access token for another security token by calling into a Security Token Service (STS). This is useful in scenario's where an Apache server is put in front of a backend service as a Reverse Proxy/Gateway that handles OAuth 2.0 tokens presented by *external* OAuth 2.0 clients but needs to forward those requests using some internal security token format, acting as an *internal* client to the backend service.

### Rationale
The split between external tokens and internal tokens may be created for security reasons i.e. separating external requests from internal requests/tokens whilst keeping "on-behalf-of-a-user" semantics, or for legacy reasons i.e. when your backend only supports consuming a proprietary/legacy token format/protocol and you don't want to enforce support for that legacy onto your external clients.

### Token Formats
Access tokens can be presented in an `Authorization` header, a query parameter or a cookie but can also be consumed from an environment variable set by a another Apache (authentication) module such as a validated access token set by [mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc) in OAuth 2.0 Resource Server mode.

Example target/internal tokens can be:
- OAuth 2.0 access tokens, (internally) scoped to a service security domain
- vendor specific tokens/cookies e.g. those produced by CA SiteMinder or Oracle Access Manager

### Exchange Protocols
This module supports a number of different protocols for talking to a Security Token Service:
- WS-Trust, see: [https://en.wikipedia.org/wiki/WS-Trust](https://en.wikipedia.org/wiki/WS-Trust)
- OAuth 2.0 Resource Owner Password Credentials flow where the access token is presented in the `password` parameter

The latter is a workaround for a draft IETF standard for REST-based Token Exchange: [https://www.ietf.org/id/draft-ietf-oauth-token-exchange](https://www.ietf.org/id/draft-ietf-oauth-token-exchange) that this module will support once (near) standardized.

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
