[![Build Status](https://github.com/OpenIDC/mod_sts/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/mod_sts/actions/workflows/build.yml)

# mod_sts
A security token exchange module for Apache HTTP Server 2.x which allows for exchanging arbitrary security
tokens by calling into a remote Security Token Service (STS).

## Overview
This Apache module allows for exchanging a security token (aka. "source token") that is presented on an
incoming HTTP request for another security token (aka. "target token") by calling into a Security Token
Service (STS) and then include that target token on the propagated HTTP request to the content or origin
server.

This can be used in scenario's where an Apache server is put in front of a backend service as a Reverse
Proxy/Gateway that handles tokens presented by *external* clients but needs to forward those requests
using some internal security token format, acting as an *internal* client to the backend service.
Note that the backend service can also be an application that is hosted on the Apache server itself,
e.g. a PHP application.

## Rationale
The split between external tokens and internal tokens may be enforced for security reasons i.e. separating
external requests from internal requests/tokens whilst keeping "on-behalf-of-a-user" semantics, or for
legacy reasons i.e. when your backend only supports consuming a proprietary/legacy token format/protocol
and you don't want to enforce support for that legacy onto your external clients (or vice versa).

## Tokens

##### Source
An source (or: incoming) token can be presented in a header (e.g. an `Authorization: bearer` header for
OAuth 2.0 bearer access tokens), a query parameter or a cookie. Alternatively the token can be consumed
from an environment variable set by a another Apache (authentication) module such as a validated access
token set by [mod_oauth2](https://github.com/OpenIDC/mod_oauth2) operating as an OAuth 2.0 Resource
Server.

Sample supported - incoming/external - source tokens:
- an OAuth 2.0 bearer access token presented by an external OAuth 2.0 Client
- a generic JWT presented in a header or query parameter
- a generic cookie
- a vendor specific token - e.g. an OpenToken produced by PingFederate - or a vendor specific cookie
  such as an SSO cookie produced by CA SiteMinder or Oracle Access Manager

##### Target
A target (or: outgoing) token can be appended in a header (e.g. an `Authorization: bearer` header for
OAuth 2.0 bearer access tokens), a query parameter or a cookie but the token can also be set as an
environment variable so it can be consumed by another Apache module or by an application that is served
from the Apache server, e.g. a PHP application.

Sample supported - outgoing/internal - target tokens:
- an OAuth 2.0 bearer access token, scoped to an internal service security domain
- a generic JWT put in a header
- a generic cookie
- a vendor specific token - e.g. an OpenToken produced by PingFederate - or a vendor specific cookie
  such as an SSO cookie produced by CA SiteMinder or Oracle Access Manager

## Security Token Service Protocols
This module supports a number of different protocols for interfacing with a Security Token Service:

##### WS-Trust
XML/SOAP based OASIS standard, see:
[https://en.wikipedia.org/wiki/WS-Trust](https://en.wikipedia.org/wiki/WS-Trust)

##### OAuth 2.0 Token Exchange
REST/OAuth 2.0 based IETF standard RFC 8693, see:
[https://tools.ietf.org/html/rfc8693](https://tools.ietf.org/html/rfc8693)

##### OAuth 2.0 Resource Owner Password Credentials (ROPC)
Essentially a workaround for communicating with servers that don't support any of the two options above
but can be configured/programmed to validate a token presented in the `password` parameter of the
OAuth 2.0 Resource Owner Password Credentials grant and return a target token in the `access token`
claim of the token response.

##### OAuth 2.0 Client Credentials (CC)
This leverages the [OAuth 2.0 Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) grant type
but does not actually require a source token. Instead the configured client credentials are used as a bootstrapping
mechanism to obtain an OAuth 2.0 access token that can be used to authenticate the service towards the backend.

## Quickstart

WS-Trust STS using HTTP Basic authentication.

```apache
<Location /sts/wstrust>	
	STSExchange wstrust https://pingfed:9031/pf/sts.wst \
auth=basic&username=wstrust&password=2Federate&\
applies_to=urn:pingfed&\
value_type=urn:pingidentity.com:oauth2:grant_type:validate_bearer&\
token_type=urn:bogus:token&\
ssl_verify=false
</Location>
```

OAuth 2.0 Resource Owner Password Credentials based STS using `client_secret_basic` authentication.

```apache
<Location /sts/ropc>
	STSExchange ropc https://pingfed:9031/as/token.oauth2 \
auth=client_secret_basic&\
client_id=sts0&\
client_secret=2Federate&\
username=dummy&\
ssl_verify=false
</Location>
```

OAuth 2.0 Client Credentials token retrieval using `client_secret_basic` authentication.

```apache
<Location /sts/cc>
	SetEnvIfExpr true dummy=dummy
	STSAcceptSourceTokenIn environment name=dummy
	STSPassTargetTokenIn header
	STSExchange cc https://keycloak:8443/realms/master/protocol/openid-connect/token \
auth=client_secret_basic&\
client_id=cc_client&\
client_secret=mysecret&\
ssl_verify=false
</Location>
```

OAuth 2.0 Token Exchange using `client_secret_basic` authentication.

```apache
<Location /sts/otx>
	STSExchange otx https://keycloak:8443/auth/realms/master/protocol/openid-connect/token \
auth=client_secret_basic&\
client_id=otxclient&\
client_secret=2Federate&\
ssl_verify=false
</Location>
```

JWT generation from a incoming access token verified by mod_oauth2. The JSON payload is passed between the modules in an environment variable.

```apache
<Location /sts/jwk>
	AuthType oauth2
	Require valid-user
	OAuth2TokenVerify introspect https://pingfed:9031/as/introspect.oauth2 introspect.ssl_verify=false&introspect.auth=client_secret_basic&client_id=rs0&client_secret=2Federate
	OAuth2TargetPass json_payload_claim=payload&headers=false
	STSAcceptSourceTokenIn environment name=OAUTH2_CLAIM_payload
	STSExchange jwt "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\",\"d\":\"Xc9d-kZERQVC0Dzh1b0sCwJE75Bf1fMr4hHAjJsovjV641ElqRdd4Borp9X2sJVcLTq1wWgmvmjYXgvhdTTg2f-vS4dqhPcGjM3VVUhzzPU6wIdZ7W0XzC1PY4E-ozTBJ1Nr-EhujuftnhRhVjYOkAAqU94FXVsaf2mBAKg-8WzrWx2MeWjfLcE79DmSL9Iw2areKVRGlKddIIPnHb-Mw9HB7ZCyVTC1v5sqhQPy6qPo8XHdQju_EYRlIOMksU8kcb20R_ezib_rHuVwJVlTNk6MvFUIj4ayXdX13Qy4kTBRiQM7pumPaypEE4CrAfTWP0AYnEwz_FGluOpMZNzoAQ\"}"
	STSPassTargetTokenIn header
</Location>
```

For a detailed overview of configuration options see the `sts.conf` Apache configuration file in this
directory.

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/OpenIDC/mod_sts/wiki](https://github.com/OpenIDC/mod_sts/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can
contact:  
  [sales@openidc.com](mailto:sales@openidc.com)


Disclaimer
----------
*This software is open sourced by OpenIDC. For commercial support
you can contact [OpenIDC](https://www.openidc.com) as described above in the [Support](#support)
section.*
