# CAS Server for Flask using SAML IDP
 
 ## Introduction
**FlaskCasSaml** is **Central Authentication Service** (CAS) server that uses a SAML2 server perform the IDP authentication. **FlaskCasSamle** is a Python application utilizing [the Flask web framework]()

This allows legacy CAS applications to utilize contemporary Identity Management platform that support SAML2 authentication. The difference between any other CAS server and the bridge is that the authentication dialog is handled by the SAML IdP.

The protocol flow thus combines both CAS and SAML:
* Client accesses a legacy CAS app, invoking a login.
* The app redirects the user to */cas/login* on the **FlaskCasSaml** server 
* If the client has not already authenticated with the bridge (i.e. has no Ticket Granting Ticket cookie), it is redirected to the SAML IdP login URL for authentication.
* The SAML IdP validates the user via dialog or SSO.
* The SAML Response is posted back (through the client) to the SAML assertion control service on the **FlasCasSaml**
* The signature on the SAML response is verified and the SAML assertions are saved in a session for the client.
* The client is then redirected back to the **FlasCasSaml** /cas/login
* The bridge returns a CAS Ticket Granting Ticket (TGT) as a cookie, and a Session Ticket back to the client with a redirect back to the legacy CAS application.
* The CAS application service validates the service ticket with the **FlasCasSaml** version specific cas endpoint.
* Depending on the CAS version configured and the API used the bridge returns the attributes for the user to the application.
* The client is then authenticated with the CAS application.
## CAS Support
**FlasCasSaml** supports the [CAS Protocol v1, v2, and v3 as defined by V2 of the CAS Specification](https://apereo.github.io/cas/6.2.x/protocol/CAS-Protocol-V2-Specification.html) with a few options not implemented.  
These unemplemented features are lesser used items that did not fit within the SSO experience:
* *gateway* - section 2.1.1 #3 - the specification is unclear on the implementation, and the value of the feature I felt was suspect. 
* *logon credential receptor* - section 2.2 - I don't belive this can be implemented with a SAML IdP.
* */cas/validate* (the version 1 endpoint) returns the user login on a successful validation. Though not part of the CAS spec almost all CAS servers do this.

**FlasCasSaml** has been tested against **Microsoft Azure AD** and PHP **SimpleSaml** IdPs. If you use this with other IdPs I'd like to hear your experience.

## Installation
It's recommended that you install BottleCasBridge in a venv. Some familiarity with Python apps is desirable.
```bash
# pip install FlaskCasSaml
```
This will install Flask, Flask-Session, FlaskSamlSP, and their dependencies.

There is a sample application sample_flask_cas_server.py and an example config_sample.py (for building your config.py) included with the distribution or available on github.

The basic structure of the CAS bridge is simple:
```python
from flask import Flask
from flask_session import Session
from FlaskSaml import FlaskSP
from FlaskCasSaml import CasBridge

from config import saml_config, session_config, cas_config

app = Flask(__name__)
app.config.from_mapping(session_config)
Session(app)

saml = FlaskSP(saml_config=saml_config,app=app)
cas = CasBridge(app, saml,config=cas_config)

```
The real work is in configuring the config.py components and the IdP to all work together.

### Session and Ticket Configuration
**FlaskCasSaml** uses **Flask-Session** (which in turn uses Pallets cachelib) to provide flexible configuration for both user sessions and ticket storage.  This can include memory or filebased caching as well as Redis or memcached mechanism.

Details on configuring the cache is Flask-Session documentation with more current details in the [Pallets project cachelib documentation](https://cachelib.readthedocs.io/en/stable/).

The simplist deployment suitable for testing is a memory based cache not requiring detailed options, however in a production deployment you will want to consider FileSystem, Memcached, or Redis as the cache backing.

### SAML Configuration
You will need to configure the SamlSP module with details on the SAML IdP. 

Some notes on SAML with **FlaskCasSaml**:
* Uses the [Flask Saml service provider implementation](https://github.com/Glocktober/FlaskSamlSP)
* Does not sign SAML Requests, though it verifies the SAML signature on the SAML Response.
* Considers assertions received valid for 3600 Seconds from authentication regardless of CONDITIONS statements. (This is based on limitations of the [*minisaml* implementation used.](https://github.com/HENNGE/minisaml))
* Assertions are available in the v2/v3 CAS validation data.

Configue for your SAML IdP [according to the documentation for CasSamlSP](https://github.com/Glocktober/CasSamlSP/blob/master/docs/READMESP.md) This will include endpoints, entity id's, etc.


### Configuring CAS

 ```python
CasBridge(app, auth=saml, config=cas_config, backing=None)
 ```
* By default session backing is provided by the caching mechanism used by Flask-Session for maintaining session state.  You can however set **backing=** to a cacheLib instance; this will keep CAS tickets in another backing store (e.g. Redis or Memcached)

#### Cas config options

| **parameter**  |**type** | **default** | **description**
|------------------|-----|--------|----------------------|
|**cas_st_life** |Seconds|300|Service Ticket TTL|
|**cas_tgt_life** |Seconds|8*60*60|Ticket Granting Ticket life|
|**cas_pgt_life** |Seconds|4*60*60|Proxy Granting Ticket life|
|**cas_service_filename** |string|*None*|Path to services file|
|**cas_proxys_filename** |string|*None*|Path to proxys file|
|**cas_proxy_support** |book|*True*|Enable CAS proxy endpoint support|


```json
cas_config = {
    "cas_st_life" : 500,
    "cas_tgt_life" : 28800, 
    "cas_services_filename" : "/configs/cas_services.json",
    "cas_proxy_support" : True
}
```

### cas_service_file and cas_proxy_file files

These are files with a JSON list of `service`/`targetService`) URL's from CAS applications that are permitted to use the CAS bridage.  In the case of the cas_proxy_file these are acceptable `pgtUrl` for proxy validations.

URLs are checked with forced lower case matching. The URL from the request `service` parameter must start with one of the URLs in the list.

```json
['https://example.com/app1', 'https://other.example.com/']
```

If *cas_service_file* or *cas_proxy_files* are not specified, CasBridge works as an **open** CAS server (unadvised) meaning any CAS app can use the bridge to authenticate (or proxy.)

### Considerations for Production

* The default Bottle WSGI server is designed for development and maybe test, and is not suitable for production.
* The default memory-base **Flask-Session** (null) cache will not work in a multi-process environment. You can use *FileSystem* for a single-node solution, but will require *memcached* or *Redis* for multi-node solutions.
* Use TLS.
* If you do not have apps that require it, disable the proxy endpoints (cas_proxy_support=False). 
* Restrict what services can use the bridge with the cas_service_file and cas_proxy_file settings.
