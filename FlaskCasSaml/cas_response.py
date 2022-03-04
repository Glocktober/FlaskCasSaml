import datetime
import json
import time
from uuid import uuid4

from flask import request, Response, render_template

TIMEFMTFRAC = '%Y-%m-%dT%H:%M:%S.%f%z'
TIMEFMT = '%Y-%m-%dT%H:%M:%S%z'
SLOP_TIME = 10      # 10 sec for time skew

saml_date = lambda utime : datetime.datetime.utcfromtimestamp(utime).strftime(TIMEFMTFRAC) + 'Z'
utc_now_saml = lambda delta=0 : saml_date(time.time() + delta) 
new_request_id = lambda : '_id' + str(uuid4())


def requested_json():
    """ Detect if request specified format JSON/XML. """

    return request.args.get('format') == 'JSON'


def xml_escape(xml):
    """ Escape XML Characters. """

    xml = xml.replace('&','&amp;')
    xml = xml.replace('"','&quote;')
    xml = xml.replace('\`','&apos;')
    xml = xml.replace('>','&gt;')
    xml = xml.replace('<','&lt;')
    return xml


def xml_unescape(xml):
    """ UnEscape XML Characters. """
    
    xml = xml.replace('&amp;', '&')
    xml = xml.replace('&quote;','"')
    xml = xml.replace('&apos;', '\`')
    xml = xml.replace('&gt;', '>')
    xml = xml.replace('&lt;', '<')
    return xml  


class CASResponse:
    """ CAS-specific response routines. """

    @staticmethod
    def auth_success(service_ticket):
        """ Respond to /cas/serviceValidate pr /cas/proxyValidate succeeded """

        if requested_json():
            auth = {
                'user' : service_ticket.get('username'),
                'attributes': service_ticket.get('details'),
            }
            
            pgtiou = service_ticket.get('pgtiou')
            if pgtiou:
                auth['proxyGrantingTicket'] = pgtiou
            
            is_proxy_ticket = service_ticket.get('is_proxy_ticket')
            proxies = service_ticket.get('proxies')
            
            if is_proxy_ticket and proxies:
                auth['proxies'] = proxies
            
            return CAS_common().asJSON({
                "serviceResponse":{
                    "authenticationSuccess" : auth,
                }
            })
        
        else: # XML
            return CAS_common().asXML(render_template(
                    'v2_auth_success.xml', 
                    service_ticket=service_ticket,
                    xmlesc=xml_escape
                ))


    @staticmethod
    def auth_failure(error, message):
        """ Respond to /cas/serviceValidate or /cas/proxyValidate failed """
        
        if requested_json():
            return CAS_common().asJSON({
                "serviceResponse":{
                    "authenticationFailure" :{
                        "code" : error,
                        "description": message,
                    }
                }
            })

        else: # XML
            return CAS_common().asXML(render_template(
                'v2_auth_failure.xml', 
                error=error,
                message=message,
                xmlesc=xml_escape
            ))
  
    
    @staticmethod
    def proxy_success(proxy_ticket):
        """ Respond to /cas/proxy succeeded """

        if requested_json():
            return CAS_common().asJSON({
                "serviceResponse":{
                    "proxySuccess" :{
                        "proxyTicket": proxy_ticket,
                    }
                }
            })

        else: # XML
            return CAS_common().asXML(render_template(
                'v2_proxy_success.xml', 
                proxy_ticket=proxy_ticket,
                xmlesc=xml_escape
            ))

    
    @staticmethod
    def proxy_failure(error, message):
        """ Respond to /cas/proxy failed """

        if requested_json():
            return CAS_common().asJSON({
                "serviceResponse":{
                    "proxyFailure" :{
                        "code" : error,
                        "description": message,
                    }
                }
            })

        else: # XML
            return CAS_common().asXML(render_template(
                'v2_proxy_failure.xml', error=error, 
                message=xml_escape(message)
            ))


    @staticmethod
    def saml_success(service_ticket, life_time):
        """ Respond to v3 samlValidate success """
        
        if 'authenticated' in service_ticket['details']:
            auth_instant = saml_date(int(service_ticket['details']['authenticated']))
        else: # we lie.
            auth_instant = utc_now_saml()

        # Build reply with data from the service_ticket
        dat = render_template( 'v3_cas_saml_success.xml',
                issue_instant = utc_now_saml(),
                expires_after = utc_now_saml(life_time),
                auth_instant = auth_instant,
                response_id = new_request_id(),
                service_ticket = service_ticket,
                xmlesc = xml_escape,
            )
        
        return CAS_common().asXML(dat)


    @staticmethod
    def saml_failure(message):
        """ Respond to SamlValidate error. """

        return CAS_common().asXML(render_template('v3_cas_saml_error.xml', 
                status_code = 'Requestor',
                status_message = xml_escape(message),
                issue_instant = utc_now_saml(),
                response_id = new_request_id()
            )
        )


    @staticmethod
    def legacy_txt(txt):
        """ Respond with text. """

        return CAS_common().asTXT(txt)
    

    @staticmethod
    def html(html):
        """ Respond with HTML. """

        return CAS_common().asHTML(html)

    
    @staticmethod
    def json(obj):
        """ Respond with JSON. """

        return CAS_common().asJSON(obj)


class CAS_common(Response):

    def __init__(self,dat=b''):

        super().__init__()

        self.data = dat
        
        self.headers['Cache-Control'] = 'no-store no-cache'
        self.headers['Pragma'] = 'no-cache'
        self.headers['Expires'] = -1


    def asXML(self, xml):
        """ as XML """

        self.headers['Content-Type'] = 'application/xml'
        self.data = xml
        return self

    def asHTML(self, html):
        """ as HTML """

        self.headers['Content-Type'] = 'text/html'
        self.data = html
        return self


    def asTXT(self, txt):
        """ as TXT """

        self.headers['Content-Type'] = 'text/plain'
        self.data = txt
        return self
        

    def asJSON(self, js):
        """ as JSON """

        self.headers['Content-Type'] = 'application/json'
        self.data = json.dumps(js)
        return self
