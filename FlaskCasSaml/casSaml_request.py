"""
CAS SAML response
"""
import datetime
import time
from uuid import uuid4
from flask import request

import defusedxml.ElementTree as ElementTree

from .cas_response import CASResponse

TIMEFMTFRAC = '%Y-%m-%dT%H:%M:%S.%f%z'
TIMEFMT = '%Y-%m-%dT%H:%M:%S%z'

SLOP_TIME = 10      # 10 sec for time skew
MAX_AGE = 1*60*60   # We don't process requests older than one houre.

unixnow = lambda : time.time()
utc_now_saml = lambda : datetime.datetime.strftime(datetime.datetime.utcnow(),TIMEFMTFRAC) + 'Z'
saml_date = lambda utime : datetime.datetime.utcfromtimestamp(utime).strftime(TIMEFMTFRAC) + 'Z'
new_request_id = lambda : '_id' + str(uuid4())


def getsamltime(tstring):
    """Return Unix time for ISO string."""

    format = TIMEFMTFRAC if '.' in tstring else TIMEFMT
    return datetime.datetime.strptime(tstring,format).timestamp()


class CASSamlRequest:
    """Process SAML1.1 Validation Request."""

    def __init__(self, xml):
        
        self.tree = ElementTree.fromstring(xml)
        self.ns = {
            'saml1': 'urn:oasis:names:tc:SAML:1.0:assertion', 
            'soap': 'http://schemas.xmlsoap.org/soap/envelope/', 
            'samlp': 'urn:oasis:names:tc:SAML:1.0:protocol'
        }
        self.max_age = MAX_AGE

        xreq = self.tree.find('./soap:Body/samlp:Request',self.ns)
        assert xreq, 'Could not find xml Request'
        
        self.request_issue_instant = getsamltime(xreq.attrib['IssueInstant'])
        
        major_version = xreq.attrib['MajorVersion']
        minor_version = xreq.attrib['MinorVersion']

        self.request_version = f'{major_version}.{minor_version}'

        # Could be used as responseID in response, but no CAS implementation seems
        # to either do this or check for it.
        self.request_id = xreq.attrib['RequestID']

        xassert = self.tree.find('./soap:Body/samlp:Request/samlp:AssertionArtifact',self.ns)
        self.ticket = xassert.text.strip()


    def is_valid_request(self):
        """Lint-pick Request."""

        t = unixnow()
        assert self.request_version == '1.1', 'Request version error: SAML 1.1 Required'
        assert t + SLOP_TIME > self.request_issue_instant, 'Request IssueInstant in Future'
        assert t + self.max_age > self.request_issue_instant, 'Request IssueInstant too Old'
        assert self.ticket, 'Request AssertionArifact (ticket) Invalid'

        return True


# route: /cas/samlValidate - [POST] REST XML response
def cas_v3_samlValidate(self):
    """ CAS v3 /cas/samlValidate - backchannel service_ticket validation (SAML1.1 response). """

    try:
        if request.method != 'POST':
            raise Exception('POST method is required for this endPoint')

        target = request.args.get('TARGET', None)
        if target is None:
            raise Exception('TARGET URN is required')

        raw_xml = request.get_data()
        if not raw_xml:
            raise Exception('XML Body is required')
            
        xml = CASSamlRequest(raw_xml.decode('utf-8'))
        xml.is_valid_request()

        (status, reason, service_ticket) = self.validate_ticket(ticket=xml.ticket, service=target)

        if status == 'OK':
            return CASResponse.saml_success(service_ticket, life_time=self.cas_tgt_life)
        else:
            raise Exception(f'{status} : {reason}')

    except Exception as e:
        return CASResponse.saml_failure(str(e))
