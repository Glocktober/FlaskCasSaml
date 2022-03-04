"""
    Bottle CAS Server - CAS Ticket Management
"""
import json
from secrets import token_urlsafe

from flask import request, current_app, session
import requests as req

from .URNmanager import URNmanager

class CasTicketManager:
    """ Cas Ticket Management """

    CAS_TGT = 'CAS-TGT'
    FRESH_CREDENTIALS = 'CAS-FRESH'
    CAS_LOGGING_IN = 'CAS-LOG-IN'

    def __init__(self, auth, config={}, db=None):

        self.db = db

        # Tie Auth to tgt
        auth.add_login_hook(self.issue_tgt_ticket_hook)

        # Ticket lifetimes
        self.cas_service_ticket_life = config.get('cas_st_life',5*60)
        self.cas_tgt_life = config.get('cas_tgt_life',8*60*60)
        self.cas_pgt_life = config.get('cas_pgt_life',4*60*60)
        
        # List of permitted services
        self.service_list = URNmanager(config.get('cas_services_filename', None))

        # List of permitted proxy services
        self.proxy_list = URNmanager(config.get('cas_proxys_filename', None))

        # verify SSL when issuing PgtIOU
        self.sslverify = config.get('verify_ssl', True)

        # Enable/disable proxy support (def: enabled)
        self.cas_proxy_support = config.get('cas_proxy_support', True)

        # Enable/disable samlValidate support (def: disabled)
        self.cas_samlValidate_support = config.get('cas_samlValidate', False)

    def issue_tgt_ticket_hook(self, username, attrs):
        """ Hook establishing Ticket Granting Ticket for authed user. """

        # Does a TGT already exist for this user?
        tgt = session.get(self.CAS_TGT, 'TGT-' + token_urlsafe())

        self.db.set(tgt, 
            json.dumps({
                    'username' : username,
                    'details' : attrs,
                    'is_proxy': False,
                }),
            self.cas_tgt_life)

        current_app.logger.info(f'CAS: created {tgt} for "{username}"')
        
        # assocaite this session with the tgt
        session[self.CAS_TGT] = tgt

        session[self.FRESH_CREDENTIALS] = session.get(self.CAS_LOGGING_IN,True)
        session[self.CAS_LOGGING_IN] = False
         
        return username, attrs  


    def issue_pgt_ticket(self, pgturl, st_ticket):
        """ Create a Proxy Granting Ticket. """

        if pgturl is None:
            # no pgturl -> no PGT is created
            return None
        
        proxy_ticket = 'PGT-' + token_urlsafe()
        pgtiou = 'PGTIOU-' + token_urlsafe()

        resp = req.get(pgturl, params={'pgtId':proxy_ticket, 'pgtIou': pgtiou}, verify=self.sslverify)
        if resp.status_code == req.codes.ok:
            # Proxy server successfully received pgtiou=>pgt mapping

            # add list of proxies to pgt
            if 'proxies' not in st_ticket:
                prox_list =[]
            else:
                prox_list = st_ticket['proxies'].copy()

            prox_list.insert(0, pgturl)

            # save the pgt
            self.db.set(proxy_ticket,
                json.dumps({
                    'username' : st_ticket['username'],
                    'details' : st_ticket['details'],
                    'is_proxy' : True,
                    'proxies' : prox_list,
                }),
                self.cas_pgt_life
            )

            # keep track of these for removal when user logs out
            self.track_pgt(proxy_ticket, st_ticket['username'])

            return pgtiou
        else:
            current_app.logger.info(f'CAS: PgtUrl call back failed {resp.status_code} - {pgturl}')
        
        return None
       

    def lookup_proxy_granting_ticket(self, pgt):
        """ Retrieve PGT. """

        return self.lookup_granting_ticket(pgt)


    def lookup_granting_ticket(self, tgt):
        """ Retrieve a proxy granting ticket or None. """
        
        ticket_data = self.db.get(tgt)
        return json.loads(ticket_data) if ticket_data else None


    def track_pgt(self, pgt, username):
        """ Track PGT for a given user. """
        
        # Retrieve list of pgt's associated with this user
        key = 'sessPGT:' + username
        pgt_track = self.db.get(key)

        if pgt_track:
            # Append to the existing list
            pgt_list = json.loads(pgt_track)
        else:
            # new list
            pgt_list = []
        
        # append this pgt and save
        pgt_list.append(pgt)
        self.db.set(key, json.dumps(pgt_list))

        return


    def destroy_pgts(self, username):
        """ Remove PGT's tracked for this username. """

        if not username:
            return

        key = 'sessPGT:' + username
        pgt_list = []
        
        # load list of pgts for this user
        pgt_track = self.db.get(key)
        pgt_list = json.loads(pgt_track) if pgt_track else []

        for pgt in pgt_list:
            # remove PGT's because user is logging out
            self.db.delete(pgt)
        
        # remove the list itself
        self.db.delete(key)


#
# CAS SERVICE/PROXY TICKET MANAGEMENT
#
    def issue_ticket(self, granting_ticket, service, proxy=False, renewed=False):
        """ Issue a service or proxy ticket. """

        prefix = 'PT-' if proxy else 'ST-'

        new_ticket = {
            'service' : service,
            'username' : granting_ticket['username'],
            'details' : granting_ticket['details'],
            'is_proxy_ticket': proxy,
            'creds_presented': renewed and not proxy,
        }
        if proxy:
            # pt's include proxy validation chain
            new_ticket['proxies'] = granting_ticket['proxies']

        service_ticket = prefix + token_urlsafe()
        self.db.set(service_ticket,
                json.dumps(new_ticket),
                self.cas_service_ticket_life,
            )

        return service_ticket


    def claim_ticket(self, service_ticket):
        """ Claim a service or proxy ticket. """

        # Redis stored tickets 
        ticket = self.db.get(service_ticket) if service_ticket else None

        if ticket:
            # ticket claims are one-shot so remove this
            self.db.delete(service_ticket)

            ticket = json.loads(ticket)
        else:
            ticket = {
                'error' : f'Can not find ticket "{service_ticket}"',
                'status' : 'INVALID_TICKET',
            }
        
        return ticket


    def validate_ticket(self, ticket=None, service=None, proxysok=False):
        """ Validate a service or proxy ticket. """

        if ticket is None:
            ticket = request.args.get('ticket')

        if service is None:
            service = request.args.get('service')
        
        pgturl = request.args.get('pgtUrl')
        renew = request.args.get('renew')
        
        status = None
        reason = None
        pgtiou = None

        # always claim the ticket - one shot at validation
        service_ticket = self.claim_ticket(ticket)

        if not service or not ticket:
            reason = f'Service and ticket both requred for ticket "{ticket}"'
            status = 'INVALID_REQUEST'
        
        elif not service_ticket:
            reason = f'Failed to validate: cant find ticket "{ticket}"'
            status = 'INVALID_TICKET'

        elif 'error' in service_ticket:
            reason = service_ticket['error']
            status = service_ticket.get('status', 'INVALID_TICKET')
        
        elif pgturl and not self.cas_proxy_support:
            reason = 'pgtUrl provided, but this server has proxy disabled.'
            status = 'INVALID_PROXY_CALLBACK'
        
        elif pgturl and not self.proxy_list.valid(pgturl):
            reason = f'Proxy service "{pgturl}" is not authorized.'
            status = 'INVALID_PROXY_CALLBACK'
        
        elif not self.cas_proxy_support and ticket.startswith('PT-'):
            reason = 'Proxy Ticket can not be validated: this server has proxy disabled.'
            status = 'INVALID_REQUEST'
        
        elif not proxysok and ticket.startswith('PT-'):
            reason = f'Failed to validate: proxy ticket "{ticket}" must use proxyValidate endpoint'
            status = 'UNAUTHORIZED_SERVICE_PROXY'

        elif not self.service_list.match(service_ticket['service'], service):
            reason = f'Failed to vaildate: service "{service}" incorrect for ticket "{ticket}"'
            status = 'INVALID_SERVICE'
        
        elif renew and not service_ticket['creds_presented']:
            reason = '"renew" validation specified but primary credentials were not presented.'
            status = 'INVALID_TICKET_SPEC'
        
        else:
            # All criteria met - Good to go
            reason = f'Successful validation of {ticket} by "{service_ticket["username"]}" for "{service}"'
            status = 'OK'
            
            pgtiou = self.issue_pgt_ticket(pgturl, service_ticket)

            if pgturl and pgtiou is None:
                status = 'INVALID_PROXY_CALLBACK'
                reason = f'Proxy callback failed for "{pgturl}" with ticket {ticket}'

            elif pgtiou:
                service_ticket['pgtiou'] = pgtiou

        current_app.logger.info(f'CAS: {reason}')

        return (status, reason, service_ticket)
    
