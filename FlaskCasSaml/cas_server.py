"""
    Bottle CAS Server - APIs
"""
from crypt import methods
from urllib.parse import unquote, parse_qs, urlencode

from flask import (
    current_app,
    url_for,
    request, 
    render_template, 
    Blueprint, 
    redirect, 
    session
)

from .cas_response import CASResponse
from .CasTicketManager import CasTicketManager
from .casSaml_request import cas_v3_samlValidate


class CasBridge(CasTicketManager, Blueprint):

    def __init__(
            self,
            app,                # application context
            auth,               # authentication provider (saml/oidc/etc)
            config = {},        # configs all have defaults
            **kwargs,
        ):
        """ Bottle API routes for the CAS service. """

        self.auth = auth

        if 'backing' in kwargs:
            # user specified different backing store for tickets
            backing = kwargs['backing']
        else:
            # use the backing store from flask-session for tickets
            backing = app.session_interface.cache
            
        # Initialize CAS Ticket manager
        super().__init__(auth=auth, config=config, db=backing)

        Blueprint.__init__(self,template_folder='./views', name='cas', import_name=__name__)

        # protocol routes - CAS protocol spec specifies /cas prefix in API
        self.add_url_rule(
            '/cas/login', 
            endpoint='login',
            view_func=self.cas_login,
            methods=['POST', 'GET']
        )
        self.add_url_rule(
            '/cas/logout',
            endpoint='logout',
            view_func=self.cas_logout
        )
        self.add_url_rule(
            '/cas/validate',
            endpoint='validate',
            view_func=self.cas_v1_validate
        )
        self.add_url_rule(
            '/cas/serviceValidate',
            endpoint='serviceValidate',
            view_func=self.cas_v2_serviceValidate
        )
        self.add_url_rule(
            '/cas/p3/serviceValidate',
            endpoint='p3serviceValidate',
            view_func=self.cas_v2_serviceValidate
        )

        if self.cas_samlValidate_support:
            self.add_url_rule(
                '/cas/samlValidate',
                endpoint='samlvalidate',
                view_func=self.cas_v3_samlValidate_prox,
                methods=["POST","GET"]
            )
        else:
            self.add_url_rule(
                '/cas/samlValidate',
                endpoint='samlvalidate',
                view_func=self.notimplemented,
                methods=["POST","GET"]
            )

        if self.cas_proxy_support:  # Enable proxy support
            self.add_url_rule(
                '/cas/proxyValidate',
                endpoint='proxyValidate',
                view_func=self.cas_v2_proxyValidate
            )
            self.add_url_rule(
                '/cas/p3/proxyValidate',
                endpoint= 'p3proxyValidate',
                view_func=self.cas_v2_proxyValidate
            )
            self.add_url_rule(
                '/cas/proxy',
                endpoint='proxy',
                view_func=self.cas_v2_proxy
            )
        else:   # Disable proxy support
            self.add_url_rule(
                '/cas/proxyValidate',
                endpoint='proxyValidate',
                view_func=self.notimplemented
            )
            self.add_url_rule(
                '/cas/p3/proxyValidate',
                endpoint='p3proxyValidate',
                view_func=self.notimplemented
            )
            self.add_url_rule(
                '/cas/proxy',
                endpoint='proxy',
                view_func=self.notimplemented
            )

        # niceness routes - go to login page
        # self.add_url_rule('/cas/<anything>', view_func=self.default_route)
        self.add_url_rule('/cas', view_func=self.default_route)
        self.add_url_rule('/cas/', view_func=self.default_route)

        app.register_blueprint(self)


    # route: /cas/samlValidate - [POST] REST XML response
    def cas_v3_samlValidate_prox(self):
        """ Process V3 samlValidate """
        return cas_v3_samlValidate(self)

#
# CAS PROTOCOL ENDPOINTS
#
    # route: /cas/login - redirect or HTML response
    def cas_login(self, next=None, *args, **kwargs):
        """ CAS V1/v2/v3 login Require TGT or initiate auth login. """

        reauth = request.args.get('renew','false') == 'true'
        kwargs['force_reauth'] = reauth

        try:
            tg_ticket = self.lookup_granting_ticket(session.get(self.CAS_TGT))

        except Exception as e:
            tg_ticket = None

        if tg_ticket and not reauth:
            # good ticket - get to work
            return self.do_cas_login(tg_ticket) 

        else:
            # 'renew' or not authenticated - initiate login
            session[self.CAS_LOGGING_IN] = True

            # remove 'renew' from querystring
            qsdict = parse_qs(request.query_string)
            if 'renew' in qsdict: del qsdict['renew']

            ## rebuild URL
            url = request.url.split('?')[0]
            if qsdict: 
                url = url +  '?' + urlencode(qsdict,doseq=True)
            
            return self.auth.initiate_login(*args, next=url, **kwargs)


    # login real work
    def do_cas_login(self, tg_ticket):
        """ CAS V1/V2/V3 /cas/login - Return a Service Ticket. """

        service = request.args.get('service')

        if service:
            # Service Ticket is Requested
            service = unquote(service) + '?'
            service_base = service.split('?')[0]
            query_string = service.split('?')[1]

            if not self.service_list.valid(service_base):
                msg = f'Invalid service requested:  "{service_base}" is not authorized.'
                current_app.logger.info(f'CAS: {msg}')
                return CASResponse.auth_failure('INVALID_SERVICE', msg)
            
            # for 'renew' checks on serviceValidate
            creds_presented = session.get(self.FRESH_CREDENTIALS, False)
            session[self.FRESH_CREDENTIALS] = False

            # Issue service ticket and redirect to service.
            service_ticket = self.issue_ticket(tg_ticket, service_base, renewed=creds_presented)
            
            user = tg_ticket['username']
            current_app.logger.info(
                f'CAS: "{user}" issued service ticket {service_ticket} for "{service_base}"'
            )

            # redirect to service with ticket
            if query_string:
                url =  service_base + '?' + query_string + '&ticket=' + service_ticket
            else:
                url =  service_base + '?ticket=' + service_ticket
            
            return redirect(url)

        else:
            # no service ticket requested - render login acknowledge page
            return CASResponse.html(render_template(
                'cas_loggedin.html',
                username = tg_ticket['username'],
                attrs = tg_ticket['details'],
                logouturl = url_for('.logout')
                ))


    # route /cas/logout
    def cas_logout(self):
        """ CAS V1/V2/V3 /cas/logout. """

        tgt = session.get(self.CAS_TGT)
        username = session.get('USERNAME')
        
        if tgt:
            # remove any associated pgts
            self.destroy_pgts(username)
            # remove this tgt 
            self.db.delete(tgt)
            del session[self.CAS_TGT]

        # Log off ends our session
        session.clear()

        current_app.logger.info(f'CAS: user "{username}" logged out')
        
        # next URL for logout - redirect
        service = request.args.get('service')
        if service:
            service = unquote(service)
            return redirect(service)
        
        # Notification of log-off - required in CAS spec
        return CASResponse.html(render_template(
                'cas_loggedout.html', 
                loginurl = url_for('.login')
            ))


    # route: /cas/validate - REST text response
    def cas_v1_validate(self):
        """ CAS V1 /cas/validate - back-channel service ticket validation. """

        (status, reason, service_ticket) = self.validate_ticket(proxysok=False)
        
        if status == 'OK':
            # v1 success response is text 'yes' with the username on the second line
            msg = f'yes\n{service_ticket["username"]}\n'
        else:
            # v1 failure response is 'no'
            msg = 'no\n'
        
        return CASResponse.legacy_txt(msg)
            

    # /cas/{p3/}proxyValidate - REST XML/JSON response
    def cas_v2_proxyValidate(self):
        """ CAS V2/V3 /cas/{p3/}proxyValidate - backchannel service ticket validation. """
        
        # proxy validate shares code with serviceValidate - proxysok differentiates
        return self.cas_v2_serviceValidate(proxysok=self.cas_proxy_support)


    # /cas/{p3/}serviceValidate - REST XML/JSON response
    def cas_v2_serviceValidate(self, proxysok=False):
        """ CAS V2/V3 /cas/{p3/}serviceValidate - backchannel service ticket validation. """

        (status, reason, service_ticket) = self.validate_ticket(proxysok=proxysok)

        if status == 'OK':
            # Build reply with data from the service_ticket
            return CASResponse.auth_success(service_ticket)
        else:
            # Build error message
            return CASResponse.auth_failure(status, reason)


    # route: /cas/proxy - REST XML/JSON response
    def cas_v2_proxy(self):
        """ CAS V2/V3 /cas/proxy - Issue Proxy Ticket, return pgtiou. """

        target_service = request.args.get('targetService')
        pgt = request.args.get('pgt')
        error = None
        
        if not self.cas_proxy_support:
            error='INVALID_REQUEST'
            message='Proxy support disabled on this server.'
        
        elif pgt and target_service:
            # pgt and target_service are required parameters for /cas/proxy
            target_service = unquote(target_service)

            if not self.service_list.valid(target_service):
                # Service is not permitted
                error='INVALID_SERVICE'
                message = f'Invalid proxy service request {target_service}'

            elif not pgt.startswith('PGT-'):
                error='INVALID_TICKET'
                message=f'{pgt} is not a Proxy Grant Ticket'
            
            else:   
                # get the granting ticket detail
                pgt_ticket = self.lookup_proxy_granting_ticket(pgt)
                if pgt_ticket:
                    # PGT is valid - issue a pt for target_service       
                    proxy_ticket = self.issue_ticket(pgt_ticket, target_service, proxy=True)

                    user = pgt_ticket['username']
                    current_app.logger.info(f'CAS: "{user}" issued proxy ticket {proxy_ticket} for "{target_service}"')
                    
                    # return pt success
                    return CASResponse.proxy_success(proxy_ticket) 

                else:
                    # PGT is not found
                    error='INVALID_TICKET'
                    message=f'Proxy Grant Ticket {pgt} is Invalid.'
                    
        else:
            # Missing pgt or targetService
            error = 'INVALID_REQUEST'
            message='Both a pgt and targetService is required.'

        current_app.logger.info(f'CAS: Error "{error}" on Proxy request {request.url} : "{message}"')
        
        # return pt failure
        return CASResponse.proxy_failure(error, message)


    # route: /cas/<unimplemented> - any service configured out or not implemented
    def notimplemented(self):
        """ Unimplemented or Disabled Functionality """

        return 'Unimplemented'


    # route: /cas/<anything> => redirect to /cas/login
    def default_route(self, anything=None):
        """ Redirect nonsense back to the login page. """

        return redirect(url_for('.login'))


