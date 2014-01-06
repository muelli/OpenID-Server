#!/usr/bin/env python

import os, os.path
import urlparse
import urllib
import sys
import hashlib, random

import web, web.http, web.form, web.session, web.contrib.template

import openid.server.server, openid.store.filestore, openid.fetchers
try:
    from openid.extensions import sreg
except ImportError:
    from openid import sreg
    
import html5lib



class HCardParser(html5lib.HTMLParser):
    # based on code
    # from ~isagalaev/scipio/trunk : /utils/__init__.py (revision 38)
    # Ivan Sagalaev, maniac@softwaremaniacs.org, 2010-05-05 19:12:52

    class HCard(object):
        
        def __init__(self, tree):
            self.tree = tree
            
        def __getitem__(self, key):
            if key in dir(self):
                attr = self.__getattribute__(key)
                if callable(attr):
                    return attr()
                else:
                    return attr
            else:
                return self._parse_property(key)
	get = __getitem__
            
        def _parse_property(self, class_name):
            result = list()
            for el in HCardParser.getElementsByClassName(self.tree, class_name):
                if el.name == 'abbr' and 'title' in el.attributes:
                    result.append(el.attributes['title'].strip())
                else:
                    result.extend((s.value.strip() for s in el if s.type == 4))
            return u''.join(result).replace(u'\n', u' ')

        def profile(self, required, optional=[]):
            TRANSLATION = {
                    'fullname': { '__name__': 'Full name' },
                    'dob': { '__name__': 'Date of Birth' },
                    'gender': { 'M': 'Male', 'F': 'Female' },
                    'postcode': { '__name__': 'Postal code' },
                }
                
            def item(field, value):
                translation = TRANSLATION.get(field, {})
                title = translation.get('__name__', field.title())
                if value:
                    value = translation.get(value, value)
                return (title, value)
            
            profile = list()
            for field in required:
                profile.append(item(field, self[field]))
            for field in optional:
                if self[field]:
                    profile.append(item(field, self[field]))
            return profile


        def gender(self):
            TITLES = {
                    'mr': 'M',
                    'ms': 'F',
                    'mrs': 'F', 
                }
            return \
                self._parse_property('x-gender') or \
                self._parse_property('gender') or \
                TITLES.get(self._parse_property('honorific-prefix'), None)

        def dob(self):
            bday = self._parse_property('bday')
            if bday:
                return bday[:10]
            else:
                return None
                
        def nickname(self):
            return \
                self._parse_property('nickname') or \
                self._parse_property('fn')
                    
        def fullname(self):
            return self['fn']
            
        def postcode(self):
            return self['postal-code']
        
        def country(self):
            return self['country-name']
            
        def timezone(self):
            return self['tz']
                
    @classmethod
    def getElementsByClassName(cls, node, class_name):
        nodes = list()
        for child in (c for c in node if c.type == 5):
            if class_name in child.attributes.get('class', '').split():
                nodes.append(child)
        return nodes

    def parse_url(self, url):
        document = openid.fetchers.fetch(url)
        charset = document.headers.get('charset', 'utf-8').replace("'", '')
        return self.parse(document.body.decode(charset, 'ignore'))

    def parse(self, *args, **kwargs):
        tree = super(HCardParser, self).parse(*args, **kwargs)
        return (HCardParser.HCard(node) for node in HCardParser.getElementsByClassName(tree, 'vcard'))
        

class WideOpenIDResponse(object):
    """
    Handle requests to OpenID, including trust root lookups
    """


    class NoneRequest(Exception):
        """
        Raise if request is empty
        """
        pass


    def _encode_response(self, response):
        self.response = response
        self.webresponse = self.openid.encodeResponse(self.response)
        return self.webresponse


    def __init__(self, server, openid, query):
        """
        Decode request
        """

        self.server = server
        self.openid = openid
        self.query = query

        # parse openid request
        self.request = self.openid.decodeRequest(query)


    def process(self, logged_in=False):
        """
        Main checks routine
        """

        # no request
        if self.request is None:
            raise OpenIDResponse.NoneRequest

        if self.request.mode in ["checkid_immediate", "checkid_setup"]:
            return self.approve()

        # return openid.server.server.WebResponse
        return self._encode_response(self.openid.handleRequest(self.request))


    def approve(self, identity=None):
        """
        Approve request

        """

        if identity is None:
            identity = self.request.identity

        response = self.request.answer(
                allow=True,
                identity=identity
            )

        try:
            hcards = HCardParser().parse_url(identity)
            if hcards:
                sreg_data = hcards.next()
                sreg_request = sreg.SRegRequest.fromOpenIDRequest(self.request)
                sreg_response = sreg.SRegResponse.extractResponse(sreg_request, sreg_data)
                response.addExtension(sreg_response)
        except:
            pass
            #TODO: fixme

        return self._encode_response(response)



class WideOpenIDServer(object):
    """
    Manage OpenID server and trust root store, emit response
    """

    def __init__(self, openid_store):
        self.openid_store = openid_store


    def request(self, endpoint, query):
        openid_server = openid.server.server.Server(self.openid_store, endpoint)
        return WideOpenIDResponse(self, openid_server, query)


class Session(web.session.Session):

    def login(self):
        session['logged_in'] = True

    def logout(self):
        session['logged_in'] = False

    @property
    def logged_in(self):
        return session.get('logged_in', False)


def render_openid_to_response(response):
    """
    Return WebResponse as web.py response
    """
    if response.code in [200]:
        for name, value in response.headers.items():
            web.header(name, value)
        return response.body
    elif response.code in [302] and response.headers.has_key('location'):
        return web.found(response.headers['location'])
    else:
        return web.HTTPError(str(response.code) + ' ', response.headers)


class WebHandler(object):


    def __init__(self):
        self.query = web.input()
        self.method = None


    def GET(self, *args, **kwargs):
        self.method = 'GET'
        return self.request(*args, **kwargs)


    def POST(self, *args, **kwargs):
        self.method = 'POST'
        return self.request(*args, **kwargs)


    def request(self):
        raise NotImplemented


class WebWideOpenIDIndex(WebHandler):


    def request(self):
        web.header('Content-type', 'text/html')
        return render.base(
                logged_in=True, #session.logged_in,
                #login_url=web.ctx.homedomain + web.url('/account/login'),
                #logout_url=web.ctx.homedomain + web.url('/account/logout'),
                #change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                #check_trusted_url=web.ctx.homedomain + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                endpoint=web.ctx.homedomain + web.url('/endpoint'),
                yadis=web.ctx.homedomain + web.url('/yadis.xrds'),
                homedomain=web.ctx.homedomain,
            )


# FIXME: This is to be reused
class WebOpenIDYadis(WebHandler):


    def request(self):
        import openid.consumer
        web.header('Content-type', 'application/xrds+xml')
        return """<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>%s</Type>
            <Type>%s</Type>
            <URI>%s</URI>
            <LocalID>%s</LocalID>
        </Service>
    </XRD>
</xrds:XRDS>\n""" %\
            (
                openid.consumer.discover.OPENID_2_0_TYPE,
                openid.consumer.discover.OPENID_1_0_TYPE,
                web.ctx.homedomain + web.url('/endpoint'),
                web.ctx.homedomain,
            )


class WebOpenIDEndpoint(WebHandler):


    def request(self):
        # check for login
        request = server.request(web.ctx.homedomain + web.url('/endpoint'), self.query)
        try:
            response = request.process(session.logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        if self.query.get('logged_in', False):
            session.logout()


        return render_openid_to_response(response)


_ROOT = os.path.abspath(os.path.dirname(__file__))

def init(
            root_store_path,
            session_store_path=None,
            password_store_path=None,
            templates_path=os.path.join(_ROOT, 'templates', 'wideopen'),
            debug=False
        ):

    if session_store_path is None:
        session_store_path  = os.path.join(root_store_path, 'sessions')

    if password_store_path is None:
        password_store_path  = os.path.join(root_store_path)

    context = globals()

    app = web.application(
            (
                '', 'WebWideOpenIDIndex',
                '/', 'WebWideOpenIDIndex',
                '/yadis.xrds', 'WebOpenIDYadis',
                '/endpoint', 'WebOpenIDEndpoint',
                '/\w+', 'WebWideOpenIDIndex',
            ),
            context,
        )


    openid_store = openid.store.filestore.FileOpenIDStore(root_store_path)
    server = WideOpenIDServer(openid_store)
    context['server'] = server

    sessions_store = web.session.DiskStore(session_store_path)
    session = Session(app, sessions_store)
    context['session'] = session

    render = web.contrib.template.render_jinja(templates_path)
    context['render'] = render

    web.config.debug = debug

    return app


def tmp_application():
    from tempfile import mkdtemp
    root_dir = mkdtemp('.store', 'tmpoid')
    app = init(root_dir)
    return app

application = lambda x,y: tmp_application().wsgifunc(x,y)

if __name__ == '__main__':
    
    ROOT_STORE = 'sstore'
    TEMPLATES = os.path.join(_ROOT, 'templates')

    SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
    PASSWORD_STORE = ROOT_STORE
    init(ROOT_STORE, SESSION_STORE, PASSWORD_STORE, TEMPLATES, True).run()
