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

from .wideopenidserver import HCardParser, WideOpenIDResponse
from .wideopenidserver import render_openid_to_response, WebHandler, WebOpenIDYadis


class TrustRootStore(object):
    """
    Store and lookup over trust root list
    """


    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)


    def _get_filename(self, url):
        """
        Encode url to filename
        TODO: doctest
        """

        url = urlparse.urlparse(url)
        filename = urllib.quote('__'.join(tuple(url)).replace('/', '_'))

        return os.path.join(self.directory, filename)


    def items(self):
        return [(item, os.readlink(os.path.join(self.directory, item)))
                for item in os.listdir(self.directory)
                if os.path.islink(os.path.join(self.directory, item))]


    def add(self, url):
        return os.symlink(url, self._get_filename(url))


    def check(self, url):
        return os.path.lexists(self._get_filename(url))


    def delete(self, url):
        return os.unlink(self._get_filename(url))


class OpenIDResponse(WideOpenIDResponse):
    """
    Handle requests to OpenID, including trust root lookups
    """

    class DecisionNeed(Exception):
        """
        Raise if user decision of approve or decline autorization need
        """
        pass


    class LogInNeed(Exception):
        """
        Raise if need user to be logged in
        """
        pass


    def process(self, logged_in=False):
        """
        Main checks routine
        """

        # no request
        if self.request is None:
            raise OpenIDResponse.NoneRequest

        if self.request.mode in ["checkid_immediate", "checkid_setup"]:
            # check request

            if not logged_in:
                # this stage required restricted access to endpoint
                raise OpenIDResponse.LogInNeed

            if self.server.trust_root_store.check(self.request.trust_root):
                # approve if request from trustroot
                return self.approve()

            elif self.request.immediate:
                # decline if immediate and not in trustroot
                return self.decline()

            # last hope route to user decision
            raise OpenIDResponse.DecisionNeed


        # return openid.server.server.WebResponse
        return self._encode_response(self.openid.handleRequest(self.request))


    def always(self, identity=None):
        """
        Approve request and to append to trust root store
        """
        self.server.trust_root_store.add(self.request.trust_root)
        return self.approve(identity)


    def decline(self):
        """
        Decline request

        """
        return self._encode_response(self.request.answer(allow=False))


class OpenIDServer(object):
    """
    Manage OpenID server and trust root store, emit response
    """

    def __init__(self, openid_store, trust_root_store):
        self.openid_store = openid_store
        self.trust_root_store = trust_root_store


    def request(self, endpoint, query):
        openid_server = openid.server.server.Server(self.openid_store, endpoint)
        return OpenIDResponse(self, openid_server, query)


class PasswordManager(web.form.Validator):
    """
    Manage access password
    """

    _hashfunc = hashlib.sha512

    class NoPassword(Exception):
        pass

    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

        self.msg = u'Invalid password'


    def _get_filename(self):
        return os.path.join(self.directory, 'password')


    def _generate_hash(self, salt, password):
        """
        build hash as _hashfunc of concat of salt and password
        """
        hash = self._hashfunc()
        hash.update(salt.encode('utf8'))
        hash.update(password.encode('utf8'))
        return hash.hexdigest()


    def valid(self, password):
        """
        Check password. Return False if passwords don't match, else return True if
        passwords match or unavailable
        """
        try:
            file = open(self._get_filename(), 'rb+')

            # read salt and hash splitted by '$' from password file
            salt, hash = file.read().strip().split('$', 1)

            file.close()

            # build hash and compare with stored
            if not self._generate_hash(salt, password) == hash:
                return False

        except:
            raise PasswordManager.NoPassword

        return True


    def set(self, password):
        """
        Set password
        """
        try:
            file = open(self._get_filename(), 'wb+')
            salt = str(random.randint(1, sys.maxint))

            file.write('$'.join([salt, self._generate_hash(salt, password)]))

            file.close()
            return True
        except:
            raise


class Session(web.session.Session):

    def login(self):
        session['logged_in'] = True

    def logout(self):
        session['logged_in'] = False

    @property
    def logged_in(self):
        return session.get('logged_in', False)



class WebOpenIDIndex(WebHandler):


    def request(self):
        web.header('Content-type', 'text/html')
        return render.base(
                logged_in=session.logged_in,
                login_url=web.ctx.homedomain + web.url('/account/login'),
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                check_trusted_url=web.ctx.homedomain + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                endpoint=web.ctx.homedomain + web.url('/endpoint'),
                yadis=web.ctx.homedomain + web.url('/yadis.xrds'),
                homedomain=web.ctx.homedomain,
            )


def WebOpenIDLoginRequired(query):
    query['return_to'] = web.ctx.homedomain + web.url(web.ctx.path)
    return web.found(web.ctx.homedomain + web.url('/account/login', **query))


def WebOpenIDLoginForm(validator):
    return web.form.Form(
            web.form.Password("password",
                validator,
                description="Password: ",
            ),
        )


class WebOpenIDLogin(WebHandler):


    def request(self):
        return_to = self.query.get('return_to', web.ctx.homedomain + web.url('/account'))

        data = filter(lambda item: item[0] not in ['password'], self.query.items())

        form = WebOpenIDLoginForm(password_manager)()

        session['no_password'] = False

        if self.method == 'POST':
            try:
                if form.validates(self.query):
                    session.login()
                    data.append(('logged_in', True))
                    return web.found(return_to + '?' + web.http.urlencode(dict(data)))

            except PasswordManager.NoPassword:
                session['no_password'] = True
                session.login()
                data.append(('logged_in', True))
                return web.found(return_to + '?' + web.http.urlencode(dict(data)))

        web.header('Content-type', 'text/html')
        return render.login(
                logged_in=session.logged_in,
                login_url=web.ctx.homedomain + web.url('/account/login'),
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                form=form,
                query=data,
            )


class WebOpenIDLogout(WebHandler):


    def request(self):
        session.logout()
        return web.found(web.ctx.homedomain + web.url('/account/login'))


WebOpenIDChangePasswordForm = web.form.Form(
            web.form.Password("password",
                web.form.notnull,
                description="Password: ",
            ),
            web.form.Password("confirm",
                web.form.notnull,
                description="Retype: ",
            ),
            validators=[
                    web.form.Validator('Passwords did not match',
                        lambda source: source['password'] == source['confirm']),
                ],
        )


class WebOpenIDChangePassword(WebHandler):


    def request(self):
        # check for login
        if not session.logged_in:
            return WebOpenIDLoginRequired(self.query)

        form = WebOpenIDChangePasswordForm()

        if self.method == 'POST':
            if form.validates(self.query):
                password_manager.set(self.query['password'])

                session['no_password'] = False

                return web.found(web.ctx.homedomain + web.url('/account'))

        web.header('Content-type', 'text/html')
        return render.password(
                logged_in=session.logged_in,
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                form=form,
            )


class WebOpenIDTrusted(WebHandler):


    def request(self):
        # check for login
        if not session.logged_in:
            return WebOpenIDLoginRequired(self.query)

        items = [
                ((
                    item[1],
                    web.ctx.homedomain + web.url('/account/trusted/%s/delete' % item[0])
                ))
                for item in trust_root_store.items()
            ]

        removed = session.get('trusted_removed_successful', False)
        session['trusted_removed_successful'] = False

        web.header('Content-type', 'text/html')
        return render.trusted(
                logged_in=session.logged_in,
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                trusted=items,
                removed=removed,
            )


class WebOpenIDTrustedDelete(WebHandler):


    def request(self, trusted_id):
        # check for login
        if not session.logged_in:
            return WebOpenIDLoginRequired(self.query)

        try:
            trust_root = dict(trust_root_store.items())[trusted_id]
        except:
            return web.notfound()

        if self.method == 'POST':
                trust_root_store.delete(trust_root)

                session['trusted_removed_successful']  = True

                return web.found(web.ctx.homedomain + web.url('/account/trusted'))

        web.header('Content-type', 'text/html')
        return render.trusted_confirm(
                logged_in=session.logged_in,
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                check_trusted_url=web.ctx.homedomain + web.url('/account/trusted'),
                trusted_remove_url=web.ctx.homedomain + web.url('/account/trusted/%s/delete' % trusted_id),
                no_password=session.get('no_password', False),
                trust_root=trust_root,
            )


class WebOpenIDEndpoint(WebHandler):


    def request(self):
        # check for login
        request = server.request(web.ctx.homedomain + web.url('/endpoint'), self.query)
        try:
            response = request.process(session.logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.LogInNeed:
            # redirect request to login form
            return WebOpenIDLoginRequired(self.query)

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            return web.found(web.ctx.homedomain + web.url('/account/decision', **self.query))

        if self.query.get('logged_in', False):
            session.logout()


        return render_openid_to_response(response)


WebOpenIDLogoutForm = web.form.Form(
            web.form.Checkbox("logout", description="Log out after"),
        )


class WebOpenIDDecision(WebHandler):


    def request(self):
        # check for login
        if not session.logged_in:
            return WebOpenIDLoginRequired(self.query)

        request = server.request(web.ctx.homedomain + web.url('/endpoint'), self.query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:

            if self.method == 'POST':
                if self.query.get('logout', False):
                    session.logout()

                if self.query.has_key('approve'):
                    response = request.approve()
                elif self.query.has_key('always'):
                    response = request.always()
                else:
                    response = request.decline()

            else:
                data = filter(
                        lambda item: item[0] not in [
                                'approve', 'always',
                                'logged_in', 'logout'
                            ],
                        self.query.items())

                sreg_request = sreg.SRegRequest.fromOpenIDRequest(request.request)

                profile = None
                if sreg_request.required or sreg_request.optional:
                    try:
			hcards = HCardParser().parse_url(request.request.identity)
			if hcards:
			    hcard = hcards.next()
			    profile = hcard.profile(sreg_request.required, sreg_request.optional)
                    except:
                        pass

                logout_form = WebOpenIDLogoutForm()
                logout_form.fill({'logout': self.query.get('logged_in', False)})

                web.header('Content-type', 'text/html')
                return render.verify(
                        logged_in=session.logged_in,
                        logout_url=web.ctx.homedomain + web.url('/account/logout'),
                        change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                        no_password=session.get('no_password', False),
                        decision_url=web.ctx.homedomain + web.url('/account/decision'),
                        identity=request.request.identity,
                        trust_root=request.request.trust_root,
                        profile=profile,
                        logout_form=logout_form,
                        query=data,
                    )

        return render_openid_to_response(response)


_ROOT = os.path.abspath(os.path.dirname(__file__))

def init(
            root_store_path,
            trust_root_store_path=None,
            session_store_path=None,
            password_store_path=None,
            templates_path=os.path.join(_ROOT, 'templates'),
            debug=False
        ):

    if trust_root_store_path is None:
        trust_root_store_path = os.path.join(root_store_path, 'trust_root')

    if session_store_path is None:
        session_store_path  = os.path.join(root_store_path, 'sessions')

    if password_store_path is None:
        password_store_path  = os.path.join(root_store_path)

    context = globals()

    app = web.application(
            (
                '', 'WebOpenIDIndex',
                '/', 'WebOpenIDIndex',
                '/account', 'WebOpenIDIndex',
                '/account/login', 'WebOpenIDLogin',
                '/account/logout', 'WebOpenIDLogout',
                '/account/change_password', 'WebOpenIDChangePassword',
                '/account/trusted', 'WebOpenIDTrusted',
                '/account/trusted/(?P<trusted_id>[^/]+)/delete', 'WebOpenIDTrustedDelete',
                '/yadis.xrds', 'WebOpenIDYadis',
                '/endpoint', 'WebOpenIDEndpoint',
                '/account/decision', 'WebOpenIDDecision',
            ),
            context,
        )


    openid_store = openid.store.filestore.FileOpenIDStore(root_store_path)
    trust_root_store = TrustRootStore(trust_root_store_path)
    server = OpenIDServer(openid_store, trust_root_store)
    context['trust_root_store'] = trust_root_store
    context['server'] = server

    sessions_store = web.session.DiskStore(session_store_path)
    session = Session(app, sessions_store)
    context['session'] = session

    password_manager = PasswordManager(password_store_path)
    context['password_manager'] = password_manager

    render = web.contrib.template.render_jinja(templates_path)
    context['render'] = render

    web.config.debug = debug

    return app


def tmp_application():
    from tempfile import mkdtemp
    root_dir = mkdtemp('.store', 'tmpoid')
    app = init(root_dir)
    return app

application = lambda x,y: tmp_application().wsgifunc()(x,y)

if __name__ == '__main__':
    
    ROOT_STORE = 'sstore'
    TEMPLATES = os.path.join(_ROOT, 'templates')

    TRUST_ROOT_STORE = os.path.join(ROOT_STORE, 'trust_root')
    SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
    PASSWORD_STORE = ROOT_STORE
    init(ROOT_STORE, TRUST_ROOT_STORE, SESSION_STORE, PASSWORD_STORE, TEMPLATES, True).run()
