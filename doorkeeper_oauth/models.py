# -*- coding: utf-8 -*-

import os
import werkzeug.urls
import urlparse
import urllib2
import simplejson

import openerp
from openerp import SUPERUSER_ID
from openerp import models, fields, api
from openerp.addons.auth_signup.res_users import SignupError
from openerp.addons.saas_utils import connector, database
from openerp.http import request
from openerp.modules.registry import RegistryManager
from openerp.tools import config

import logging


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _name = 'res.users'
    _inherit = 'res.users'

    def __auth_oauth_rpc_post (self, cr, uid, endpoint, data):
        """ performs a POST request to a given endpoint with a given data """

        _logger.info ("\n\nPOSTing: %s", data)

        params = werkzeug.url_encode (data)
        req = urllib2.Request (endpoint, params)
        try:
            f = urllib2.urlopen (req)
        except Exception, e:
            _logger.exception ("\n\nError [%s]\n", e.read())
            raise e
        response = f.read()

        _logger.info ("\n\nRESPONSE: %s", response)

        return simplejson.loads(response)

    def __auth_oauth_rpc_get (self, cr, uid, endpoint, access_token):
        """ performs a GET request to a given endpoint with a given access_token """

        _logger.info ("\n\nGETing: %s", access_token)

        params = werkzeug.url_encode({'access_token': access_token})
        if urlparse.urlparse(endpoint)[4]:
            req = endpoint + '&' + params
        else:
            req = endpoint + '?' + params

        try:
            f = urllib2.urlopen (req)
        except Exception, e:
            _logger.exception ("\n\nError [%s]\n", e.read())
            raise e
        response = f.read()

        _logger.info ("\n\nRESPONSE: %s", response)

        return simplejson.loads(response)

    def _auth_oauth_rpc (self, cr, uid, endpoint, data):
        return {
            dict: self.__auth_oauth_rpc_post,
            unicode: self.__auth_oauth_rpc_get,
        }.get(type (data), self.__auth_oauth_rpc_get) (
            cr, uid, endpoint, data
        )

    def __get_oauth_provider (self, cr, uid, provider, context=None):
        """ retrieves data on a given provider """

        return self.pool.get ('auth.oauth.provider').browse (cr,
            uid,
            provider,
            context=context
        )

    def __auth_oauth_validation (self, cr, uid, endpoint, data):
        """ requests validation from provider's validation endpoint """

        validation = self.__auth_oauth_rpc_post (cr, uid, endpoint, data)
        if validation.get("error"):
            raise Exception(validation['error'])

        return validation

    def __auth_oauth_data (self, cr, uid, endpoint, data):
        """ requests data from provider's validation endpoint """

        validation = self.__auth_oauth_rpc_get (cr, uid, endpoint, data)
        if validation.get("error"):
            raise Exception(validation['error'])

        return validation

    def __auth_oauth_code_validate (self, cr, uid, provider, code, context=None):
        """ return the validation data corresponding to the access token """

        p = self.__get_oauth_provider (cr, uid, provider, context=context)
        params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': p.client_id,
            'client_secret': p.client_secret,
            'redirect_uri': request.httprequest.url_root + p.return_url,
        }

        validation = self.__auth_oauth_validation (cr, uid, p.validation_endpoint, params)
        access_token = validation.get('access_token', False)

        if p.data_endpoint and access_token:
            data = self.__auth_oauth_rpc_get (cr, uid, p.data_endpoint, access_token)
            if data and data['resource_owner_id']['$oid']:
                validation.update({'user_id': data['resource_owner_id']['$oid']})

        return validation
    
    def __auth_oauth_token_validate (self, cr, uid, provider, access_token, context=None):
        """ return the validation data corresponding to the access token """

        p = self.__get_oauth_provider (cr, uid, provider, context=context)

        validation = {}
        if p.data_endpoint and access_token:
            data = self.__auth_oauth_rpc_get (cr, uid, p.data_endpoint, access_token)
            if data and data['resource_owner_id']['$oid']:
                validation.update({'user_id': data['resource_owner_id']['$oid']})

        return validation

    def __auth_oauth_signin(self, cr, uid, provider, validation, params, context=None):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: openerp.exceptions.AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        try:
            _logger.info ("\n\nValidated data:\n%s\n", validation)
            _logger.info ("\n\nParams:\n%s\n", params)
            oauth_uid = validation['user_id']
            _logger.info ("\n\nOAuth UID: %s\n", oauth_uid)
            _logger.info ("\n\nOAuth Provider ID: %s\n", provider)

            user_ids = self.search(cr, uid, [
                ("oauth_uid", "=", oauth_uid),
                ('oauth_provider_id', '=', provider)
            ])
            _logger.info ("\n\nUser UIDs: %s\n", user_ids)

            if not user_ids:
                raise openerp.exceptions.AccessDenied()

            assert len(user_ids) == 1

            _logger.info ("\n\nloading state\n")
            state = simplejson.loads (params.get('state'))
            if state.get ('td', False):
                _logger.info ("\n\nOpening registry for: %s\n", state['td'])
                reg = RegistryManager.get (state['td'])
                cr = reg.cr
            _logger.info ("\n\nOpened registry: %s\n", cr.dbname)
            
            user = self.browse(cr, uid, user_ids[0], context=context)
            _logger.info ("\n\nUser fetched: %s\n", user)
            user.write({'oauth_access_token': params['access_token']})

            return cr, user.login
        except openerp.exceptions.AccessDenied, access_denied_exception:
            if context and context.get('no_user_creation'):
                return None

            state = simplejson.loads(params['state'])
            _logger.info ("\n\nSTATE: %s\n", state)
            _logger.info ("\n\nVALIDATION: %s\n", validation)

            token = state.get('t')

            oauth_uid = validation['user_id']
            email = state.get('login', 'provider_%s_user_%s' % (provider, oauth_uid))
            name = state.get('name', email)
            organization = state.get ('organization', name)
            plan_id = state.get ('plan', 1)
            values = {
                'name': name,
                'login': email,
                'email': email,
                'oauth_provider_id': provider,
                'oauth_uid': oauth_uid,
                'oauth_access_token': params['access_token'],
                'active': True,
                'organization': organization,
                'plan_id': plan_id,
            }
            try:
                arg0, login, arg2 = self.signup (cr, uid, values, token,
                                           context=context)
                _logger.info ("\n\nARGs are %s & %s", arg0, arg2)
                return cr, login
            except SignupError:
                raise access_denied_exception

    def __get_credentials (self, cr, uid, provider, validation, params,
                           context=None):
        """ passes validation result to get login credentials """

        # required check
        if not validation.get('user_id'):
            raise openerp.exceptions.AccessDenied()

        # retrieve and sign in user
        cr, login = self.__auth_oauth_signin (
            cr, uid, provider, validation, params, context=context
        )
        if not login:
            raise openerp.exceptions.AccessDenied()

        # return user credentials
        return (cr.dbname, login)

    def __auth_oauth_code(self, cr, uid, provider, params, context=None):
        code = params.get('code')
        validation = self.__auth_oauth_code_validate(cr, uid, provider, code)

        return validation.get('access_token')

    def auth_oauth(self, cr, uid, provider, params, context=None):
        # Advice by Google (to avoid Confused Deputy Problem)
        # if validation.audience != OUR_CLIENT_ID:
        #   abort()
        # else:
        #   continue with the process

        _logger.info ("\n\nAUTH with params: %s\n", params)
        access_token = params.get ('access_token', False)
        if not access_token:
            access_token = self.__auth_oauth_code (
                cr, uid, provider, params, context
            )
            
        validation = self.__auth_oauth_token_validate (
            cr, uid, provider, access_token
        )
        
        (dbname, login) = self.__get_credentials (
            cr, uid, provider, validation, params, context=context
        )
        return (dbname, login, access_token)
        
