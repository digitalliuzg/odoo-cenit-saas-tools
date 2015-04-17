# -*- coding: utf-8 -*-
import openerp
from openerp import SUPERUSER_ID
from openerp.addons.auth_oauth.controllers.main import fragment_to_query_string
from openerp.addons.web import http
from openerp.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect
from openerp.addons.web.http import request
from openerp.modules.registry import RegistryManager

import werkzeug
import simplejson
import uuid
import random
import logging


_logger = logging.getLogger(__name__)

class DoorkeeperOauth (http.Controller):

    def __create_app_for_db (self, dbname):
        provider = self.get_provider ()
        client_id = provider.client_id
        
        request.registry['oauth.application'].create (
            request.cr, SUPERUSER_ID, {
                'client_id': client_id,
                'name': dbname
            }
        )

        return provider

    def __signup_user (self, provider, values):
        u = request.registry.get('res.users')
        credentials = u.auth_oauth (request.cr, SUPERUSER_ID, provider.id, values, context={})
        
        user = u.search_read (
            request.cr, SUPERUSER_ID, [
                ('login', '=', credentials[1])
            ]
        )[0]

        return user['oauth_uid'], credentials
        
    @http.route ('/auth_oauth/doorkeeper_cb', type='http', auth='none')
    def doorkeeper_cb (self, **kw):
        if kw.get('state', False):
            state = simplejson.loads(kw['state'])

            master_db = db_monodb ()
            proto, root_url = request.httprequest.url_root.split ("://")
            if not master_db:
                return BadRequest()
                
            if state.get('login', False):
                login = state['login']
                db_prefix = state['login'].split('@')[0]
                dbname = "%s_%s" %(db_prefix, master_db)
                redirect = "%s://%s.%s" %(proto, db_prefix, root_url)
                if not redirect.endswith ("/"):
                    redirect += "/"

            state.update ({'d': dbname})
            kw['state'] = simplejson.dumps (state)
            if openerp.service.db.exp_db_exist (dbname):
                registry = RegistryManager.get (dbname)

                with registry.cursor() as cr:
                    IMD = registry['ir.model.data']
                    try:
                        model, provider_id = IMD.get_object_reference(
                            cr, SUPERUSER_ID,
                            'saas_server', 'saas_oauth_provider'
                        )
                    except ValueError:
                        return set_cookie_and_redirect('/web?db=%s' % dbname)
                    assert model == 'auth.oauth.provider'
                
                params = {
                    'access_token': kw['access_token'],
                    'state': simplejson.dumps({
                        'd': dbname,
                        'p': provider_id,
                        }),
                    }
                
                return werkzeug.utils.redirect('{host}{controller}?{params}'.format(
                        host = redirect,
                        controller = 'auth_oauth/signin',
                        params = werkzeug.url_encode(params)
                    )
                )
            else:
                _logger.info ("No DB: meaning signup")
                registry = RegistryManager.get (master_db)

                if not state.get ('name', False):
                    state.update ({
                        'name': db_prefix.capitalize ()
                    })
                
                if not state.get ('organization', False):
                    state.update ({
                        'organization': db_prefix.capitalize ()
                    })

                if not state.get ('plan', False):
                    plan = self.get_plan ()
                else:
                    plan = self.get_plan (state.get ('plan'))
                state.update ({
                    'plan': plan['id']
                })

                try:
                    provider = self.__create_app_for_db (state['d'])
                    partner_id, credentials = self.__signup_user (provider, kw)
                    request.cr.commit ()

                except Exception, e:
                    _logger.exception (e)
                    url = "/web/login?oauth_error=2"
                    return set_cookie_and_redirect (url)

                url = "/saas_server/new_database"
                kw['state'] = simplejson.dumps (state)
                kw['admin_data'] = simplejson.dumps ({
                    'user_id': partner_id,
                    'client_id': provider.client_id,
                    'email': login,
                    'name': state['name']
                })

                full_url = '%s?%s' % (url, werkzeug.url_encode(kw))
                return login_and_redirect (*credentials, redirect_url=full_url)
        else:
            _logger.exception ('OAuth2: No state provided.')
            url = "/web/login?oauth_error=2"

        return set_cookie_and_redirect(url)

    def get_provider(self):
        imd = request.registry['ir.model.data']
        return imd.xmlid_to_object (
            request.cr, SUPERUSER_ID,
            'saas_server.saas_oauth_provider'
        )

    def get_plan (self, name=None):
        ssp = request.registry['saas_server.plan']
        conditions = [
            ('state', '=', 'confirmed'),
        ]
        if name is not None:
            conditions.append (('name', '=', name))
        plans = ssp.search_read (
            request.cr, SUPERUSER_ID, conditions
        )

        if name is not None:
            assert len(plans) == 1
        else:
            assert len(plans) > 0
        
        return plans[0]
