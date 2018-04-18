import os
import pytest
import shutil

from fedoidcmsg import MetadataStatement
from fedoidcmsg import test_utils
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.entity import FederationEntity

from fedoidcservice.service import build_services

from oidcmsg.message import Message
from oidcmsg.key_jar import KeyJar
from oidcmsg.oidc import ProviderConfigurationResponse

from oidcservice import rndstr
from oidcservice.service_context import ServiceContext


KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SYMKEY = rndstr(16)

TOOL_ISS = 'https://localhost'

FO = {'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no'}

OA = {'sunet': 'https://sunet.se', 'uninett': 'https://uninett.no'}

IA = {}

EO = {'sunet.op': 'https://sunet.se/op',
      'foodle.rp': 'https://foodle.uninett.no'}

BASE = {'sunet.op': EO['sunet.op']}

SMS_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['swamid'], 'uri': False},
            ],
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['feide'], 'uri': False},
            ]
        },
        "registration": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['swamid'], 'uri': False},
            ],
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['feide'], 'uri': False},
            ]
        },
    },
    OA['uninett']: {
        "registration": {
            FO['feide']: [
                {'request': {}, 'requester': OA['uninett'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['feide'], 'uri': False},
            ]
        }
    },
    EO['sunet.op']: {
        "response": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'response'},
                 'signer': FO['swamid'], 'uri': False},
                {'request': {}, 'requester': EO['sunet.op'],
                 'signer_add': {}, 'signer': OA['sunet'], 'uri': False}
            ],
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': "response"},
                 'signer': FO['feide'], 'uri': False},
                {'request': {}, 'requester': EO['sunet.op'],
                 'signer_add': {}, 'signer': OA['sunet'], 'uri': False}
            ]
        }
    },
    EO['foodle.rp']: {
        'registration': {
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': "registration"},
                 'signer': FO['feide'], 'uri': False},
                {'request': {}, 'requester': EO['sunet.op'],
                 'signer_add': {}, 'signer': OA['sunet'], 'uri': False}
            ]
        }
    }
}

# Clear out old stuff
for d in ['mds', 'ms']:
    if os.path.isdir(d):
        shutil.rmtree(d)

liss = list(FO.values())
liss.extend(list(OA.values()))
liss.extend(list(EO.values()))

signer, keybundle = test_utils.setup(KEYDEFS, TOOL_ISS, liss, ms_path='ms',
                                     csms_def=SMS_DEF, mds_dir='mds')

fo_keybundle = JWKSBundle('https://example.com')
for iss in FO.values():
    kj = KeyJar()
    kj.import_jwks(keybundle[iss].export_jwks(), iss)
    fo_keybundle[iss] = kj


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        try:
            return self.db[item]
        except KeyError:
            return None


def create_client_request_response():
    req = ProviderConfigurationResponse(
        issuer=EO['sunet.op'], response_types_supported=['code'],
        grant_types_supported=['Bearer'],
        subject_types_supported=['pairwise'],
        authorization_endpoint='https://example.com/op/authz',
        jwks_uri='https://example.com/op/jwks.json',
        token_endpoint='https://example.com/op/token',
        id_token_signing_alg_values_supported=['RS256', 'RS384',
                                               'RS512'],
        userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                               'RS512']
    )

    req['metadata_statements'] = signer[
        OA['sunet']].create_signed_metadata_statement(req, 'discovery')

    return req.to_json()


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


class TestProviderInfoRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        # RP
        foodle_rp = EO['foodle.rp']

        _kj = signer[foodle_rp].signing_service.signing_keys
        fed_ent = FederationEntity(None, keyjar=_kj, iss=foodle_rp,
                                   signer=signer[OA['uninett']],
                                   fo_bundle=fo_keybundle)

        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': EO['sunet.op'],
                         'client_preferences': {
                             'id_token_signed_response_alg': 'RS384',
                             'userinfo_signed_response_alg': 'RS384'
                         }}
        _context = ServiceContext(config=client_config)
        _context.fo_priority = [FO['feide']]
        _context.federation = ''
        _context.provider_federations = None
        _context.registration_federations = None
        self.service = build_services(
            {'FedProviderInfoDiscovery': {}, 'FedRegistrationRequest': {}},
            factory, _context, DB(), federation_entity=fed_ent)

    def test_construct(self):
        _srv = self.service['registration']
        _req = _srv.construct()
        assert isinstance(_req, Message)
        assert _req.to_dict() == {
            'redirect_uris': ['https://example.com/cli/authz_cb']}

    def test_request_info(self):
        _srv = self.service['provider_info']
        _info = _srv.get_request_parameters()
        assert set(_info.keys()) == {'method', 'url'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            EO['sunet.op'])

    def test_parse_response_one_federation_priority(self):
        req_resp = create_client_request_response()
        _srv = self.service['provider_info']
        resp = _srv.parse_response(req_resp)
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(_srv.service_context.provider_info.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'federation_usage'}
        assert _srv.service_context.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}
        assert _srv.service_context.federation == FO['feide']

    def test_parse_response_another_federation_priority(self):
        _srv = self.service['provider_info']
        _srv.service_context.fo_priority = [FO['swamid'], FO['feide']]
        req_resp = create_client_request_response()
        resp = _srv.parse_response(req_resp, body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(_srv.service_context.provider_info.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'federation_usage'}
        assert _srv.service_context.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}
        assert _srv.service_context.federation == FO['swamid']


class TestRegistrationRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        # RP
        foodle_rp = EO['foodle.rp']

        _kj = signer[foodle_rp].signing_service.signing_keys
        fed_ent = FederationEntity(None, keyjar=_kj, iss=foodle_rp,
                                   signer=signer[OA['uninett']],
                                   fo_bundle=fo_keybundle)

        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id',
                         'client_secret': 'password',
                         'redirect_uris': [
                             'https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        _context = ServiceContext(config=client_config)
        _context.federation = FO['feide']
        self.service = build_services(
            {'FedProviderInfoDiscovery': {}, 'FedRegistrationRequest': {}},
            factory, _context, DB(), fed_ent)

    def test_construct(self):
        _srv = self.service['registration']
        _req = _srv.construct()
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 2
        assert set(_req['metadata_statements'].keys()) == {FO['feide']}

    def test_config_with_post_logout(self):
        _srv = self.service['registration']
        _srv.service_context.post_logout_redirect_uris = [
            'https://example.com/post_logout']
        _req = _srv.construct()
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 3
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        _srv = self.service['registration']
        _srv.service_context.provider_info[
            'require_request_uri_registration'] = True
        _req = _srv.construct()
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 3
        assert 'request_uris' in _req
