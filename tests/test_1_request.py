import os
import pytest
import shutil

from fedoicmsg import MetadataStatement
from fedoicmsg import test_utils
from fedoicmsg.bundle import JWKSBundle
from fedoicmsg.entity import FederationEntity

from fedoiccli.request import factory

from oicmsg.message import Message
from oicmsg.oic import ProviderConfigurationResponse

from oiccli import rndstr
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.client_info import ClientInfo
from oiccli.oauth2 import build_services

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
    fo_keybundle[iss] = keybundle[iss]


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

    return Response(
        200, req.to_json(), headers={'content-type': "application/json"})


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

        self.req = factory('FedProviderInfoDiscovery',
                           client_authn_method=CLIENT_AUTHN_METHOD,
                           federation_entity=fed_ent)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': EO['sunet.op'],
                         'client_prefs': {
                             'id_token_signed_response_alg': 'RS384',
                             'userinfo_signed_response_alg': 'RS384'
                         }}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(
            ['FedProviderInfoDiscovery', 'FedRegistrationRequest'],
            factory, None, None, CLIENT_AUTHN_METHOD)

        self.cli_info.fo_priority = [FO['feide']]
        self.cli_info.federation = ''
        self.cli_info.provider_federations = None
        self.cli_info.registration_federations = None

    def test_construct(self):
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_request_info(self):
        _info = self.req.request_info(self.cli_info)
        assert set(_info.keys()) == {'uri'}
        assert _info['uri'] == '{}/.well-known/openid-configuration'.format(
            EO['sunet.op'])

    def test_parse_request_response_one_federation_priority(self):
        req_resp = create_client_request_response()
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(self.cli_info.provider_info.keys()) == {
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
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}
        assert self.cli_info.federation == FO['feide']

    def test_parse_request_response_another_federation_priority(self):
        self.cli_info.fo_priority = [FO['swamid'], FO['feide']]
        req_resp = create_client_request_response()
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(self.cli_info.provider_info.keys()) == {
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
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}
        assert self.cli_info.federation == FO['swamid']


class TestRegistrationRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        # RP
        foodle_rp = EO['foodle.rp']

        _kj = signer[foodle_rp].signing_service.signing_keys
        fed_ent = FederationEntity(None, keyjar=_kj, iss=foodle_rp,
                                   signer=signer[OA['uninett']],
                                   fo_bundle=fo_keybundle)

        self.req = factory('FedRegistrationRequest',
                           client_authn_method=CLIENT_AUTHN_METHOD,
                           federation_entity=fed_ent)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id',
                         'client_secret': 'password',
                         'redirect_uris': [
                             'https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(
            ['FedProviderInfoDiscovery', 'FedRegistrationRequest'],
            factory, None, None, CLIENT_AUTHN_METHOD)
        self.cli_info.federation = FO['feide']

    def test_construct(self):
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 2
        assert set(_req['metadata_statements'].keys()) == {FO['feide']}

    def test_config_with_post_logout(self):
        self.cli_info.post_logout_redirect_uris = [
            'https://example.com/post_logout']
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 3
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        self.cli_info.provider_info['require_request_uri_registration'] = True
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 3
        assert 'request_uris' in _req
