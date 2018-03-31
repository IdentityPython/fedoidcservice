import os
import pytest
import shutil

from fedoidcmsg import ClientMetadataStatement
from fedoidcmsg import ProviderConfigurationResponse
from fedoidcmsg import test_utils
from fedoidc.operator import Operator
from oidccli import rndstr
from oidccli.exception import ConfigurationError
from oidcmsg.message import Message

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

op_sup = OA['sunet']
op = Operator(keyjar=signer[op_sup].signing_service.signing_keys, iss=op_sup)


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


class TestProviderInfoRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            'client_id': 'client_id', 'client_secret': 'password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': EO['sunet.op'],
            'client_prefs': {
                'id_token_signed_response_alg': 'RS384',
                'userinfo_signed_response_alg': 'RS384'
            },
            'federation': {
                'signing_keys': {
                    'private_path': 'sign_keys',
                    'public_path': 'static',
                    'keydefs': KEYDEFS
                },
                'superior': {
                    'private_key_path': 'sup_jwks/foo.json',
                    'keydefs': KEYDEFS,
                    'id': 'https://foo.example.com',
                    'ms_dir': 'ms/https%3A%2F%2Fsunet.se'
                },
                'jwks_dir': 'fo_jwks'
            }
        }

        self.cli = Client(config=client_config)

    def test_construct(self):
        _req = self.cli.service['provider_info'].construct(self.cli.client_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_request_info(self):
        _info = self.cli.service['provider_info'].request_info(
            self.cli.client_info)
        assert set(_info.keys()) == {'uri'}
        assert _info['uri'] == '{}/.well-known/openid-configuration'.format(
            self.cli.client_info.issuer)

    def test_parse_request_response_1(self):
        pcr = ProviderConfigurationResponse(
            issuer=self.cli.client_info.issuer,
            response_types_supported=['code'],
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
        sms = op.pack_metadata_statement(pcr, alg='RS256')
        pcr['metadata_statements'] = {FO['swamid']: sms}
        req_resp = Response(200, pcr.to_json(),
                            headers={'content-type': "application/json"})
        resp = self.cli.service['provider_info'].parse_request_response(
            req_resp, self.cli.client_info, body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'metadata_statements'
        }
        assert self.cli.client_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}

    def test_parse_request_response_2(self):
        pcr = ProviderConfigurationResponse(
            issuer=self.cli.client_info.issuer,
            response_types_supported=['code'],
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
        sms = op.pack_metadata_statement(pcr, alg='RS256')
        pcr['metadata_statements'] = {FO['swamid']: sms}
        req_resp = Response(200, pcr.to_json(),
                            headers={'content-type': "application/json"})
        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'

        resp = self.cli.service['provider_info'].parse_request_response(
            req_resp, self.cli.client_info,
            body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'metadata_statements'
        }
        assert self.cli.client_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic'}

    def test_parse_request_response_added_default(self):
        pcr = ProviderConfigurationResponse(
            issuer=self.cli.client_info.issuer,
            response_types_supported=['code'],
            subject_types_supported=['pairwise'],
            authorization_endpoint='https://example.com/op/authz',
            jwks_uri='https://example.com/op/jwks.json',
            token_endpoint='https://example.com/op/token',
            id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512'],
            userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512']
        )
        sms = op.pack_metadata_statement(pcr, alg='RS256')
        pcr['metadata_statements'] = {FO['swamid']: sms}
        req_resp = Response(200, pcr.to_json(),
                            headers={'content-type': "application/json"})

        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs['grant_types'] = [
            'authorization_code']

        resp = self.cli.service['provider_info'].parse_request_response(
            req_resp, self.cli.client_info,
            body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'metadata_statements'
        }
        assert self.cli.client_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic',
            'grant_types': ['authorization_code']}

    def test_parse_request_response_no_match(self):
        pcr = ProviderConfigurationResponse(
            issuer=self.cli.client_info.issuer,
            response_types_supported=['code'],
            subject_types_supported=['pairwise'],
            authorization_endpoint='https://example.com/op/authz',
            jwks_uri='https://example.com/op/jwks.json',
            token_endpoint='https://example.com/op/token',
            id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512'],
            userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512']
        )
        sms = op.pack_metadata_statement(pcr, alg='RS256')
        pcr['metadata_statements'] = {FO['swamid']: sms}
        req_resp = Response(200, pcr.to_json(),
                            headers={'content-type': "application/json"})

        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs['grant_types'] = [
            'authorization_code']
        self.cli.client_info.client_prefs['request_object_signing_alg'] = [
            'ES256']

        resp = self.cli.service['provider_info'].parse_request_response(
            req_resp, self.cli.client_info,
            body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported',
            'metadata_statements'
        }
        assert self.cli.client_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic',
            'grant_types': ['authorization_code'],
            'request_object_signing_alg': 'ES256'}

    def test_parse_request_response_no_match_strict(self):
        pcr = ProviderConfigurationResponse(
            issuer=self.cli.client_info.issuer,
            response_types_supported=['code'],
            subject_types_supported=['pairwise'],
            authorization_endpoint='https://example.com/op/authz',
            jwks_uri='https://example.com/op/jwks.json',
            token_endpoint='https://example.com/op/token',
            id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512'],
            userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                   'RS512']
        )
        sms = op.pack_metadata_statement(pcr, alg='RS256')
        pcr['metadata_statements'] = {FO['swamid']: sms}
        req_resp = Response(200, pcr.to_json(),
                            headers={'content-type': "application/json"})

        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli.client_info.client_prefs['grant_types'] = [
            'authorization_code']
        self.cli.client_info.client_prefs['request_object_signing_alg'] = [
            'ES256']
        self.cli.client_info.strict_on_preferences = True

        with pytest.raises(ConfigurationError):
            self.cli.service['provider_info'].parse_request_response(
                req_resp, self.cli.client_info,
                body_type='json')


class TestRegistrationRequest(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        client_config = {
            'client_id': 'client_id', 'client_secret': 'password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': EO['sunet.op'],
            'client_prefs': {
                'id_token_signed_response_alg': 'RS384',
                'userinfo_signed_response_alg': 'RS384'
            },
            'federation': {
                'signing_keys': {
                    'private_path': 'sign_keys',
                    'public_path': 'static',
                    'keydefs': KEYDEFS
                },
                'superior': {
                    'private_key_path': 'sup_jwks/foo.json',
                    'keydefs': KEYDEFS,
                    'id': 'https://foo.example.com',
                    'ms_dir': 'ms/https%3A%2F%2Fsunet.se'
                },
                'jwks_dir': 'fo_jwks'
            },
            'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/'
        }

        self.cli = Client(config=client_config)
        self.cli.client_info.federation = FO['swamid']

    def test_construct(self):
        _req = self.cli.service['registration'].construct(self.cli.client_info)
        assert isinstance(_req, ClientMetadataStatement)
        assert len(_req) == 2

    def test_config_with_post_logout(self):
        self.cli.client_info.post_logout_redirect_uris = [
            'https://example.com/post_logout']
        _req = self.cli.service['registration'].construct(self.cli.client_info)
        assert isinstance(_req, ClientMetadataStatement)
        assert len(_req) == 3
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        self.cli.client_info.provider_info[
            'require_request_uri_registration'] = True
        _req = self.cli.service['registration'].construct(self.cli.client_info)
        assert isinstance(_req, ClientMetadataStatement)
        assert len(_req) == 3
        assert 'request_uris' in _req
