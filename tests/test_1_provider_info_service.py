import copy
import os

import pytest
from fedoidcmsg import MetadataStatement
from fedoidcmsg import MIN_SET
from fedoidcmsg import NoSuitableFederation
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.test_utils import create_compounded_metadata_statement
from fedoidcmsg.test_utils import create_federation_entities
from cryptojwt.key_jar import KeyJar
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcservice import rndstr
from oidcservice.service import build_services
from oidcservice.service_context import ServiceContext

from fedoidcservice.service import factory

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SYMKEY = rndstr(16)

TOOL_ISS = 'https://localhost'

ALL = ['https://swamid.sunet.se', 'https://www.feide.no', 'https://sunet.se',
       'https://uninett.no', 'https://sunet.se/op', 'https://foodle.uninett.no']

_path = os.path.realpath(__file__)
root_dir, _fname = os.path.split(_path)

FEDENT = create_federation_entities(ALL, KEYDEFS, root_dir=root_dir)

fo_keybundle = JWKSBundle('')
for iss in ['https://swamid.sunet.se', 'https://www.feide.no']:
    kj = KeyJar()
    kj.import_jwks(FEDENT[iss].signing_keys_as_jwks(), iss)
    fo_keybundle[iss] = kj

SUNET_OP = FEDENT['https://sunet.se/op']
ORG_SUNET = FEDENT['https://sunet.se']
SWAMID = FEDENT['https://swamid.sunet.se']
FOODLE = FEDENT['https://foodle.uninett.no']
FEIDE = FEDENT['https://www.feide.no']
UNINETT = FEDENT['https://uninett.no']


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


def clear_metadata_statements(entities):
    for fedent in entities:
        fedent.metadata_statements = copy.deepcopy(MIN_SET)


def create_provider_info_response(fo):
    sunet_metadata = MetadataStatement()

    pi_response = ProviderConfigurationResponse(
        issuer=SUNET_OP.iss, response_types_supported=['code'],
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

    clear_metadata_statements(FEDENT.values())

    _ = create_compounded_metadata_statement(
        [SUNET_OP.iss, ORG_SUNET.iss, fo.iss],
        FEDENT,
        {ORG_SUNET.iss: sunet_metadata, SUNET_OP.iss: pi_response})

    # clean copy
    pi_response = ProviderConfigurationResponse(
        issuer=SUNET_OP.iss, response_types_supported=['code'],
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

    SUNET_OP.add_sms_spec_to_request(pi_response)
    resp = SUNET_OP.self_sign(pi_response)

    return resp.to_json()


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


class TestProviderInfoRequest(object):
    @pytest.fixture(autouse=True)
    def create_services(self):
        # OP

        fed_ent = FOODLE
        fed_ent.fo_priority = [SWAMID.iss, FEIDE.iss]
        fed_ent.federation = ''
        fed_ent.provider_federations = None
        fed_ent.registration_federations = None
        fed_ent.jwks_bundle = fo_keybundle

        client_config = {
            'client_id': 'client_id',
            'client_secret': 'password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_preferences': {
                'id_token_signed_response_alg': 'RS384',
                'userinfo_signed_response_alg': 'RS384'
            }
        }
        _context = ServiceContext(config=client_config)
        _context.federation_entity = fed_ent
        _context.issuer = SUNET_OP.iss
        self.service = build_services(
            {'FedProviderInfoDiscovery': {}, 'FedRegistrationRequest': {}},
            factory, _context, DB())
        _context.service = self.service

    def test_request_info(self):
        _srv = self.service['provider_info']
        _info = _srv.get_request_parameters()
        assert set(_info.keys()) == {'method', 'url'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            SUNET_OP.iss)

    def test_parse_response_one_federation_priority(self):
        req_resp = create_provider_info_response(SWAMID)
        _srv = self.service['provider_info']
        resp = _srv.parse_response(req_resp)
        assert isinstance(resp, ProviderConfigurationResponse)
        _srv.update_service_context(resp)
        assert set(_srv.service_context.provider_info.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert _srv.service_context.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
        assert _srv.service_context.federation_entity.federation == SWAMID.iss

    def test_parse_response_another_federation_priority(self):
        _srv = self.service['provider_info']
        _srv.service_context.federation_entity.fo_priority = [SWAMID.iss,
                                                              FEIDE.iss]
        req_resp = create_provider_info_response(FEIDE)
        resp = _srv.parse_response(req_resp, body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        _srv.update_service_context(resp)
        assert set(_srv.service_context.provider_info.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert _srv.service_context.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
        assert _srv.service_context.federation_entity.federation == FEIDE.iss

    def test_parse_response_unknown_federations(self):
        _srv = self.service['provider_info']
        _srv.service_context.federation_entity.fo_priority = [
            'https://fo.surfnet.nl']
        req_resp = create_provider_info_response(SWAMID)
        resp = _srv.parse_response(req_resp, body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        with pytest.raises(NoSuitableFederation):
            _srv.update_service_context(resp)

    def test_no_federation_response(self):
        pc_resp = ProviderConfigurationResponse(
            issuer=SUNET_OP.iss, response_types_supported=['code'],
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

        _srv = self.service['provider_info']
        _srv.service_context.federation_entity.fo_priority = [
            'https://fo.surfnet.nl']
        resp = _srv.parse_response(pc_resp.to_json(), body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        _srv.update_service_context(resp)
        assert set(_srv.service_context.provider_info.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert _srv.service_context.federation_entity.federation == ''
