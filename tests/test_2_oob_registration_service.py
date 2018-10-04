import os

import pytest
from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.operator import Operator
from fedoidcmsg.test_utils import create_federation_entities, make_signing_sequence
from cryptojwt.key_jar import KeyJar
from oidcservice import rndstr
from oidcservice.service import build_services
from oidcservice.service_context import ServiceContext

from fedoidcservice.service import factory

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SYMKEY = rndstr(16)

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

SMS = make_signing_sequence([FOODLE.iss, UNINETT.iss, FEIDE.iss], FEDENT,
                            context='registration')


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


class TestRegistrationRequest(object):
    @pytest.fixture(autouse=True)
    def create_services(self):
        # RP

        client_config = {
            "base_url": "https://foodle.example.com",
            "issuer": SUNET_OP.iss,
            "client_id": "xxxxxxxxx",
            "client_secret": "2222222222",
            "redirect_uris": ["https://foodle.example.com/authz_cb/sunet_op"],
            "client_prefs": {
                "response_types": ["code"],
                "scope": ["openid", "profile", "email"],
                "token_endpoint_auth_method": "client_secret_basic"
            }
        }
        _context = ServiceContext(config=client_config)

        FOODLE.context='registration'
        FOODLE.federation = FEIDE.iss
        _context.federation_entity = FOODLE

        self.service = build_services(
            {'FedProviderInfoDiscovery': {}, 'FedRegistrationRequest': {}},
            factory, _context, DB())

    def test_construct(self):
        _srv = self.service['registration']
        _req = _srv.construct()
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 2
        assert set(_req['metadata_statements'].keys()) == {FEIDE.iss}

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
        _srv.service_context.requests_dir = 'rdir'
        _srv.service_context.provider_info[
            'require_request_uri_registration'] = True
        _req = _srv.construct()
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 3
        assert 'request_uris' in _req

    def test_construct_with_receiver(self):
        _srv = self.service['registration']
        _srv.service_context.federation_entity.metadata_statements[
            'registration'] = {}
        make_signing_sequence([FOODLE.iss, UNINETT.iss, FEIDE.iss], FEDENT,
                              context='registration')
        _req = _srv.construct(receiver='https://example.com/op')
        assert isinstance(_req, MetadataStatement)
        assert len(_req) == 2
        assert set(_req['metadata_statements'].keys()) == {FEIDE.iss}
        op = Operator(jwks_bundle=fo_keybundle)
        r = op.unpack_metadata_statement(_req)
        assert r
        l = op.evaluate_metadata_statement(r.result)
        assert l
        assert len(l) == 1
        assert set(l[0].le.keys()) == {'redirect_uris'}

        # assert r.signers() == [
        #     ['https://www.feide.no', 'https://uninett.no',
        #      'https://foodle.uninett.no']
        # ]
