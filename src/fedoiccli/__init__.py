import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from fedoiccli import request
from fedoicmsg.bundle import FSJWKSBundle
from fedoicmsg.entity import FederationEntity
from fedoicmsg.signing_service import Signer, InternalSigningService
from oiccli import oic
from oicmsg.key_jar import build_keyjar
from oicmsg.key_jar import KeyJar

__version__ = '0.0.1'

DEFAULT_SERVICES = ['FedProviderInfoDiscovery', 'FedRegistrationRequest',
                    'AuthorizationRequest', 'AccessTokenRequest',
                    'RefreshAccessTokenRequest', 'UserInfoRequest']


def private_keys(path, keydefs):
    if os.path.isfile(path):
        _jwks = open(path, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks_as_json(_jwks, '')
    else:
        # Check the directories
        head, tail = os.path.split(path)
        if head:
            os.makedirs(head)
        _kj = build_keyjar(keydefs)[1]
        fp = open(path, 'w')
        fp.write(_kj.export_jwks_as_json(private=True))
        fp.close()
    return _kj


def own_sign_keys(config):
    _kj = private_keys(config['private_path'], config['keydefs'])

    jwks = _kj.export_jwks_as_json()  # public part
    fp = open(config['public_path'], 'w')
    fp.write(jwks)
    fp.close()

    return _kj


def create_federation_entity(self, config):
    sig_keys = own_sign_keys(config['signing_keys'])
    sup_conf = config['superior']

    try:
        _kj = private_keys(sup_conf['private_key_path'], sup_conf['keydefs'])
    except KeyError:
        signer = Signer(sup_conf['ms_dir'])
    else:
        signer = Signer(
            InternalSigningService(sup_conf['id'], _kj),
            ms_dir=sup_conf['ms_dir'])

    _public_keybundle = FSJWKSBundle('', fdir=config['jwks_dir'],
                                     key_conv={'to': quote_plus,
                                               'from': unquote_plus})

    return FederationEntity(self.http, iss=self.client_info.client_id,
                            keyjar=sig_keys, signer=signer,
                            fo_bundle=_public_keybundle)


class Client(oic.Client):
    def __init__(self, ca_certs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, config=None, client_cert=None, httplib=None,
                 services=None, service_factory=None):
        _srvs = services or DEFAULT_SERVICES
        service_factory = service_factory or request.factory
        oic.Client.__init__(self, ca_certs,
                            client_authn_method=client_authn_method,
                            keyjar=keyjar, verify_ssl=verify_ssl,
                            config=config, client_cert=client_cert,
                            httplib=httplib, services=_srvs,
                            service_factory=service_factory)

        fed_ent = create_federation_entity(self, config['federation'])

        for req in ['provider_info', 'registration']:
            self.service[req].federation_entity = fed_ent
