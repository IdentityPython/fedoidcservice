import inspect
import sys

import fedoidcmsg
from fedoidcmsg import ClientMetadataStatement
from fedoidcmsg import ProviderConfigurationResponse
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.utils import replace_jwks_key_bundle

from oidcservice.oidc import service
from oidcservice.oidc.service import ProviderInfoDiscovery
from oidcservice.oidc.service import Registration
from oidcservice.service import Service
from oidcmsg.exception import RegistrationError


IGNORE = ['metadata_statements', 'metadata_statement_uri']


class FedRegistrationRequest(Registration):
    msg_type = ClientMetadataStatement
    response_cls = ClientMetadataStatement

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, federation_entity=None, **kwargs):
        Registration.__init__(self, service_context, state_db, conf=conf,
                              client_authn_factory=client_authn_factory)
        self.federation_entity = federation_entity
        #
        self.pre_construct.append(self.carry_receiver)
        self.post_construct.append(self.fedoidc_post_construct)
        self.post_construct.append(self.self_signed_request)

    @staticmethod
    def carry_receiver(request, **kwargs):
        if 'receiver' in kwargs:
            return request, {'receiver': kwargs['receiver']}
        else:
            return request, {}

    def fedoidc_post_construct(self, request=None, service=None, **kwargs):
        request = self.federated_client_registration_request(request)
        return request

    def self_signed_request(self, request, receiver='', service=None, **kwargs):
        if receiver:
            _args = dict([(k,v) for k,v in request.items() if k not in IGNORE])
            new_request = self.msg_type(**_args)
            new_request['metadata_statements'] = {}

            iss = InternalSigningService(self.federation_entity.iss,
                                         self.federation_entity.keyjar)
            for fo,_jws in request['metadata_statements'].items():
                _req =  self.msg_type(**_args)
                _req['metadata_statements'] = {fo:_jws}
                _data = iss.create(_req, receiver)
                new_request['metadata_statements'][fo] = _data['sms']

            return new_request
        else:
            return request

    def federated_client_registration_request(self, req_args):
        """
        Constructs a client registration request to be used by a client in a 
        federation.

        :param req_args: The request arguments
        :return: A :py:class:`ClientMetadataStatement`
        """

        if self.service_context.federation:
            return self.federation_entity.update_request(
                req_args, federation=self.service_context.federation)
        elif self.service_context.provider_federations:
            return self.federation_entity.update_request(
                req_args, loes=self.service_context.provider_federations)

    def post_parse_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response, verifies the
        signature and parses the compounded metadata statement.
        If only one federation are mentioned in the response then the name
        of that federation are stored in the *federation* attribute and
        the flattened response is handled in the normal pyoidc way.
        If there are more then one federation involved then the decision
        on which to use has to be made higher up, hence the list of
        :py:class:`fedoidcmsg.operator.LessOrEqual` instances are stored in the
        attribute *registration_federations*

        :param resp: A MetadataStatement instance or a dictionary
        """
        ms_list = self.federation_entity.get_metadata_statement(
            resp, cls=ClientMetadataStatement)

        if not ms_list:  # No metadata statement that I can use
            raise RegistrationError('No trusted metadata')

        # response is a list of registration infos

        # At this point in time I may not know within which
        # federation I'll be working.
        if len(ms_list) == 1:
            ms = ms_list[0]
            self.service_context.provider_info = ms.protected_claims()
            self.service_context.federation = ms.fo
        else:
            self.service_context.registration_federations = ms_list

    # def _post_parse_response(self, resp, cli_info, **kwargs):
    #     self.parse_federation_registration(resp, cli_info=cli_info)


class FedProviderInfoDiscovery(ProviderInfoDiscovery):
    response_cls = fedoidcmsg.ProviderConfigurationResponse

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, federation_entity=None, **kwargs):
        ProviderInfoDiscovery.__init__(
            self, service_context, state_db, conf=conf,
            client_authn_factory=client_authn_factory, )
        self.federation_entity = federation_entity

    def store_federation_info(self, loe):
        """

        :param loe: LessOrEqual instance
        """
        # Only use trusted claims
        trusted_claims = loe.protected_claims()
        if trusted_claims is None:
            raise fedoidcmsg.NoTrustedClaims()
        _pi = self.response_cls(**trusted_claims)

        if 'signed_jwks_uri' in _pi:
            _kb = fedoidcmsg.KeyBundle(source=_pi['signed_jwks_uri'],
                                       verify_keys=loe.signing_keys,
                                       verify_ssl=False)
            _kb.do_remote()
            replace_jwks_key_bundle(self.service_context.keyjar,
                                    self.service_context.issuer, _kb)

        self.service_context.provider_info = _pi
        self.service_context.federation = loe.fo

    def update_service_context(self, response, **kwargs):
        """
        The list of :py:class:`fedoidcmsg.operator.LessOrEqual` instances are
        stored in *provider_federations*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param response:
        :param kwargs:
        """
        try:
            fos = response['fos']
        except KeyError:
            self.service_context.provider_info = response
        else:
            # Possible FO choices
            possible = set(fos.keys()).intersection(
                self.service_context.fo_priority)
            if not possible:
                raise fedoidcmsg.NoSuitableFederation(
                    'Available: {}'.format(fos.keys()))

            # At this point in time I may not know within which
            # federation I'll be working.
            if len(possible) == 1:
                self.store_federation_info(fos[possible.pop()])
            else:
                # store everything I may use of what I got for later reference
                self.service_context.provider_federations = possible

                # Go through the priority list and grab the first one that
                # matches and store that information in *provider_info*.
                for fo in self.service_context.fo_priority:
                    if fo in possible:
                        self.store_federation_info(fos[fo])
                        break

        if self.service_context.provider_info:
            self.match_preferences(self.service_context.provider_info,
                                   self.service_context.issuer)

    def post_parse_response(self, response, **kwargs):
        """
        Takes a provider info response and parses it.
        If according to the info the OP has more then one federation
        in common with the client then the decision has to be handled higher up.
        For each Metadata statement that appears in the response, and was
        possible to parse, one :py:class:`fedoidcmsg.operator.LessOrEqual`
        instance is store in the response by federatiion operator ID under the
        key 'fos'.

        :param response: A MetadataStatement instance
        """

        les = self.federation_entity.get_metadata_statement(
            response, cls=ProviderConfigurationResponse)

        if les:
            response['fos'] = dict([(l.fo, l) for l in les])

        return response


def build_services(service_definitions, service_factory, service_context,
                   state_db, client_authn_factory=None, federation_entity=None):
    """
    This function will build a number of :py:class:`oidcservice.service.Service`
    instances based on the service definitions provided.

    :param service_definitions: A dictionary of service definitions. The keys
        are the names of the subclasses. The values are configurations.
    :param service_factory: A factory that can initiate a service class
    :param service_context: A reference to the service context, this is the same
        for all service instances.
    :param state_db: A reference to the state database. Shared by all the
        services.
    :param client_authn_factory: A list of methods the services can use to
        authenticate the client to a service.
    :return: A dictionary, with service name as key and the service instance as
        value.
    """
    services = {}
    for service_name, service_configuration in service_definitions.items():
        _srv = service_factory(service_name, service_context=service_context,
                               state_db=state_db,
                               client_authn_factory=client_authn_factory,
                               conf=service_configuration,
                               federation_entity=federation_entity)
        services[_srv.service_name] = _srv

    return services


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Service):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    # If not here look at oidcservice.oidc.service
    return service.factory(req_name, **kwargs)
