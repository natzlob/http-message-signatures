import collections
import datetime
import hashlib
import logging
import shlex
import subprocess
import tempfile
from typing import Any, Dict, List, Tuple

import http_message_signatures.exceptions
import http_sfv

from .algorithms import signature_algorithms
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .resolvers import HTTPSignatureComponentResolver
from .structures import VerifyResult

logger = logging.getLogger(__name__)


class HTTPSignatureHandler:
    signature_metadata_parameters = {"alg", "created", "expires", "keyid", "nonce"}

    def __init__(
        self,
        *,
        signature_algorithm=None,
        key_resolver=None,
        component_resolver_class=HTTPSignatureComponentResolver,
        tpm_device=None,
        key_object_handle=None,
    ):
        if signature_algorithm not in signature_algorithms.values():
            raise HTTPMessageSignaturesException(f"Unknown signature algorithm {signature_algorithm}")
        self.signature_algorithm = signature_algorithm
        self.component_resolver_class = component_resolver_class
        if key_resolver:
            self.key_resolver = key_resolver
        if tpm_device:
            self.tpm_device = tpm_device
        if key_object_handle:
            self.key_object_handle = key_object_handle

    def _build_signature_base(
        self, message, *, covered_component_ids: List[Any], signature_params: Dict[str, str]
    ) -> Tuple:
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            component_key = str(http_sfv.List([component_id]))
            # TODO: model situations when header occurs multiple times
            component_value = component_resolver.resolve(component_id)
            if str(component_id.value).lower() != str(component_id.value):
                msg = f'Component ID "{component_id.value}" is not all lowercase'  # type: ignore
                raise HTTPMessageSignaturesException(msg)
            if "\n" in component_key:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" contains newline character')
            if component_key in sig_elements:
                raise HTTPMessageSignaturesException(
                    f'Component ID "{component_key}" appeared multiple times in ' "signature input"
                )
            sig_elements[component_key] = component_value
        sig_params_node = http_sfv.InnerList(covered_component_ids)
        sig_params_node.params.update(signature_params)
        sig_elements['"@signature-params"'] = str(sig_params_node)
        sig_base = "\n".join(f"{k}: {v}" for k, v in sig_elements.items())
        return sig_base, sig_params_node, sig_elements


class HTTPMessageSigner(HTTPSignatureHandler):
    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def _parse_covered_component_ids(self, covered_component_ids):
        covered_component_nodes = []
        for component_id in covered_component_ids:
            component_name_node = http_sfv.Item()
            if component_id.startswith('"'):
                component_name_node.parse(component_id.encode())
            else:
                component_name_node.value = component_id
            covered_component_nodes.append(component_name_node)
        return covered_component_nodes

    def get_signature_base(
        self,
        message,
        *,
        key_id,
        created=None,
        expires=None,
        nonce=None,
        include_alg=True,
        covered_component_ids=("@method", "@authority", "@target-uri"),
    ):
        # TODO: Accept-Signature autonegotiation
        if created is None:
            created = datetime.datetime.now()
        signature_params: Dict[str, Any] = collections.OrderedDict()
        signature_params["created"] = int(created.timestamp())
        signature_params["keyid"] = key_id
        if expires:
            signature_params["expires"] = int(expires.timestamp())
        if nonce:
            signature_params["nonce"] = nonce
        if include_alg:
            signature_params["alg"] = self.signature_algorithm.algorithm_id
        print('before _parse_covered_component_ids')
        covered_component_nodes = self._parse_covered_component_ids(covered_component_ids)
        print('just finished _parse_covered_component_ids')
        sig_base, sig_params_node, _ = self._build_signature_base(
            message, covered_component_ids=covered_component_nodes, signature_params=signature_params
        )
        return sig_base, sig_params_node, _

    def sign(
        self,
        message,
        *,
        key_id: str,
        created=None,
        expires=None,
        nonce=None,
        label=None,
        include_alg=True,
        covered_component_ids=("@method", "@authority", "@target-uri")
    ):
        if (hasattr(self, 'key_resolver') and hasattr(self.key_resolver, 'resolve_private_key')):
            print('this means key_resolver in not None')
            # when the private key is available
            key = self.key_resolver.resolve_private_key(key_id)
            signer = self.signature_algorithm(private_key=key)
            sig_base, sig_params_node, _ = self.get_signature_base(message, key_id=key_id)
            signature = signer.sign(sig_base.encode())
        else:
            sig_base, sig_params_node, _ = self.get_signature_base(message, key_id=key_id)
            # this code path uses the TPM to sign
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as digest_file:
                digest_file.write(hashlib.sha256(sig_base.encode("ascii")).digest())
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as signature_file:
                sign_command = "tpm2_sign --tcti={} -c {} -g sha256 -d -f plain -o {} {}".format(
                    self.tpm_device,
                    self.key_object_handle,
                    signature_file.name,
                    digest_file.name,
                )
            output = subprocess.run(shlex.split(sign_command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if output.stderr:
                raise http_message_signatures.exceptions.SigningError(output.stderr)
            else:
                with open(signature_file.name, "rb") as f:
                    signature = f.read()
        sig_label = self.DEFAULT_SIGNATURE_LABEL
        if label is not None:
            sig_label = label
        sig_input_node = http_sfv.Dictionary({sig_label: sig_params_node})
        message.headers["Signature-Input"] = str(sig_input_node)
        sig_node = http_sfv.Dictionary({sig_label: signature})
        message.headers["Signature"] = str(sig_node)


class HTTPMessageVerifier(HTTPSignatureHandler):
    require_created: bool = True

    def _parse_dict_header(self, header_name, headers):
        if header_name not in headers:
            raise InvalidSignature(f'Expected "{header_name}" header field to be present')
        try:
            dict_header_node = http_sfv.Dictionary()
            dict_header_node.parse(headers[header_name].encode())
        except Exception as e:
            raise InvalidSignature(f'Malformed structured header field "{header_name}"') from e
        return dict_header_node

    def _parse_integer_timestamp(self, ts, field_name):
        try:
            ts = int(ts)
            dt = datetime.datetime.fromtimestamp(ts)
        except Exception as e:
            raise InvalidSignature(f'Malformed "{field_name}" parameter: {e}') from e
        return dt

    def validate_created_and_expires(self, sig_input, max_age=None):
        now = datetime.datetime.now()
        if "created" in sig_input.params:
            if self._parse_integer_timestamp(sig_input.params["created"], field_name="created") > now:
                raise InvalidSignature('Signature "created" parameter is set to a time in the future')
        elif self.require_created:
            raise InvalidSignature('Signature is missing a required "created" parameter')
        if "expires" in sig_input.params:
            if self._parse_integer_timestamp(sig_input.params["expires"], field_name="expires") < now:
                raise InvalidSignature('Signature "expires" parameter is set to a time in the past')
        if max_age is not None:
            if self._parse_integer_timestamp(sig_input.params["created"], field_name="created") + max_age < now:
                raise InvalidSignature(f"Signature age exceeds maximum allowable age {max_age}")

    def verify(
        self, message, *, max_age=datetime.timedelta(days=1), key_file=None
    ) -> List[VerifyResult]:
        sig_inputs = self._parse_dict_header("Signature-Input", message.headers)
        if len(sig_inputs) != 1:
            # TODO: validate all behaviors with multiple signatures
            raise InvalidSignature("Multiple signatures are not supported")
        signature = self._parse_dict_header("Signature", message.headers)
        verify_results = []
        for label, sig_input in sig_inputs.items():
            self.validate_created_and_expires(sig_input, max_age=max_age)
            if label not in signature:
                raise InvalidSignature("Signature-Input contains a label not listed in Signature")
            if "alg" in sig_input.params:
                if sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
                    raise InvalidSignature("Unexpected algorithm specified in the signature")
            if self.key_resolver:
                key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
            if key_file:
                with open(key_file, "rb") as f:
                    key = f.read()
            for param in sig_input.params:
                if param not in self.signature_metadata_parameters:
                    raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
            try:
                sig_base, sig_params_node, sig_elements = self._build_signature_base(
                    message, covered_component_ids=list(sig_input), signature_params=sig_input.params
                )
            except Exception as e:
                raise InvalidSignature(e) from e
            verifier = self.signature_algorithm(public_key=key)
            raw_signature = signature[label].value
            try:
                verifier.verify(signature=raw_signature, message=sig_base.encode())
            except Exception as e:
                raise InvalidSignature(e) from e
            verify_result = VerifyResult(
                label=label,
                algorithm=self.signature_algorithm,
                covered_components=sig_elements,
                parameters=dict(sig_params_node.params),
                body=None,
            )
            verify_results.append(verify_result)
        return verify_results
