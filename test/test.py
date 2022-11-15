#!/usr/bin/env python

import base64
import copy
import io
import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import requests
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from http_message_signatures.resolvers import HTTPSignatureKeyResolver
from http_message_signatures.signatures import (  # noqa
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureComponentResolver,
    InvalidSignature,
)
from http_message_signatures.algorithms import (  # noqa
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
)

test_shared_secret = base64.b64decode(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasj" "lTMtDQ=="
)


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    known_pem_keys = {"test-key-rsa-pss", "test-key-ecc-p256", "test-key-ed25519"}

    def resolve_public_key(self, key_id: str):
        if key_id == "test-shared-secret":
            return test_shared_secret
        if key_id in self.known_pem_keys:
            with open("test/{}.pem".format(key_id), "rb") as fh:
                return load_pem_public_key(fh.read())

    def resolve_private_key(self, key_id: str):
        if key_id == "test-shared-secret":
            return test_shared_secret
        if key_id in self.known_pem_keys:
            with open("test/{}.key".format(key_id), "rb") as fh:
                return load_pem_private_key(fh.read(), password=None)


class TestHTTPMessageSignatures(unittest.TestCase):
    def setUp(self):
        request = requests.Request("POST", "https://example.com/foo?param=Value&Pet=dog", json={"hello": "world"})
        self.test_request = request.prepare()
        self.test_request.headers["Date"] = "Tue, 20 Apr 2021 02:07:55 GMT"
        self.test_request.headers["Content-Digest"] = (
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+" "AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        )
        self.test_response = requests.Response()
        self.test_response.request = self.test_request
        self.test_response.status_code = 200
        self.test_response.headers = {
            "Date": "Tue, 20 Apr 2021 02:07:56 GMT",
            "Content-Type": "application/json",
            "Content-Digest": (
                "sha-512=:JlEy2bfUz7WrWIjc1qV6KVLpdr/7L5/L4h7Sxvh6sNHpDQWDCL+" "GauFQWcZBvVDhiyOnAQsxzZFYwi0wDH+1pw==:"
            ),
            "Content-Length": "23",
        }
        self.test_response.raw = io.BytesIO(json.dumps({"message": "good dog"}).encode())
        self.max_age = timedelta(weeks=90000)

    def verify(self, verifier, message, max_age=None):
        if max_age is None:
            max_age = self.max_age
        m = copy.deepcopy(message)
        m.headers["Signature"] = m.headers["Signature"][:8] + m.headers["Signature"][8:].upper()
        with self.assertRaises(InvalidSignature):
            verifier.verify(m, max_age=max_age)
        m.headers["Signature"] = m.headers["Signature"].upper()
        with self.assertRaisesRegex(InvalidSignature, "Malformed structured header field"):
            verifier.verify(m, max_age=max_age)
        del m.headers["Signature"]
        with self.assertRaisesRegex(InvalidSignature, 'Expected "Signature" header field to be present'):
            verifier.verify(m, max_age=max_age)
        return verifier.verify(message, max_age=max_age)

    @patch('subprocess.run')
    def test_http_message_signatures_tpm(self, subprocess_run):
        self.setUp()
        subprocess_run.return_value = (0, '',)
        signer = HTTPMessageSigner(signature_algorithm=RSA_PSS_SHA512)
        signer.sign(
            self.test_request,
            key_id="test-key-rsa-pss",
            covered_component_ids=(),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b21",
            nonce="b3k2pp5k7z-50gnwp.yemd",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        )
    #     verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
    #     self.verify(verifier, self.test_request)  # Non-deterministic signing algorithm
        self.test_request.headers["Signature"] = (
            "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem"
            "LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG"
            "52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx"
            "2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6"
            "UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3"
            "+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:"
        )
        # self.verify(verifier, self.test_request)

    def test_http_message_signatures_B24(self):
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        signer.sign(
            self.test_response,
            key_id="test-key-ecc-p256",
            covered_component_ids=("@status", "content-type", "content-digest", "content-length"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b24",
            include_alg=False,
        )
        self.assertEqual(
            self.test_response.headers["Signature-Input"],
            (
                'sig-b24=("@method" "@authority" "@target-uri");created=1668514729);'
                'keyid="test-key-ecc-p256";alg="ecdsa-p256-sha256"'
            ),
        )
        # Non-deterministic signing algorithm
        self.assertTrue(self.test_response.headers["Signature"].startswith("sig-b24="))
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P256_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        self.verify(verifier, self.test_response)
        self.test_response.headers["Signature"] = (
            "sig-b24=:0Ry6HsvzS5VmA6HlfBYS/fYYeNs7fYuA7s0tAdxfUlPGv0CSVuwrrzBOjc" "CFHTxVRJ01wjvSzM2BetJauj8dsw==:"
        )
        self.verify(verifier, self.test_response)

    def test_http_message_signatures_B25(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("date", "@authority", "content-type"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b25",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b25=("@method" "@authority" "@target-uri");created=1668514729;'
            'keyid="test-shared-secret";alg="hmac-sha256"',
        )
        self.assertEqual(
            self.test_request.headers["Signature"], "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
        )
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        self.verify(verifier, self.test_request)

    def test_http_message_signatures_B26(self):
        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=MyHTTPSignatureKeyResolver())
        signer.sign(
            self.test_request,
            key_id="test-key-ed25519",
            covered_component_ids=("date", "@method", "@path", "@authority", "content-type", "content-length"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b26",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'sig-b26=("@method" "@authority" "@target-uri");created=1668514729;'
                'keyid="test-key-ed25519";alg="ed25519"'
            ),
        )
        signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
        self.assertEqual(self.test_request.headers["Signature"], signature)
        verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=MyHTTPSignatureKeyResolver())
        result = self.verify(verifier, self.test_request)[0]

        self.assertEqual(result.parameters["keyid"], "test-key-ed25519")
        self.assertIn("created", result.parameters)
        self.assertEqual(result.label, "sig-b26")

        self.test_request.headers["Signature"] = "sig-b26=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)
        self.test_request.headers["Signature"] = signature[::-1]
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)

    def test_query_parameters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("date", "@authority", "content-type", '"@query-params";name="Pet"'),
            created=datetime.fromtimestamp(1618884473),
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'pyhms=("@method" "@authority" "@target-uri");created=1668514729;'
                'keyid="test-shared-secret";alg="hmac-sha256"'
            ),
        )
        self.assertEqual(self.test_request.headers["Signature"], "pyhms=:LOYhEJpBn34v3KohQBFl5qSy93haFd3+Ka9wwOmKeN0=:")
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        self.verify(verifier, self.test_request)

    def test_created_expires(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.fromtimestamp(1))
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
        self.verify(verifier, self.test_request)
        with self.assertRaisesRegex(InvalidSignature, "Signature age exceeds maximum allowable age"):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.now() + self.max_age)
        with self.assertRaisesRegex(InvalidSignature, 'Signature "created" parameter is set to a time in the future'):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", expires=datetime.fromtimestamp(1))
        with self.assertRaisesRegex(InvalidSignature, 'Signature "expires" parameter is set to a time in the past'):
            verifier.verify(self.test_request)


if __name__ == "__main__":
    unittest.main()
