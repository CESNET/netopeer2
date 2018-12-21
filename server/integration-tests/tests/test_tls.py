import shutil
import subprocess
import base64
import hashlib
import tempfile
import os
import ssl

from pyasn1_modules import pem
import pytest

from common import edit_config_dict, wait_for

SERVER_CA = "pki/server/root-ca/certs/ca.crt"
SERVER_INTR = "pki/server/intermediate/certs/intermediate.crt"
SERVER_LEAF = "pki/server/out/Server.crt"
SERVER_LEAF_KEY = "pki/server/out/Server.key"

CLIENT_CA = "pki/client/root-ca/certs/ca.crt"
CLIENT_INTR = "pki/client/intermediate/certs/intermediate.crt"
CLIENT_LEAF = "pki/client/out/Client.crt"
CLIENT_LEAF_KEY = "pki/client/out/Client.key"


def test_tls_server_missing_client_intermediate_and_leaf(mgr, temp_chains, cleanup):
    """Verify that when the server only has the client's root CA it still
       accepts the connection"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            }
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_server_missing_client_leaf(mgr, temp_chains, cleanup):
    """Verify that when the server has the client's root and intermediate
       CA but not the leaf certificate that it still accepts the
       connection"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_all_keys_match_root(mgr, temp_chains, cleanup):
    """Verify that when the server has all client certificates installed
       it can still connect"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_all_keys_match_intermediate(mgr, temp_chains, cleanup):
    """Verify that when the cert-to-name fingerprint matches the
       intermediate client cert the connection is accepted"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_INTR),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_all_keys_match_leaf(mgr, temp_chains, cleanup):
    """Verify that when the cert-to-name fingerprint matches the
       leaf client cert the connection is accepted"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_LEAF),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_only_client_leaf_trusted_and_fingerprint_of_client_CA(
    mgr, temp_chains, cleanup
):
    """Verify that when the server only trusts the client's leaf
       certificate but has a cert-to-name fingerprint that matches the
       client's root CA the connection is accepted"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            }
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_only_client_leaf_trusted_and_fingerprint_of_client_leaf(
    mgr, temp_chains, cleanup
):
    """Verify that when the server only trusts the client's leaf
       certificate and has a cert-to-name fingerprint that matches the
       client's leaf the connection is accepted"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            }
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_LEAF),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def test_tls_fingerprint_cascade(mgr, temp_chains, cleanup):
    """Verify that when the first cert-to-name entry doesn't match, the
       next one is tried"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_INTR, SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": [
                {
                    "^ncs:id": "1",
                    "ncs:fingerprint": "04" + 8 * ":DE:AD:BE:EF",
                    "ncs:map-type": "x509c2n:specified",
                    "ncs:name": "not-exist",
                },
                {
                    "^ncs:id": "2",
                    "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                    "ncs:map-type": "x509c2n:specified",
                    "ncs:name": "root",
                },
            ]
        },
    )


def test_tls_client_missing_server_intermediate(mgr, temp_chains, cleanup):
    """Verify that when the client only has the server's root CA then the
       server's intermediate CA can be negotiated during the connection"""
    do_cert_test(
        mgr,
        temp_chains,
        client_ca_certs=[SERVER_CA, CLIENT_INTR, CLIENT_CA],
        server_trusted_client_certs=[
            {
                "^ks:name": "TrustedClientRootCA",
                "ks:certificate": read_pem_b64(CLIENT_CA),
            },
            {
                "^ks:name": "TrustedClientIntermediateCA",
                "ks:certificate": read_pem_b64(CLIENT_INTR),
            },
            {
                "^ks:name": "TrustedClientLeaf",
                "ks:certificate": read_pem_b64(CLIENT_LEAF),
            },
        ],
        cert_to_names={
            "ncs:cert-to-name": {
                "^ncs:id": "1",
                "ncs:fingerprint": cert_fingerprint(CLIENT_CA),
                "ncs:map-type": "x509c2n:specified",
                "ncs:name": "root",
            }
        },
    )


def do_cert_test(
    mgr, temp_chains, client_ca_certs, server_trusted_client_certs, cert_to_names
):
    install_keystore()
    setup_tls_config(mgr, server_trusted_client_certs, cert_to_names)

    def openssl_connect():
        with open(os.devnull, "r") as n:
            subprocess.check_call(
                "openssl s_client -connect localhost:6513 -CAfile {ca_certs} -cert {certfile} -key {keyfile} "
                "-state -debug -showcerts -verify_return_error -verify 1 2>&1".format(
                    keyfile=CLIENT_LEAF_KEY,
                    certfile=CLIENT_LEAF,
                    ca_certs=temp_chains.create(client_ca_certs),
                ),
                shell=True,
                stdin=n,
            )

    wait_for(openssl_connect, timeout=30, period=0.5)


def setup_tls_config(
    mgr,
    server_trusted_client_certs,
    cert_to_names,
    server_cert_chain=[SERVER_LEAF, SERVER_INTR, SERVER_CA],
):
    config = {
        "ks:keystore": {
            "ks:private-keys": {
                "ks:private-key": {
                    "^ks:name": "ServerKey",
                    "ks:certificate-chains": {
                        "ks:certificate-chain": {
                            "^ks:name": "ServerKeyChain",
                            "ks:certificate": list(
                                map(read_pem_b64, server_cert_chain)
                            ),
                        }
                    },
                }
            },
            "ks:trusted-certificates": {
                "^ks:name": "TrustedClientCerts",
                "ks:trusted-certificate": server_trusted_client_certs,
            },
        },
        "ncs:netconf-server": {
            "ncs:listen": {
                "ncs:endpoint": {
                    "^ncs:name": "EndpointTLS",
                    "ncs:tls": {
                        "ncs:address": "0.0.0.0",
                        "ncs:port": "6513",
                        "ncs:certificates": {
                            "ncs:certificate": {"ncs:name": "ServerKeyChain"}
                        },
                        "ncs:client-auth": {
                            "ncs:trusted-ca-certs": "TrustedClientCerts",
                            'ncs:cert-maps@xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name"': cert_to_names,
                        },
                    },
                }
            }
        },
    }
    edit_config_dict(mgr, config)


def install_keystore():
    shutil.copy(SERVER_LEAF_KEY, "/etc/keystored/keys/ServerKey.pem")
    shutil.copy(SERVER_LEAF, "/etc/keystored/keys/ServerKey.pub.pem")


def read_pem_b64(path):
    with open(path, "r") as f:
        bits = pem.readPemFromFile(f)
        return base64.b64encode(bits).decode("utf-8")


def cert_fingerprint(path):
    with open(path, "r") as f:
        bits = pem.readPemFromFile(f)
        digest = hashlib.sha256(bits).hexdigest()
        # Thanks stack overflow!
        chunked = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
        # 04 is the TLS Hash ID
        return "04:" + chunked


class TempChains:
    def __init__(self):
        self.temp_files = []

    def create(self, certs):
        (_, p) = tempfile.mkstemp()
        with open(p, "w") as f:
            for cert in certs:
                with open(cert, "r") as src:
                    f.write(src.read())
        self.temp_files.append(p)
        return p

    def clean(self):
        for p in self.temp_files:
            os.remove(p)
        self.temp_files = []


@pytest.fixture()
def temp_chains():
    t = TempChains()
    yield t
    t.clean()


@pytest.fixture()
def cleanup(mgr):
    yield
    edit_config_dict(
        mgr,
        {
            "ks:keystore": {
                "ks:private-keys": {
                    "ks:private-key": {
                        "@nc:operation": "remove",
                        "^ks:name": "ServerKey",
                    }
                },
                "ks:trusted-certificates": {
                    "@nc:operation": "remove",
                    "^ks:name": "TrustedClientCerts",
                },
            },
            "ncs:netconf-server": {
                "ncs:listen": {
                    "ncs:endpoint": {
                        "@nc:operation": "remove",
                        "^ncs:name": "EndpointTLS",
                    }
                }
            },
        },
    )
