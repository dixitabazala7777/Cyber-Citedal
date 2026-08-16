"""
DEEPSHIELD Enterprise — Cryptographic Signature Verifier

Pure cryptographic verification using the `cryptography` library.
Supports RSA (PSS / PKCS1v1.5), ECDSA (P-256 / P-384 / secp256k1), and Ed25519.
"""

import base64
import logging
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding as asym_padding,
    rsa,
    ec,
    ed25519,
    utils as asym_utils,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from .models import KeyAlgorithm

logger = logging.getLogger("DeepShield.SignatureGuard.Verifier")


def _load_public_key(pem_str: str):
    """Load a PEM-encoded public key."""
    pem_bytes = pem_str.encode("utf-8") if isinstance(pem_str, str) else pem_str
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


def verify_signature(
    algorithm: KeyAlgorithm,
    public_key_pem: str,
    payload_b64: str,
    signature_b64: str,
) -> Tuple[bool, str]:
    """
    Verify a digital signature.

    Returns:
        (is_valid, message) tuple.
    """
    try:
        pub_key = _load_public_key(public_key_pem)
        payload = base64.b64decode(payload_b64)
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        return False, f"Failed to decode inputs: {e}"

    try:
        if algorithm == KeyAlgorithm.RSA_PSS:
            if not isinstance(pub_key, rsa.RSAPublicKey):
                return False, "Public key is not RSA"
            pub_key.verify(
                signature,
                payload,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True, "RSA-PSS signature verified successfully"

        elif algorithm == KeyAlgorithm.RSA_PKCS1:
            if not isinstance(pub_key, rsa.RSAPublicKey):
                return False, "Public key is not RSA"
            pub_key.verify(
                signature,
                payload,
                asym_padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True, "RSA-PKCS1v1.5 signature verified successfully"

        elif algorithm == KeyAlgorithm.ECDSA_P256:
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                return False, "Public key is not ECDSA"
            pub_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            return True, "ECDSA P-256 signature verified successfully"

        elif algorithm == KeyAlgorithm.ECDSA_P384:
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                return False, "Public key is not ECDSA"
            pub_key.verify(signature, payload, ec.ECDSA(hashes.SHA384()))
            return True, "ECDSA P-384 signature verified successfully"

        elif algorithm == KeyAlgorithm.ECDSA_SECP256K1:
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                return False, "Public key is not ECDSA"
            pub_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            return True, "ECDSA secp256k1 signature verified successfully"

        elif algorithm == KeyAlgorithm.ED25519:
            if not isinstance(pub_key, ed25519.Ed25519PublicKey):
                return False, "Public key is not Ed25519"
            pub_key.verify(signature, payload)
            return True, "Ed25519 signature verified successfully"

        else:
            return False, f"Unsupported algorithm: {algorithm}"

    except InvalidSignature:
        return False, f"Invalid {algorithm.value} signature — cryptographic verification failed"
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False, f"Verification error: {e}"


def generate_test_keypair(algorithm: KeyAlgorithm) -> Tuple[str, str]:
    """
    Generate a test key pair for simulation purposes.
    Returns (private_key_pem, public_key_pem).
    """
    if algorithm in (KeyAlgorithm.RSA_PSS, KeyAlgorithm.RSA_PKCS1):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    elif algorithm == KeyAlgorithm.ECDSA_P256:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif algorithm == KeyAlgorithm.ECDSA_P384:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif algorithm == KeyAlgorithm.ECDSA_SECP256K1:
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    elif algorithm == KeyAlgorithm.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return priv_pem, pub_pem


def sign_payload(
    algorithm: KeyAlgorithm,
    private_key_pem: str,
    payload_b64: str,
) -> str:
    """
    Sign a payload with the given private key. Returns base64-encoded signature.
    Used for testing / simulation.
    """
    pem_bytes = private_key_pem.encode("utf-8")
    private_key = serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
    payload = base64.b64decode(payload_b64)

    if algorithm == KeyAlgorithm.RSA_PSS:
        sig = private_key.sign(
            payload,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif algorithm == KeyAlgorithm.RSA_PKCS1:
        sig = private_key.sign(payload, asym_padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == KeyAlgorithm.ECDSA_P256:
        sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    elif algorithm == KeyAlgorithm.ECDSA_P384:
        sig = private_key.sign(payload, ec.ECDSA(hashes.SHA384()))
    elif algorithm == KeyAlgorithm.ECDSA_SECP256K1:
        sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    elif algorithm == KeyAlgorithm.ED25519:
        sig = private_key.sign(payload)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return base64.b64encode(sig).decode("utf-8")
