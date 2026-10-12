"""Prepare private local Foundation/JWT configuration without changing source."""
import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

TASK = Path(os.environ.get("EA_WORKSPACE", str(Path(__file__).resolve().parents[4]))).resolve()
RUNTIME = TASK / "work/reference-runtime"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main():
    offset = int(os.environ.get("EA_PORT_OFFSET", "0"))
    instance = os.environ.get("EA_INSTANCE", "earned-authority")
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(RUNTIME, 0o700)
    tls = RUNTIME / "tls"
    tls.mkdir(exist_ok=True)
    os.chmod(tls, 0o755)
    now = datetime.now(timezone.utc)
    if not (tls / "foundation.crt").exists():
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Earned Authority Local CA")])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(ca_key, hashes.SHA256()))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "s0s1-rest-bff")]))
                .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("s0s1-rest-bff"), x509.DNSName("gateway"),
                                                          x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (tls / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (tls / "foundation.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tls / "foundation.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        # The enclosing runtime directory is private; the mounted TLS directory
        # permits the nonroot Foundation container to read its own key.
        for path in tls.iterdir():
            os.chmod(path, 0o644)
    signer_path = RUNTIME / "jwt-private.pem"
    if signer_path.exists():
        signer = serialization.load_pem_private_key(signer_path.read_bytes(), password=None)
    else:
        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer_path.write_bytes(signer.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(signer_path, 0o600)
    numbers = signer.public_key().public_numbers()
    jwks_dir = RUNTIME / "jwks" / ".well-known"
    jwks_dir.mkdir(parents=True, exist_ok=True)
    (jwks_dir / "jwks.json").write_text(json.dumps({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
        "kid": "earned-authority-local-1", "n": b64(numbers.n.to_bytes((numbers.n.bit_length()+7)//8, "big")),
        "e": b64(numbers.e.to_bytes((numbers.e.bit_length()+7)//8, "big"))}]}))
    header = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "earned-authority-local-1"}, separators=(",", ":")).encode())
    claims = b64(json.dumps({"sub": "earned-authority-operator", "iat": int(time.time()), "exp": int(time.time()) + 86400}, separators=(",", ":")).encode())
    signing_input = (header + "." + claims).encode()
    token = signing_input.decode() + "." + b64(signer.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    env_path = RUNTIME / "reference.env"
    previous = {}
    if env_path.exists():
        previous = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if "=" in line)
    if "EA_PORT_OFFSET" not in os.environ and previous:
        offset = int(previous.get("FOUNDATION_GATEWAY_PORT", "29585")) - 29585
    if "EA_INSTANCE" not in os.environ and previous:
        instance = previous.get("REFERENCE_INSTANCE", instance)
    values = {
        "REFERENCE_INSTANCE": instance,
        "FOUNDATION_DB_PORT": str(29532 + offset), "FOUNDATION_BFF_PORT": str(29543 + offset),
        "FOUNDATION_BFF_HEALTH_PORT": str(29599 + offset), "FOUNDATION_GATEWAY_PORT": str(29585 + offset),
        "FOUNDATION_GATEWAY_HEALTH_PORT": str(29586 + offset), "OPA_PORT": str(29582 + offset), "JWKS_PORT": str(29588 + offset),
        "REFERENCE_RUNTIME_DIR": str(RUNTIME), "FOUNDATION_SOURCE_DIR": str(TASK / "work/foundation-track"),
        "PASSPORT_SOURCE_DIR": str(TASK / "work/passport-track"),
        "PASSPORT_SDK_DIR": str(TASK / "work/passport-python-sdk"),
        "CASCADE_SOURCE_DIR": str(TASK / "work/cascade-compression-oss"),
        "GCL_SOURCE_DIR": str(TASK / "work/governed-cognitive-loop-oss"),
        "FOUNDATION_DB_PASSWORD": previous.get("FOUNDATION_DB_PASSWORD", secrets.token_hex(24)),
        "ARE_FOUNDATION_BASE_URL": "http://127.0.0.1:" + str(29585 + offset), "ARE_FOUNDATION_TOKEN": token,
        "ARE_PASSPORT_MUTATION_TOKEN": previous.get("ARE_PASSPORT_MUTATION_TOKEN", secrets.token_hex(32)),
        "ARE_PASSPORT_REGISTRY_URL": "http://127.0.0.1:" + str(29585 + offset), "ARE_PASSPORT_REGISTRY_TOKEN": token,
        "ARE_PASSPORT_FENCE_LOCK_PATH": str(RUNTIME / "authority.fence"),
        "ARE_PASSPORT_MODE": "durable", "ARE_PASSPORT_STATE_PATH": str(RUNTIME / "passport/state.json"),
        "ARE_PASSPORT_KEY_PATH": str(RUNTIME / "passport/ed25519.pem"), "ARE_PASSPORT_BIND_HOST": "127.0.0.1",
        "ARE_PASSPORT_PUBLIC_KEY_PATH": str(RUNTIME / "passport/ed25519-public.pem"),
        "ARE_PASSPORT_GRPC_PORT": str(29594 + offset), "ARE_PASSPORT_HEALTH_PORT": str(29580 + offset), "ARE_PASSPORT_METRICS_PORT": str(29581 + offset),
        "ARE_PASSPORT_POLICY_ID": "earned-authority-reference", "ARE_PASSPORT_POLICY_VERSION": "0.1.0",
    }
    for field in ("OPA_POLICY_SNAPSHOT_DIR", "ARE_OPA_BASE_URL", "ARE_OPA_POLICY_ID", "ARE_OPA_POLICY_DIGEST", "ARE_OPA_AUTHZ_POLICY_ID", "ARE_OPA_AUTHZ_POLICY_DIGEST", "FOUNDATION_SOURCE_DIR",
                  "PASSPORT_SOURCE_DIR", "PASSPORT_SDK_DIR", "CASCADE_SOURCE_DIR", "GCL_SOURCE_DIR"):
        if field in previous:
            values[field] = previous[field]
    if previous.get("ARE_PASSPORT_HISTORICAL_KEYS_PATH"):
        values["ARE_PASSPORT_HISTORICAL_KEYS_PATH"] = previous["ARE_PASSPORT_HISTORICAL_KEYS_PATH"]
    (RUNTIME / "passport").mkdir(mode=0o700, exist_ok=True)
    env_path.write_text("".join(f"{key}={value}\n" for key,value in values.items()))
    os.chmod(env_path, 0o600)
    print(json.dumps({"env_file": str(env_path), "token_printed": False, "token_valid_seconds": 86400,
                      "foundation_base_url": values["ARE_FOUNDATION_BASE_URL"]}))


if __name__ == "__main__":
    main()
