import os
import asyncio
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class CAService:
    def __init__(self, cert_dir="certs"):
        self.cert_dir = cert_dir
        self.ca_key_path = os.path.join(cert_dir, "rootCA.key")
        self.ca_cert_path = os.path.join(cert_dir, "rootCA.crt")
        self._root_ca_key = None
        self._root_ca_cert = None
        
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
            
        self._ensure_root_ca()

    def _ensure_root_ca(self):
        if not os.path.exists(self.ca_key_path) or not os.path.exists(self.ca_cert_path):
            print("[CA] Generating new Root CA...")
            self._generate_root_ca()
        else:
            with open(self.ca_key_path, "rb") as f:
                self._root_ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(self.ca_cert_path, "rb") as f:
                self._root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    def _generate_root_ca(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self._root_ca_key = key
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MH"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Pune"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Shadow Spike Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Shadow Spike Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(key, hashes.SHA256(), default_backend())
        
        self._root_ca_cert = cert
        
        # Save to disk
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    async def generate_site_cert(self, hostname):
        """Generates a certificate for a specific hostname, signed by Root CA."""
        # Check if already exists in cache/disk to save time
        cert_path = os.path.join(self.cert_dir, f"{hostname}.crt")
        key_path = os.path.join(self.cert_dir, f"{hostname}.key")
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
             return cert_path, key_path

        # Offload CPU-heavy RSA generation to a thread to avoid freezing the event loop
        return await asyncio.to_thread(self._generate_site_cert_sync, hostname, cert_path, key_path)

    def _generate_site_cert_sync(self, hostname, cert_path, key_path):
        print(f"[CA] Generating spoofed certificate for {hostname}...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self._root_ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        
        cert = builder.sign(self._root_ca_key, hashes.SHA256(), default_backend())
        
        # Save leaf
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return cert_path, key_path

ca_service = CAService()
