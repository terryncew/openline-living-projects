"""Generate disposable fixture credentials only. Never reuse for a real deployment."""
from datetime import datetime,timedelta,timezone
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID


def generate(directory):
    out=Path(directory);out.mkdir(parents=True,exist_ok=True)
    now=datetime.now(timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'OpenLine disposable fixture CA')])
    ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
    (out/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result={}
    for name,eku in [('server',ExtendedKeyUsageOID.SERVER_AUTH),('worker',ExtendedKeyUsageOID.CLIENT_AUTH),('other',ExtendedKeyUsageOID.CLIENT_AUTH)]:
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        b=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.ExtendedKeyUsage([eku]),critical=True)
        if name=='server':b=b.add_extension(x509.SubjectAlternativeName([x509.DNSName('openline.local')]),critical=False)
        cert=b.sign(ca_key,hashes.SHA256())
        (out/(name+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (out/(name+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        (out/(name+'.key')).chmod(0o600)
        result[name]=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return result
