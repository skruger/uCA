from OpenSSL import crypto, SSL
import socket
import os
from microCA import settings

from coreCA.models import Certificate, CertificateAuthority, KeyPair

class CertificateException(Exception):
    pass

def create_unsigned_cert(commonName, years=1, C=False, ST=False, L=False, O=False):
    cert = crypto.X509()
    if C:
        cert.get_subject().C = C
    if ST:
        cert.get_subject().ST = ST
    if L:
        cert.get_subject().L = L
    if O:
        cert.get_subject().O = O
    cert.get_subject().CN = commonName
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(years*365*24*3600)
    return cert

def make_signed_cert(commonName, pub_key, ca_key, ca_cert=False, years=1, C=False, ST=False, L=False, O=False, extensions=False):
    cert_object = Certificate(commonName=commonName)
    cert_object.save()

    cert = create_unsigned_cert(commonName, years=years, C=C, ST=ST, L=L, O=O)

    cert.set_serial_number(cert_object.id)

    if not ca_cert:
        ca_cert = cert

    extensions = [crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca_cert)]

    cert.add_extensions(extensions)

    
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(pub_key)
    cert.sign(ca_key, 'sha1')
    cert_object.certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    cert_object.active = True
    cert_object.save()
    return cert_object


def make_ca_cert(commonName, years=20, **kwargs):
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_csr = create_unsigned_cert(commonName, years=years, **kwargs)
    ca = CertificateAuthority(commonName=commonName)
    cert = Certificate(commonName=commonName)
    cert.save()
    
    ca_csr.set_serial_number(cert.id)
    ca_csr.set_issuer(ca_csr.get_subject())
    ca_csr.set_pubkey(ca_key)
    
    extensions = [crypto.X509Extension("basicConstraints", True, "CA:TRUE"),
                  crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
                  crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca_csr),
#                  crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca_csr),
                  ]
    
    ca_csr.add_extensions(extensions)
    ca_csr.sign(ca_key, 'sha1')
    
    cert.certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_csr)
    cert.active = True
    cert.save()

    ca.certificate = cert
    ca.private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key)
    ca.save()
    return ca

def get_ca(commonName):
    return CertificateAuthority.objects.get(commonName=commonName)

def quick_gen_cert(ca_CN, CN, years=2, **kwargs):
    try:
        CA = get_ca(ca_CN)
    except CertificateAuthority.DoesNotExist:
        raise CertificateException()
    pubkey = crypto.PKey()
    pubkey.generate_key(crypto.TYPE_RSA, 2048)
    cert = make_signed_cert(CN, pubkey, CA.load_private_key(),
                            ca_cert=CA.load_certificate(), years=years)
    cert.ca_certificate = CA.certificate
    cert.save()

    key = KeyPair()
    key.commonName = CN
    key.active = True
    key.certificate = cert
    key.private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pubkey)
    key.save()
    return key

def get_or_create_keypair(commonName):
    try:
        keypair = KeyPair.objects.get(commonName=commonName)
    except KeyPair.DoesNotExist:
        keypair = quick_gen_cert(settings.CERTIFICATE_AUTHORITY_CN, commonName, years=5)
        
    return keypair
