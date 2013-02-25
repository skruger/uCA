from OpenSSL import crypto, SSL
import socket
import os

from coreCA.models import Certificate, CertificateAuthority, KeyPair

class CertificateException(Exception):
    pass

def make_signed_cert(commonName, pub_key, ca_key, ca_cert=False, years=1, C=False, ST=False, L=False, O=False, extensions=False):
    cert_object = Certificate(commonName=commonName)
    cert_object.save()

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
    
    cert.set_serial_number(cert_object.id)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(years*365*24*3600)
    
    if extensions:
        cert.add_extensions(extensions)
    
    if not ca_cert:
        ca_cert = cert
    
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
    
    ca = CertificateAuthority(commonName=commonName)
    
    extensions = [crypto.X509Extension("basicConstraints", True, "CA:TRUE"),
                  crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
                  ]
    
    cert = make_signed_cert(commonName, ca_key, ca_key, years=years, extensions=extensions, **kwargs)
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
