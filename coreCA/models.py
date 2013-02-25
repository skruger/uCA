from django.db import models
from django.contrib import admin
from OpenSSL import crypto

class Certificate(models.Model):
    commonName = models.CharField(max_length=200)
    active = models.BooleanField(default=False)
    certificate_pem = models.TextField(default='')
    ca_certificate = models.ForeignKey('self', blank=True, null=True)

    def __unicode__(self):
        return u"%s" % self.commonName

admin.site.register(Certificate)

class CertificateAuthority(models.Model):
    commonName = models.CharField(max_length=200, unique=True)
    active = models.BooleanField(default=False)
    passkey = models.CharField(blank=True, max_length=50)
    certificate = models.ForeignKey('Certificate')
    private_key_pem = models.TextField(default='')
    
    def load_private_key(self, *args):
        return crypto.load_privatekey(crypto.FILETYPE_PEM, self.private_key_pem, *args)
    
    def load_certificate(self):
        cert = self.certificate.certificate_pem
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    def __unicode__(self):
        return u"%s" % self.commonName

admin.site.register(CertificateAuthority)

class KeyPair(models.Model):
    commonName = models.CharField(max_length=200, unique=True)
    active = models.BooleanField(default=True)
    passkey = models.CharField(blank=True, max_length=50)
    certificate = models.ForeignKey('Certificate')
    private_key_pem = models.TextField(default='')
    
    def load_private_key(self, *args):
        return crypto.load_privatekey(crypto.FILETYPE_PEM, self.private_key_pem, *args)
    
    def load_certificate(self):
        cert = self.certificate.certificate_pem
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    def __unicode__(self):
        return u"%s" % self.commonName
    
admin.site.register(KeyPair)
