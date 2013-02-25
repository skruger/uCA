
from django.http import HttpResponse, Http404
from django.template import Context, loader
from django.shortcuts import render_to_response

from coreCA.models import Certificate, CertificateAuthority, KeyPair
from coreCA.lib import quick_gen_cert, get_ca

from microCA import settings

def cacert(request, commonName=None):
    if commonName:
        try:
            ca = get_ca(commonName)
        except CertificateAuthority.DoesNotExist:
            raise Http404
        response = HttpResponse(ca.certificate.certificate_pem, mimetype="text/plain")
        response['Content-Disposition'] = 'attachment; filename="%s.cacert.pem"' % commonName
        return response
    calist = CertificateAuthority.objects.all()
    return render_to_response('coreCA/calist.html', {'calist': calist})

def keycertchain(request, cname):
    try:
        keypair = KeyPair.objects.get(commonName=cname)
    except KeyPair.DoesNotExist:
        keypair = quick_gen_cert(settings.CERTIFICATE_AUTHORITY_CN, cname, years=5)
    
    output = keypair.certificate.certificate_pem
    if keypair.certificate.ca_certificate:
        output = output + keypair.certificate.ca_certificate.certificate_pem
    output = output + keypair.private_key_pem
    return HttpResponse(output, mimetype="text/plain")
