from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'microCA.views.home', name='home'),
    # url(r'^microCA/', include('microCA.foo.urls')),
    url(r'^ca$', 'coreCA.views.cacert'),
    url(r'^ca/(.*)$', 'coreCA.views.cacert'),
    url(r'^keycertchain/(.*)$', 'coreCA.views.keycertchain'),
    
    url(r'^key/(.*)$', 'coreCA.views.key'),
    url(r'^cert/(.*)$', 'coreCA.views.cert'),
    url(r'^chain/(.*)$', 'coreCA.views.chain'),



    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)
