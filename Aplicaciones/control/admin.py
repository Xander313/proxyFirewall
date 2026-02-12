from django.contrib import admin

from .models import HttpMethod, Policy, Rule, Service, Url, UrlCategory, User, Zone

admin.site.register(User)
admin.site.register(HttpMethod)
admin.site.register(UrlCategory)
admin.site.register(Url)
admin.site.register(Policy)
admin.site.register(Rule)
admin.site.register(Zone)
admin.site.register(Service)
