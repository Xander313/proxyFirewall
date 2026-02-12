from django.contrib import admin

from .models import CacheEntry, ErrorLog, FirewallEvent, Request, RuleMatch, SecurityAlert

admin.site.register(Request)
admin.site.register(RuleMatch)
admin.site.register(SecurityAlert)
admin.site.register(FirewallEvent)
admin.site.register(CacheEntry)
admin.site.register(ErrorLog)
