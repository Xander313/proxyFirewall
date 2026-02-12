from django.contrib import admin

from .models import (
    User,
    HttpMethod,
    Policy,
    Rule,
    Service,
    Url,
    UrlCategory,
    Zone,
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("user_id", "username", "auth_type", "created_at")
    list_filter = ("auth_type",)
    search_fields = ("username",)

@admin.register(HttpMethod)
class HttpMethodAdmin(admin.ModelAdmin):
    list_display = ("method_id", "method")
    search_fields = ("method",)

@admin.register(UrlCategory)
class UrlCategoryAdmin(admin.ModelAdmin):
    list_display = ("category_id", "name", "description")
    search_fields = ("name",)

@admin.register(Url)
class UrlAdmin(admin.ModelAdmin):
    list_display = ("url_id", "scheme", "host", "port", "path", "category")
    list_filter = ("scheme", "port", "category")
    search_fields = ("host", "path")

@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("policy_id", "name", "type", "enabled", "created_at")
    list_filter = ("enabled", "type")
    search_fields = ("name",)

@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "policy", "priority", "action", "enabled", "created_at")
    list_filter = ("enabled", "action", "policy")
    search_fields = ("policy__name",)
    ordering = ("policy", "priority")
    readonly_fields = ("created_at",)

@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ("zone_id", "zone_name", "description")
    search_fields = ("zone_name",)

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("service_id", "name", "protocol", "port")
    list_filter = ("protocol", "port")
    search_fields = ("name",)
