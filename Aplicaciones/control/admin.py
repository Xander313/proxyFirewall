from django.contrib import admin

from .models import (
    HttpMethod,
    Policy,
    Rule,
    Service,
    Url,
    UrlCategory,
    User,
    Zone,
)


@admin.action(description="Activar seleccionados")
def make_enabled(modeladmin, request, queryset):
    queryset.update(enabled=True)


@admin.action(description="Desactivar seleccionados")
def make_disabled(modeladmin, request, queryset):
    queryset.update(enabled=False)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("user_id", "username", "auth_type", "created_at")
    list_filter = ("auth_type",)
    search_fields = ("username",)


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("policy_id", "name", "type", "enabled", "is_delete", "created_at")
    list_filter = ("enabled", "type", "is_delete")
    search_fields = ("name",)
    actions = (make_enabled, make_disabled)


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = (
        "rule_id",
        "policy",
        "url_category",
        "priority",
        "action",
        "enabled",
        "is_delete",
        "created_at",
    )
    list_filter = ("enabled", "action", "policy", "url_category", "is_delete")
    search_fields = ("policy__name", "url_category__name", "note")
    ordering = ("policy", "priority")
    readonly_fields = ("created_at",)
    actions = (make_enabled, make_disabled)


@admin.register(UrlCategory)
class UrlCategoryAdmin(admin.ModelAdmin):
    list_display = ("category_id", "name", "description", "is_delete")
    list_filter = ("is_delete",)
    search_fields = ("name",)


@admin.register(Url)
class UrlAdmin(admin.ModelAdmin):
    list_display = ("url_id", "scheme", "host", "port", "path", "category", "is_delete")
    list_filter = ("scheme", "port", "category", "is_delete")
    search_fields = ("host", "path")


@admin.register(HttpMethod)
class HttpMethodAdmin(admin.ModelAdmin):
    list_display = ("method_id", "method", "is_delete")
    list_filter = ("is_delete",)
    search_fields = ("method",)


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ("zone_id", "zone_name", "description", "is_delete")
    list_filter = ("is_delete",)
    search_fields = ("zone_name",)


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("service_id", "name", "protocol", "port", "is_delete")
    list_filter = ("protocol", "port", "is_delete")
    search_fields = ("name",)
