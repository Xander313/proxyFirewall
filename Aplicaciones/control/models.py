from django.db import models
from django.db.models import Q
from django.db.models.functions import Upper


class AuthType(models.TextChoices):
    LOCAL = "LOCAL", "LOCAL"
    LDAP = "LDAP", "LDAP"
    OIDC = "OIDC", "OIDC"
    SAML = "SAML", "SAML"
    OTHER = "OTHER", "OTHER"


class NetProtocol(models.TextChoices):
    TCP = "TCP", "TCP"
    UDP = "UDP", "UDP"


class Verdict(models.TextChoices):
    ALLOW = "ALLOW", "ALLOW"
    DENY = "DENY", "DENY"


class RuleAction(models.TextChoices):
    ALLOW = "ALLOW", "ALLOW"
    DENY = "DENY", "DENY"
    ALERT = "ALERT", "ALERT"
    LOG_ONLY = "LOG_ONLY", "LOG_ONLY"


class User(models.Model):
    user_id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    auth_type = models.CharField(max_length=10, choices=AuthType.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "users"

    def __str__(self):
        return self.username


class HttpMethod(models.Model):
    method_id = models.BigAutoField(primary_key=True)
    method = models.CharField(max_length=16, unique=True)

    class Meta:
        managed = False
        db_table = "http_method"
        constraints = [
            models.CheckConstraint(
                condition=Q(method=Upper("method")),
                name="http_method_uppercase_check",
            )
        ]

    def __str__(self):
        return self.method


class UrlCategory(models.Model):
    category_id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, default="")

    class Meta:
        managed = False
        db_table = "url_category"

    def __str__(self):
        return self.name


class Url(models.Model):
    url_id = models.BigAutoField(primary_key=True)
    scheme = models.CharField(max_length=10)
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField()
    path = models.TextField()
    query = models.TextField(blank=True, default="")
    category = models.ForeignKey(
        UrlCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="category_id",
        related_name="urls",
    )

    class Meta:
        managed = False
        db_table = "url"
        constraints = [
            models.UniqueConstraint(
                fields=["scheme", "host", "port", "path", "query"],
                name="url_scheme_host_port_path_query_key",
            )
        ]

    def __str__(self):
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


class Policy(models.Model):
    policy_id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=150, unique=True)
    type = models.CharField(max_length=50)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "policy"

    def __str__(self):
        return self.name


class Rule(models.Model):
    rule_id = models.BigAutoField(primary_key=True)
    policy = models.ForeignKey(
        Policy,
        on_delete=models.CASCADE,
        db_column="policy_id",
        related_name="rules",
    )
    condition = models.JSONField()
    action = models.CharField(max_length=10, choices=RuleAction.choices)
    priority = models.IntegerField()
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "rule"
        constraints = [
            models.UniqueConstraint(
                fields=["policy", "priority"],
                name="rule_policy_id_priority_key",
            )
        ]

    def __str__(self):
        return f"{self.policy.name}#{self.priority}:{self.action}"


class Zone(models.Model):
    zone_id = models.BigAutoField(primary_key=True)
    zone_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, default="")

    class Meta:
        managed = False
        db_table = "zone"

    def __str__(self):
        return self.zone_name


class Service(models.Model):
    service_id = models.BigAutoField(primary_key=True)
    protocol = models.CharField(max_length=3, choices=NetProtocol.choices)
    port = models.PositiveIntegerField()
    name = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = "service"
        constraints = [
            models.UniqueConstraint(
                fields=["protocol", "port"],
                name="service_protocol_port_key",
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.protocol}/{self.port})"
