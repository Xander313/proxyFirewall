from django.core.management.base import BaseCommand

from Aplicaciones.control.models import HttpMethod, Policy, Rule, RuleAction, Url, UrlCategory


class Command(BaseCommand):
    help = "Create demo data for web filtering rules."

    def handle(self, *args, **options):
        social_category, _ = UrlCategory.all_objects.update_or_create(
            name="Redes Sociales",
            defaults={
                "description": "Sitios de redes sociales bloqueados en horario de clase.",
                "is_delete": False,
            },
        )

        for host in ("facebook.com", "instagram.com", "tiktok.com", "x.com"):
            Url.all_objects.update_or_create(
                scheme="https",
                host=host,
                port=443,
                path="/",
                query="",
                defaults={"category": social_category, "is_delete": False},
            )

        HttpMethod.all_objects.update_or_create(method="GET", defaults={"is_delete": False})
        HttpMethod.all_objects.update_or_create(method="POST", defaults={"is_delete": False})

        policy, _ = Policy.all_objects.update_or_create(
            name="Filtrado Web",
            defaults={"type": "SQUID", "enabled": True, "is_delete": False},
        )

        rule, created = Rule.all_objects.update_or_create(
            policy=policy,
            priority=10,
            defaults={
                "url_category": social_category,
                "note": "Bloquear redes sociales durante horario de clase para reducir distracciones y proteger ancho de banda academico.",
                "schedule_days": "MON,TUE,WED,THU,FRI",
                "schedule_start": "07:00",
                "schedule_end": "13:00",
                "schedule_tz": "America/Guayaquil",
                "action": RuleAction.DENY,
                "enabled": True,
                "is_delete": False,
            },
        )

        status = "created" if created else "updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"Demo data {status}. Rule id={rule.rule_id}, policy={policy.name}, action={rule.action}, priority={rule.priority}."
            )
        )
