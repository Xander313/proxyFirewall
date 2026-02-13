from django.core.management.base import BaseCommand
from django.db import connection

from Aplicaciones.control.models import HttpMethod, Policy, Rule, RuleAction, Url, UrlCategory


class Command(BaseCommand):
    help = "Crea/actualiza una regla demo: bloquear redes sociales en horario de clase."

    def handle(self, *args, **options):
        policy, _ = Policy.all_objects.update_or_create(
            name="Politica Académica",
            defaults={"type": "CONTENT_FILTER", "enabled": True, "is_delete": False},
        )

        social_cat, _ = UrlCategory.all_objects.update_or_create(
            name="Redes Sociales",
            defaults={
                "description": "Plataformas de redes sociales no permitidas durante horario de clase.",
                "is_delete": False,
            },
        )

        HttpMethod.all_objects.update_or_create(
            method="GET", defaults={"is_delete": False}
        )
        HttpMethod.all_objects.update_or_create(
            method="POST", defaults={"is_delete": False}
        )

        for host in ("facebook.com", "instagram.com", "tiktok.com", "x.com"):
            Url.all_objects.update_or_create(
                scheme="https",
                host=host,
                port=443,
                path="/",
                query="",
                defaults={"category": social_cat, "is_delete": False},
            )

        rule, created = Rule.all_objects.update_or_create(
            policy=policy,
            priority=100,
            defaults={
                "url_category": social_cat,
                "note": (
                    "Bloqueo de redes sociales durante horario de clase para preservar "
                    "ancho de banda academico y reducir distracciones en aula."
                ),
                "schedule_days": "MON,TUE,WED,THU,FRI",
                "schedule_start": "07:00",
                "schedule_end": "13:00",
                "schedule_tz": "America/Guayaquil",
                "action": RuleAction.DENY,
                "enabled": True,
                "is_delete": False,
            },
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Regla {'creada' if created else 'actualizada'}: id={rule.rule_id}, policy={policy.name}, action={rule.action}"
            )
        )

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.rule_id, p.name AS policy, r.priority, r.action, r.enabled, r.note, r.schedule_days, r.schedule_start, r.schedule_end, r.schedule_tz
                FROM rule r
                JOIN policy p ON p.policy_id = r.policy_id
                WHERE r.rule_id = %s
                """,
                [rule.rule_id],
            )
            row = cursor.fetchone()

        self.stdout.write("Registro en PostgreSQL (rule):")
        self.stdout.write(str(row))
