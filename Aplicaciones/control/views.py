from pathlib import Path
import shlex
import subprocess

from django.conf import settings
from django.contrib import messages
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.shortcuts import get_object_or_404, redirect, render

from .forms import (
    HttpMethodForm,
    PolicyForm,
    RuleForm,
    ServiceForm,
    UrlCategoryForm,
    UrlForm,
    ZoneForm,
)
from .models import HttpMethod, Policy, Rule, Service, Url, UrlCategory, Zone


def _default_export_path() -> Path:
    output_path = getattr(settings, "SQUID_RULES_OUTPUT_PATH", None)
    if output_path:
        return Path(output_path).expanduser()
    return Path(settings.BASE_DIR) / "generated" / "django_squid_rules.conf"


def _apply_squid_rules() -> str:
    output_path = _default_export_path()
    call_command("export_squid_rules", output=str(output_path))

    reload_cmd = (getattr(settings, "SQUID_RELOAD_COMMAND", "") or "").strip()
    if not reload_cmd:
        return f"Reglas aplicadas en Squid. Archivo actualizado: {output_path}"

    completed = subprocess.run(
        shlex.split(reload_cmd),
        check=True,
        capture_output=True,
        text=True,
    )
    command_result = (completed.stdout or completed.stderr or "OK").strip()
    return (
        f"Reglas aplicadas en Squid. Archivo actualizado: {output_path}. "
        f"Recarga de Squid: {command_result}"
    )


def _humanize_validation_error(exc: ValidationError) -> str:
    messages_list = []
    if hasattr(exc, "message_dict"):
        for field, field_messages in exc.message_dict.items():
            for msg in field_messages:
                if field == "__all__":
                    messages_list.append(str(msg))
                else:
                    messages_list.append(f"{field}: {msg}")
    elif hasattr(exc, "messages"):
        messages_list = [str(msg) for msg in exc.messages]
    else:
        messages_list = [str(exc)]

    message_text = " ".join(m.strip() for m in messages_list if m).strip()
    if (
        "rule_policy_priority_active_uniq" in message_text
        or "restriccion \"rule_policy_priority_active_uniq\"" in message_text.lower()
        or "restricción \"rule_policy_priority_active_uniq\"" in message_text.lower()
    ):
        return "Ya existe una regla con la misma politica y prioridad. Cambia la prioridad o edita la regla existente."
    return message_text or "No se pudo guardar la regla por un error de validacion."


WEEK_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
DAY_LABEL = {
    "MON": "LUN",
    "TUE": "MAR",
    "WED": "MIE",
    "THU": "JUE",
    "FRI": "VIE",
    "SAT": "SAB",
    "SUN": "DOM",
}


def _schedule_text(rule):
    days = rule.schedule_days_list
    start = rule.schedule_start
    end = rule.schedule_end
    if not days or not start or not end:
        return "Sin horario"

    if days == ["MON", "TUE", "WED", "THU", "FRI"]:
        day_text = "LUN-VIE"
    elif days == WEEK_DAYS:
        day_text = "TODOS"
    else:
        day_text = ",".join(DAY_LABEL.get(d, d) for d in days)
    return f"{day_text} {start.strftime('%H:%M')}-{end.strftime('%H:%M')}"


def _rule_form_context(rule=None, form_data=None):
    defaults = {
        "policy_id": str(rule.policy_id) if rule else "",
        "action": (rule.action if rule else "DENY"),
        "priority": (rule.priority if rule else 10),
        "enabled": (rule.enabled if rule else True),
        "url_category": (str(rule.url_category_id) if rule and rule.url_category_id else ""),
        "note": (rule.note if rule else ""),
        "days": (rule.schedule_days_list if rule else []),
        "start": (rule.schedule_start.strftime("%H:%M") if rule and rule.schedule_start else ""),
        "end": (rule.schedule_end.strftime("%H:%M") if rule and rule.schedule_end else ""),
        "tz": (rule.schedule_tz if rule else "America/Guayaquil"),
    }
    if form_data is not None:
        defaults.update(form_data)

    return {
        "rule": rule,
        "policies": Policy.objects.filter(enabled=True, is_delete=False).order_by("name"),
        "categories": UrlCategory.objects.filter(is_delete=False).order_by("name"),
        "week_days": WEEK_DAYS,
        "initial": defaults,
    }


def _required_int(post_data, key, label):
    raw = post_data.get(key)
    if raw in (None, ""):
        raise ValidationError(f"Debes seleccionar {label}.")
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} invalida.") from exc


def control_index(request):
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "exportar_squid":
            try:
                result = _apply_squid_rules()
                messages.success(request, result)
            except Exception as exc:
                messages.error(request, f"No se pudo exportar reglas: {exc}")
            return redirect("control_index")

        if action == "alternar_regla":
            rule = get_object_or_404(Rule, pk=request.POST.get("rule_id"))
            rule.enabled = not rule.enabled
            rule.save(update_fields=["enabled"])
            messages.success(
                request,
                f"Regla {rule.rule_id} {'activada' if rule.enabled else 'desactivada'}.",
            )
            return redirect("control_index")

    rules = Rule.all_objects.select_related("policy").order_by("policy_id", "priority", "rule_id")

    preview_lines = []
    export_path = _default_export_path()
    try:
        if export_path.exists():
            preview_lines = export_path.read_text(encoding="utf-8").splitlines()[:25]
    except OSError:
        # Ignore permission/path errors when previewing files outside the project.
        preview_lines = []

    context = {
        "rules": rules,
        "export_path": str(export_path),
        "preview_lines": preview_lines,
    }
    return render(request, "control/control_index.html", context)


def edit_rule(request, rule_id):
    rule = get_object_or_404(Rule.all_objects.select_related("policy"), pk=rule_id)

    if request.method == "POST":
        form = RuleForm(request.POST, instance=rule)
        if form.is_valid():
            form.save()
            messages.success(request, f"Regla {rule.rule_id} actualizada.")
            return redirect("control_index")
        messages.error(request, "No se pudo actualizar la regla. Revisa el JSON de condicion.")
    else:
        form = RuleForm(instance=rule)

    return render(request, "control/rule_edit.html", {"rule": rule, "form": form})


# ---------------------
# Rules CRUD (panel web)
# ---------------------
def rule_list(request):
    rules_qs = Rule.all_objects.select_related("policy").order_by("policy_id", "priority", "rule_id")
    rules = []
    for r in rules_qs:
        r.schedule_display = _schedule_text(r)
        rules.append(r)
    return render(request, "control/rule_list.html", {"rules": rules})


def rule_create(request):
    if request.method == "POST":
        try:
            policy_id = _required_int(request.POST, "policy", "una politica")
            category_id = _required_int(request.POST, "url_category", "una categoria URL")
            rule = Rule(
                policy_id=policy_id,
                url_category_id=category_id,
                note=(request.POST.get("note") or "").strip(),
                action=request.POST.get("action", "DENY"),
                priority=int(request.POST.get("priority", "10")),
                enabled=request.POST.get("enabled") == "on",
                schedule_start=(request.POST.get("start") or None),
                schedule_end=(request.POST.get("end") or None),
                schedule_tz=(request.POST.get("tz") or "").strip(),
            )
            rule.schedule_days_list = request.POST.getlist("days")
            rule.save()
            messages.success(request, f"Regla {rule.rule_id} creada correctamente.")
            return redirect("rule_list")
        except ValidationError as exc:
            messages.error(request, _humanize_validation_error(exc))
            form_data = {
                "policy_id": request.POST.get("policy", ""),
                "action": request.POST.get("action", "DENY"),
                "priority": request.POST.get("priority", "10"),
                "enabled": request.POST.get("enabled") == "on",
                "url_category": request.POST.get("url_category", ""),
                "note": request.POST.get("note", ""),
                "days": request.POST.getlist("days"),
                "start": request.POST.get("start", ""),
                "end": request.POST.get("end", ""),
                "tz": request.POST.get("tz", "America/Guayaquil"),
            }
            return render(
                request,
                "control/rule_form.html",
                _rule_form_context(rule=None, form_data=form_data),
            )
        except (ValueError, IntegrityError):
            messages.error(
                request,
                "Ya existe una regla con la misma politica y prioridad. Cambia la prioridad o edita la regla existente.",
            )
            form_data = {
                "policy_id": request.POST.get("policy", ""),
                "action": request.POST.get("action", "DENY"),
                "priority": request.POST.get("priority", "10"),
                "enabled": request.POST.get("enabled") == "on",
                "url_category": request.POST.get("url_category", ""),
                "note": request.POST.get("note", ""),
                "days": request.POST.getlist("days"),
                "start": request.POST.get("start", ""),
                "end": request.POST.get("end", ""),
                "tz": request.POST.get("tz", "America/Guayaquil"),
            }
            return render(
                request,
                "control/rule_form.html",
                _rule_form_context(rule=None, form_data=form_data),
            )

    return render(request, "control/rule_form.html", _rule_form_context())


def rule_edit(request, rule_id):
    rule = get_object_or_404(Rule.all_objects.select_related("policy"), pk=rule_id)
    if request.method == "POST":
        try:
            rule.policy_id = _required_int(request.POST, "policy", "una politica")
            rule.url_category_id = _required_int(request.POST, "url_category", "una categoria URL")
            rule.note = (request.POST.get("note") or "").strip()
            rule.action = request.POST.get("action", "DENY")
            rule.priority = int(request.POST.get("priority", "10"))
            rule.enabled = request.POST.get("enabled") == "on"
            rule.schedule_start = request.POST.get("start") or None
            rule.schedule_end = request.POST.get("end") or None
            rule.schedule_tz = (request.POST.get("tz") or "").strip()
            rule.schedule_days_list = request.POST.getlist("days")
            rule.save()
            messages.success(request, f"Regla {rule.rule_id} actualizada.")
            return redirect("rule_list")
        except ValidationError as exc:
            messages.error(request, _humanize_validation_error(exc))
            form_data = {
                "policy_id": request.POST.get("policy", ""),
                "action": request.POST.get("action", "DENY"),
                "priority": request.POST.get("priority", "10"),
                "enabled": request.POST.get("enabled") == "on",
                "url_category": request.POST.get("url_category", ""),
                "note": request.POST.get("note", ""),
                "days": request.POST.getlist("days"),
                "start": request.POST.get("start", ""),
                "end": request.POST.get("end", ""),
                "tz": request.POST.get("tz", "America/Guayaquil"),
            }
            return render(
                request,
                "control/rule_form.html",
                _rule_form_context(rule=rule, form_data=form_data),
            )
        except (ValueError, IntegrityError):
            messages.error(
                request,
                "Ya existe una regla con la misma politica y prioridad. Cambia la prioridad o edita la regla existente.",
            )
            form_data = {
                "policy_id": request.POST.get("policy", ""),
                "action": request.POST.get("action", "DENY"),
                "priority": request.POST.get("priority", "10"),
                "enabled": request.POST.get("enabled") == "on",
                "url_category": request.POST.get("url_category", ""),
                "note": request.POST.get("note", ""),
                "days": request.POST.getlist("days"),
                "start": request.POST.get("start", ""),
                "end": request.POST.get("end", ""),
                "tz": request.POST.get("tz", "America/Guayaquil"),
            }
            return render(
                request,
                "control/rule_form.html",
                _rule_form_context(rule=rule, form_data=form_data),
            )

    return render(request, "control/rule_form.html", _rule_form_context(rule=rule))


def rule_toggle(request, rule_id):
    rule = get_object_or_404(Rule, pk=rule_id)
    if request.method == "POST":
        rule.enabled = not rule.enabled
        rule.save(update_fields=["enabled"])
        messages.success(
            request, f"Regla {rule.rule_id} {'activada' if rule.enabled else 'desactivada'}."
        )
    return redirect("rule_list")


def rule_apply(request):
    if request.method == "POST":
        try:
            result = _apply_squid_rules()
            messages.success(request, result)
        except Exception as exc:
            messages.error(request, f"No se pudo aplicar reglas en Squid: {exc}")
    return redirect("rule_list")


# ---------------------
# Politicas
# ---------------------
def policy_list(request):
    policies = Policy.all_objects.order_by("name")
    return render(request, "control/policy_list.html", {"policies": policies})


def policy_create(request):
    if request.method == "POST":
        form = PolicyForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Politica creada.")
            return redirect("policy_list")
        messages.error(request, "No se pudo crear la politica.")
    else:
        form = PolicyForm()
    return render(request, "control/policy_form.html", {"form": form, "titulo": "Agregar Politica"})


def policy_edit(request, policy_id):
    policy = get_object_or_404(Policy.all_objects, pk=policy_id)
    if request.method == "POST":
        form = PolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            messages.success(request, "Politica actualizada.")
            return redirect("policy_list")
        messages.error(request, "No se pudo actualizar la politica.")
    else:
        form = PolicyForm(instance=policy)
    return render(request, "control/policy_form.html", {"form": form, "titulo": "Editar Politica"})


def policy_delete(request, policy_id):
    policy = get_object_or_404(Policy.all_objects, pk=policy_id)
    if request.method == "POST":
        policy.delete()
        messages.success(request, "Politica eliminada (borrado logico).")
    return redirect("policy_list")


# ---------------------
# Categorias URL
# ---------------------
def category_list(request):
    categories = UrlCategory.all_objects.order_by("name")
    return render(request, "control/category_list.html", {"categories": categories})


def category_create(request):
    if request.method == "POST":
        form = UrlCategoryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Categoria creada.")
            return redirect("category_list")
        messages.error(request, "No se pudo crear la categoria.")
    else:
        form = UrlCategoryForm()
    return render(request, "control/category_form.html", {"form": form, "titulo": "Agregar Categoria"})


def category_edit(request, category_id):
    category = get_object_or_404(UrlCategory.all_objects, pk=category_id)
    if request.method == "POST":
        form = UrlCategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, "Categoria actualizada.")
            return redirect("category_list")
        messages.error(request, "No se pudo actualizar la categoria.")
    else:
        form = UrlCategoryForm(instance=category)
    return render(request, "control/category_form.html", {"form": form, "titulo": "Editar Categoria"})


def category_delete(request, category_id):
    category = get_object_or_404(UrlCategory.all_objects, pk=category_id)
    if request.method == "POST":
        category.delete()
        messages.success(request, "Categoria eliminada (borrado logico).")
    return redirect("category_list")


# ---------------------
# URLs
# ---------------------
def url_list(request):
    urls = Url.all_objects.select_related("category").order_by("host", "path")
    return render(request, "control/url_list.html", {"urls": urls})


def url_create(request):
    if request.method == "POST":
        form = UrlForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "URL creada.")
            return redirect("url_list")
        messages.error(request, "No se pudo crear la URL.")
    else:
        form = UrlForm()
    return render(request, "control/url_form.html", {"form": form, "titulo": "Agregar URL"})


def url_edit(request, url_id):
    obj = get_object_or_404(Url.all_objects, pk=url_id)
    if request.method == "POST":
        form = UrlForm(request.POST, instance=obj)
        if form.is_valid():
            form.save()
            messages.success(request, "URL actualizada.")
            return redirect("url_list")
        messages.error(request, "No se pudo actualizar la URL.")
    else:
        form = UrlForm(instance=obj)
    return render(request, "control/url_form.html", {"form": form, "titulo": "Editar URL"})


def url_delete(request, url_id):
    obj = get_object_or_404(Url.all_objects, pk=url_id)
    if request.method == "POST":
        obj.delete()
        messages.success(request, "URL eliminada (borrado logico).")
    return redirect("url_list")


# ---------------------
# Metodos HTTP
# ---------------------
def method_list(request):
    methods = HttpMethod.all_objects.order_by("method")
    return render(request, "control/method_list.html", {"methods": methods})


def method_create(request):
    if request.method == "POST":
        form = HttpMethodForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Metodo HTTP creado.")
            return redirect("method_list")
        messages.error(request, "No se pudo crear el metodo HTTP.")
    else:
        form = HttpMethodForm()
    return render(request, "control/method_form.html", {"form": form, "titulo": "Agregar Metodo HTTP"})


def method_edit(request, method_id):
    obj = get_object_or_404(HttpMethod.all_objects, pk=method_id)
    if request.method == "POST":
        form = HttpMethodForm(request.POST, instance=obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Metodo HTTP actualizado.")
            return redirect("method_list")
        messages.error(request, "No se pudo actualizar el metodo HTTP.")
    else:
        form = HttpMethodForm(instance=obj)
    return render(request, "control/method_form.html", {"form": form, "titulo": "Editar Metodo HTTP"})


def method_delete(request, method_id):
    obj = get_object_or_404(HttpMethod.all_objects, pk=method_id)
    if request.method == "POST":
        obj.delete()
        messages.success(request, "Metodo HTTP eliminado (borrado logico).")
    return redirect("method_list")


# ---------------------
# Zonas
# ---------------------
def zone_list(request):
    zones = Zone.all_objects.order_by("zone_name")
    return render(request, "control/zone_list.html", {"zones": zones})


def zone_create(request):
    if request.method == "POST":
        form = ZoneForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Zona creada.")
            return redirect("zone_list")
        messages.error(request, "No se pudo crear la zona.")
    else:
        form = ZoneForm()
    return render(request, "control/zone_form.html", {"form": form, "titulo": "Agregar Zona"})


def zone_edit(request, zone_id):
    obj = get_object_or_404(Zone.all_objects, pk=zone_id)
    if request.method == "POST":
        form = ZoneForm(request.POST, instance=obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Zona actualizada.")
            return redirect("zone_list")
        messages.error(request, "No se pudo actualizar la zona.")
    else:
        form = ZoneForm(instance=obj)
    return render(request, "control/zone_form.html", {"form": form, "titulo": "Editar Zona"})


def zone_delete(request, zone_id):
    obj = get_object_or_404(Zone.all_objects, pk=zone_id)
    if request.method == "POST":
        obj.delete()
        messages.success(request, "Zona eliminada (borrado logico).")
    return redirect("zone_list")


# ---------------------
# Servicios
# ---------------------
def service_list(request):
    services = Service.all_objects.order_by("name", "port")
    return render(request, "control/service_list.html", {"services": services})


def service_create(request):
    if request.method == "POST":
        form = ServiceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Servicio creado.")
            return redirect("service_list")
        messages.error(request, "No se pudo crear el servicio.")
    else:
        form = ServiceForm()
    return render(request, "control/service_form.html", {"form": form, "titulo": "Agregar Servicio"})


def service_edit(request, service_id):
    obj = get_object_or_404(Service.all_objects, pk=service_id)
    if request.method == "POST":
        form = ServiceForm(request.POST, instance=obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Servicio actualizado.")
            return redirect("service_list")
        messages.error(request, "No se pudo actualizar el servicio.")
    else:
        form = ServiceForm(instance=obj)
    return render(request, "control/service_form.html", {"form": form, "titulo": "Editar Servicio"})


def service_delete(request, service_id):
    obj = get_object_or_404(Service.all_objects, pk=service_id)
    if request.method == "POST":
        obj.delete()
        messages.success(request, "Servicio eliminado (borrado logico).")
    return redirect("service_list")
