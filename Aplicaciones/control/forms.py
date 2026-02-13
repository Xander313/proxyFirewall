from django import forms

from .models import HttpMethod, Policy, Rule, Service, Url, UrlCategory, Zone


class BaseStyledForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            else:
                field.widget.attrs.setdefault("class", "form-control")


class PolicyForm(BaseStyledForm):
    class Meta:
        model = Policy
        fields = ["name", "type", "enabled"]
        labels = {
            "name": "Nombre",
            "type": "Tipo",
            "enabled": "Activa",
        }


class UrlCategoryForm(BaseStyledForm):
    class Meta:
        model = UrlCategory
        fields = ["name", "description"]
        labels = {
            "name": "Nombre",
            "description": "Descripcion",
        }


class UrlForm(BaseStyledForm):
    class Meta:
        model = Url
        fields = ["scheme", "host", "port", "path", "query", "category"]
        labels = {
            "scheme": "Esquema",
            "host": "Dominio",
            "port": "Puerto",
            "path": "Ruta",
            "query": "Consulta",
            "category": "Categoria",
        }


class HttpMethodForm(BaseStyledForm):
    class Meta:
        model = HttpMethod
        fields = ["method"]
        labels = {
            "method": "Metodo HTTP",
        }


class ZoneForm(BaseStyledForm):
    class Meta:
        model = Zone
        fields = ["zone_name", "description"]
        labels = {
            "zone_name": "Nombre de zona",
            "description": "Descripcion",
        }


class ServiceForm(BaseStyledForm):
    class Meta:
        model = Service
        fields = ["name", "protocol", "port"]
        labels = {
            "name": "Nombre",
            "protocol": "Protocolo",
            "port": "Puerto",
        }


class RuleForm(BaseStyledForm):
    class Meta:
        model = Rule
        fields = [
            "policy",
            "url_category",
            "note",
            "schedule_days",
            "schedule_start",
            "schedule_end",
            "schedule_tz",
            "action",
            "priority",
            "enabled",
        ]
        labels = {
            "policy": "Politica",
            "url_category": "Categoria URL",
            "note": "Nota",
            "schedule_days": "Dias (MON,TUE,...)",
            "schedule_start": "Hora inicio",
            "schedule_end": "Hora fin",
            "schedule_tz": "Zona horaria",
            "action": "Accion",
            "priority": "Prioridad",
            "enabled": "Activa",
        }
