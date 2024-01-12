"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .constants import *
from pycti import OpenCTIApiClient, Identity

logger = get_logger("opencti")


class OpenCTI:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url").strip('/')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        self.url = server_url
        self.access_token = config.get("access_token")
        self.verify_ssl = config.get("verify_ssl")
        self.open_cti = OpenCTIApiClient(self.url, self.access_token, ssl_verify=self.verify_ssl)

    def build_params(self, params):
        new_params = {}
        for key, value in params.items():
            if value is False or value == 0 or value:
                new_params[key] = value
        return new_params


def create_organization(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    reliability = params.get("reliability")
    if reliability:
        reliability = RELIABILITY.get(reliability.lower())
    identity = Identity(ob.open_cti)
    result = identity.create(
        name=params.get("name"),
        type="Organization",
        description=params.get("description"),
        x_opencti_reliability=reliability
    )
    return result


def get_organizations(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    identity = Identity(ob.open_cti)
    result = identity.list(
        types="Organization",
        first=params.get("limit", 50),
        after=params.get("end_cursor_id"),
        withPagination=True
    )
    return result


def create_label(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.label.create(
        value=str(params.get("name"))
    )
    return result


def get_labels(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.label.list(
        first=params.get("limit", 50),
        after=params.get("end_cursor_id"),
        withPagination=True
    )
    return result


def create_external_reference(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.external_reference.create(
        url=params.get("url"),
        source_name=params.get("name")
    )
    return result


def get_external_references(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.external_reference.list(
        first=params.get("limit", 50),
        after=params.get("end_cursor_id"),
        withPagination=True
    )
    return result


def get_marking_definition(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.marking_definition.list(
        first=params.get("limit", 50),
        after=params.get("end_cursor_id"),
        withPagination=True
    )
    return result


def create_indicator(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    indicator_type = params.get("type")
    value = params.get("value")
    data = {"type": INDICATOR_TYPES.get(indicator_type.lower()), "value": value}
    if indicator_type == 'Registry Key':
        data["key"] = value
    if indicator_type == 'Account':
        data["account_login"] = value
    simple_observable_key = None
    simple_observable_value = None
    if "file" in indicator_type.lower():
        simple_observable_key = FILE_TYPES.get(indicator_type.lower())
        simple_observable_value = value

    result = ob.open_cti.stix_cyber_observable.create(
        simple_observable_key=simple_observable_key,
        simple_observable_value=simple_observable_value,
        type=indicator_type,
        createdBy=params.get("created_by"),
        objectMarking=params.get("marking_id"),
        objectLabel=params.get("label_id"),
        externalReferences=params.get("external_reference_id"),
        simple_observable_description=params.get("description"),
        x_opencti_score=params.get("score", 50),
        observableData=data
    )
    return result


def get_indicators(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)

    filters = []
    min_score = str(params.get("min_score", ""))
    max_score = str(params.get("max_score", ""))
    indicator_types = [INDICATOR_TYPES.get(ind_type.lower()) for ind_type in params.get("type", [])]
    if min_score:
        filters.append({"key": "x_opencti_score", "values": [min_score], "operator": "gte", "mode": "or"})
    if max_score:
        filters.append({"key": "x_opencti_score", "values": [max_score], "operator": "lte", "mode": "or"})
    if indicator_types:
        filters.append({"key": "entity_type", "values": indicator_types, "operator": "eq", "mode": "or"})
    filters = {"mode": "and", "filterGroups": [], "filters": filters} if filters else None

    result = ob.open_cti.stix_cyber_observable.list(
        after=params.get("end_cursor_id"),
        first=params.get("limit", 50),
        filters=filters,
        withPagination=True
    )
    return result


def delete_indicator(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    result = ob.open_cti.stix_cyber_observable.delete(id=params.get("indicator_id"))
    return {"message": "success"}


def add_indicator_field(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    field = params.get("field")
    result = None
    if field == "Marking Definition":
        result = ob.open_cti.stix_cyber_observable.add_marking_definition(
            id=params.get("indicator_id"),
            marking_definition_id=params.get("field_id")
        )
    elif field == "Label":
        result = ob.open_cti.stix_cyber_observable.add_label(
            id=params.get("indicator_id"),
            label_id=params.get("field_id")
        )
    if result:  # result is returned as True or False
        return {"message": "success"}
    else:
        return {"message": "unsuccessful"}


def update_indicator_field(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    field = UPDATE_FIELDS.get(params.get("field").lower())
    result = ob.open_cti.stix_cyber_observable.update_field(
        id=params.get("indicator_id"),
        input={"key": field, "value": params.get("field_value")}
    )
    return result


def remove_indicator_field(config, params):
    ob = OpenCTI(config)
    params = ob.build_params(params)
    field = params.get("field")
    result = {}
    if field == "Marking Definition":
        result = ob.open_cti.stix_cyber_observable.remove_marking_definition(
            id=params.get("indicator_id"),
            marking_definition_id=params.get("field_id")
        )
    elif field == "Label":
        result = ob.open_cti.stix_cyber_observable.remove_label(
            id=params.get("indicator_id"),
            label_id=params.get("field_id")
        )
    logger.error(f"\n-----------------------------\nresult: {result}")
    if result:  # result is returned as True or False
        return {"message": "success"}
    else:
        return {"message": "unsuccessful"}


def check_health_ex(config):
    get_labels(config, {"limit": 1})
    return True


operations = {
    "create_organization": create_organization,
    "get_organizations": get_organizations,
    "create_label": create_label,
    "get_labels": get_labels,
    "create_external_reference": create_external_reference,
    "get_external_references": get_external_references,
    "get_marking_definition": get_marking_definition,
    "create_indicator": create_indicator,
    "get_indicators": get_indicators,
    "delete_indicator": delete_indicator,
    "add_indicator_field": add_indicator_field,
    "update_indicator_field": update_indicator_field,
    "remove_indicator_field": remove_indicator_field
}
