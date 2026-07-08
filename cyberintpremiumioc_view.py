# File: cyberintpremiumioc_view.py
#
# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import json
from datetime import datetime, time, timezone

import phantom.app as phantom
from django.http import HttpResponse
from django.template import loader

from cyberintpremiumioc_connector import CyberintpremiumiocConnector
from cyberintpremiumioc_consts import IOC_FEED_JSONL_ENDPOINT, IOC_FEED_PAGE_SIZE


def _enrichment_view(all_app_runs, context, template, param_key):
    """
    Render the results of an already-run enrichment action.

    Custom views do not run actions; SOAR passes the results of the action that
    has already executed via ``all_app_runs``. Each app run is a
    ``(summary, action_results)`` tuple, and every ``ActionResult`` exposes the
    action parameters (``get_param``) and the data the connector attached
    (``get_data``). We flatten those into ``context["results"]`` for the template.
    """
    context["results"] = results = []
    for _summary, action_results in all_app_runs:
        for result in action_results:
            param = result.get_param()
            data = result.get_data()
            enrichment = data[0] if data else {}
            results.append(
                {
                    "indicator_value": param.get(param_key, ""),
                    "data": enrichment,
                    "data_json": json.dumps(enrichment, indent=2, sort_keys=True) if enrichment else "",
                }
            )
    return template


def enrich_sha256_view(provides, all_app_runs, context):
    return _enrichment_view(all_app_runs, context, "enrich_sha256_view.html", "Hash")


def enrich_ipv4_view(provides, all_app_runs, context):
    return _enrichment_view(all_app_runs, context, "enrich_ipv4_view.html", "IP")


def enrich_url_view(provides, all_app_runs, context):
    return _enrichment_view(all_app_runs, context, "enrich_url_view.html", "URL")


def enrich_domain_view(provides, all_app_runs, context):
    return _enrichment_view(all_app_runs, context, "enrich_domain_view.html", "Domain")


def ioc_view(request, **kwargs):
    """
    Standalone dashboard component that paginates the daily IOC feed on demand.

    Unlike the action-result views above, this is a custom REST/dashboard view
    (wired via default/data/ui) and therefore receives an HTTP request and
    queries the feed API directly.
    """
    connector = CyberintpremiumiocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()

    action_result = connector.add_action_result(phantom.action_result.ActionResult(dict()))

    today = datetime.now(timezone.utc).date()
    today_str = today.strftime("%Y-%m-%d")
    added_after = datetime.combine(today, time.min, tzinfo=timezone.utc).isoformat()
    added_before = datetime.combine(today, time.max, tzinfo=timezone.utc).isoformat()

    offset = 0
    limit = IOC_FEED_PAGE_SIZE
    all_iocs = []

    while True:
        body = {
            "filters": {
                "added_to_feed_after": added_after,
                "added_to_feed_before": added_before,
            },
            "pagination": {"limit": limit, "offset": offset},
            "sort": {"field": "added_to_feed", "direction": "desc"},
        }
        ret_val, iocs = connector._make_rest_call(IOC_FEED_JSONL_ENDPOINT, action_result, json=body, method="post")
        if phantom.is_fail(ret_val) or not iocs:
            break
        all_iocs.extend(iocs)
        if len(iocs) < limit:
            break
        offset += limit

    template = loader.get_template("ioc_view.html")
    context = {
        "iocs": all_iocs,
        "date": today_str,
    }
    return HttpResponse(template.render(context, request))
