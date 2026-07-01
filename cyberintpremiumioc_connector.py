# File: cyberintpremiumioc_connector.py
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
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from cyberintpremiumioc_consts import (
    IOC_ENRICHMENT_ENDPOINT,
    IOC_FEED_JSONL_ENDPOINT,
    IOC_FEED_PAGE_SIZE,
    IOC_TYPE_DOMAIN,
    IOC_TYPE_IPV4,
    IOC_TYPE_SHA256,
    IOC_TYPE_URL,
)


class CyberintpremiumiocConnector(BaseConnector):
    """
    Check Point EM ThreatCloud Intelligence Feed connector.
    """

    def __init__(self):
        super().__init__()
        self._state = None
        self._base_url = None
        self._access_token = None
        self._customer_name = None
        self._verify = False

    def _get_custom_headers(self):
        app_json = self.get_app_json()
        config = self.get_config()
        return {
            "X-Integration-Type": "Splunk SOAR",
            "X-Integration-Instance-Name": config.get("asset_name"),
            "X-Integration-Instance-Id": str(self.get_asset_id()),
            "X-Integration-Customer-Name": self._customer_name,
            "X-Integration-Version": app_json.get("app_version"),
        }

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """
        Helper function to make REST calls for the connector. Authenticates via the
        `access_token` cookie as required by the Check Point EM ThreatCloud APIs.
        """
        try:
            url = f"{self._base_url}{endpoint}"
            self.debug_print(f"Making REST call to: {url}")

            try:
                request_func = getattr(requests, method.lower())
            except AttributeError:
                return action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), None

            all_headers = self._get_custom_headers()
            if headers:
                all_headers.update(headers)

            cookies = {"access_token": self._access_token}

            response = request_func(
                url,
                json=json,
                data=data,
                headers=all_headers,
                params=params,
                cookies=cookies,
                verify=self._verify,
            )

            if hasattr(action_result, "add_debug_data"):
                action_result.add_debug_data({"r_status_code": response.status_code})
                action_result.add_debug_data({"r_text": response.text})
                action_result.add_debug_data({"r_headers": response.headers})

            if 200 <= response.status_code < 300:
                content_type = response.headers.get("Content-Type", "")
                if "jsonl" in content_type or endpoint.endswith("/jsonl"):
                    return phantom.APP_SUCCESS, self._parse_jsonl(response.text)
                if not response.text:
                    return phantom.APP_SUCCESS, {}
                try:
                    return phantom.APP_SUCCESS, response.json()
                except ValueError:
                    return phantom.APP_SUCCESS, response.text

            error_message = f"Error from server. Status Code: {response.status_code}"
            if response.text:
                try:
                    resp_json = response.json()
                    detail = resp_json.get("detail") or resp_json.get("error") or resp_json
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {detail}"
                except ValueError:
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {response.text}"

            return action_result.set_status(phantom.APP_ERROR, error_message), None

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error making REST call: {e!s}"), None

    @staticmethod
    def _parse_jsonl(text):
        """Parse a JSON Lines payload into a list of dicts. Skips blank lines."""
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
        return items

    def _enrich_indicator(self, action_result, indicator_type, indicator_value):
        """Call the premium enrichment endpoint for a single IOC."""
        body = {"type": indicator_type, "value": indicator_value}
        return self._make_rest_call(IOC_ENRICHMENT_ENDPOINT, action_result, json=body, method="post")

    def _handle_test_connectivity(self, param):
        """
        Validate the asset configuration for connectivity using supplied credentials.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to instance...")

        ret_val, _ = self._enrich_indicator(action_result, IOC_TYPE_DOMAIN, "cyberint.com")
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_sha256(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._enrich_indicator(action_result, IOC_TYPE_SHA256, param["Hash"])
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_ipv4(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._enrich_indicator(action_result, IOC_TYPE_IPV4, param["IP"])
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._enrich_indicator(action_result, IOC_TYPE_URL, param["URL"])
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enrich_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._enrich_indicator(action_result, IOC_TYPE_DOMAIN, param["Domain"])
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        today = datetime.now(timezone.utc).date()
        today_str = today.strftime("%Y-%m-%d")

        container = {
            "name": f"Check Point EM ThreatCloud Daily IOC Feed - {today_str}",
            "source_data_identifier": f"cyberint_premium_ioc_feed_{today_str}",
        }
        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            self.debug_print(f"Could not create container (likely already exists): {message}")

        if not container_id:
            sdi = f"cyberint_premium_ioc_feed_{today_str}"
            url = f"{self.get_phantom_base_url()}/rest/container?_filter_source_data_identifier='{sdi}'"
            try:
                r = self._get_requests_session().get(url, verify=False)
                r.raise_for_status()
                data = r.json()
                if data.get("count", 0) > 0:
                    container_id = data["data"][0]["id"]
                else:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "Failed to create or find container for IOC feed",
                    )
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Failed to create or find container for IOC feed: {e}",
                )

        added_after = datetime.combine(today, time.min, tzinfo=timezone.utc).isoformat()
        added_before = datetime.combine(today, time.max, tzinfo=timezone.utc).isoformat()

        offset = 0
        limit = IOC_FEED_PAGE_SIZE
        total_iocs = 0
        while True:
            self.save_progress(f"Fetching IOCs, offset: {offset}")
            body = {
                "filters": {
                    "added_to_feed_after": added_after,
                    "added_to_feed_before": added_before,
                },
                "pagination": {"limit": limit, "offset": offset},
                "sort": {"field": "added_to_feed", "direction": "desc"},
            }
            ret_val, iocs = self._make_rest_call(IOC_FEED_JSONL_ENDPOINT, action_result, json=body, method="post")
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not iocs:
                break

            for ioc in iocs:
                indicator_type = ioc.get("indicator_type")
                indicator_value = ioc.get("indicator_value")
                activity = ioc.get("activity", "")
                artifact = {
                    "name": indicator_value,
                    "cef": {indicator_type: indicator_value},
                    "container_id": container_id,
                    "source_data_identifier": f"{indicator_value}|{activity}",
                }
                self.save_artifact(artifact)

            total_iocs += len(iocs)
            if len(iocs) < limit:
                break
            offset += limit

        action_result.update_summary({"iocs_ingested": total_iocs})
        return action_result.set_status(phantom.APP_SUCCESS)

    def initialize(self):
        """
        Initialize the connector.
        """
        self.debug_print("Initializing connector")
        self._state = self.load_state()
        config = self.get_config()

        self._base_url = config.get("base_url")
        self._access_token = config.get("access_token")
        self._customer_name = config.get("customer_name")
        self._verify = config.get("verify_server_cert", False)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """
        Dispatcher for actions.
        """
        if hasattr(self, "_get_requests_session"):
            self._requests_session = self._get_requests_session()

        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "enrich_sha256": self._handle_enrich_sha256,
            "enrich_ipv4": self._handle_enrich_ipv4,
            "enrich_url": self._handle_enrich_url,
            "enrich_domain": self._handle_enrich_domain,
            "on_poll": self._handle_on_poll,
        }

        ret_val = phantom.APP_SUCCESS
        if action_id in action_mapping:
            ret_val = action_mapping[action_id](param)
        return ret_val


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("input_test_json", help="Input Test JSON file")
    args = parser.parse_args()

    with open(args.input_test_json) as f:
        in_json = json.load(f)

    connector = CyberintpremiumiocConnector()
    connector.print_progress_message = True

    connector._base_url = in_json["config"].get("base_url")
    connector._access_token = in_json["config"].get("access_token")
    connector._customer_name = in_json["config"].get("customer_name")

    connector._action_identifier = in_json.get("action")

    ret_val = connector.handle_action(in_json.get("parameters", [{}])[0])
    print(ret_val)

    sys.exit(0)
