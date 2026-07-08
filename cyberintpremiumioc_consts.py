# File: cyberintpremiumioc_consts.py
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

# API Endpoints
IOC_ENRICHMENT_ENDPOINT = "/ioc-intel/enrichment-api/v1/enrichment"
IOC_FEED_JSONL_ENDPOINT = "/ioc-intel/feed-api/v1/feed/jsonl"

# Default page size for feed pagination (max 100000 per the API spec)
IOC_FEED_PAGE_SIZE = 10000

# Indicator type constants used by the enrichment endpoint
IOC_TYPE_SHA256 = "sha256"
IOC_TYPE_IPV4 = "ipv4"
IOC_TYPE_URL = "url"
IOC_TYPE_DOMAIN = "domain"

# On-poll feed ingestion
# State-file key holding the ISO-8601 timestamp of the last successful ingestion,
# used as the "added_to_feed_after" cursor on the next scheduled poll.
FEED_STATE_CURSOR_KEY = "last_ingested_time"
# How far back to look on the very first scheduled poll (no checkpoint yet).
FEED_FIRST_FETCH_DAYS = 3
# Lookback window for a manual "poll now" run (does not advance the checkpoint).
POLL_NOW_LOOKBACK_DAYS = 1
