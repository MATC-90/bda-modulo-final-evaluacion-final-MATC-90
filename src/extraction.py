# Libraries
# -----------------------------------------------------------------------
import requests
import time
from datetime import datetime, timedelta


# -----------------------------------------------------------------------
# Fetches security data from an API and returns a JSON, retrying on temporary errors
# -----------------------------------------------------------------------
def api_requests(url, params, headers, max_retries=3, wait_seconds=5):

    for attempt in range(1, max_retries + 1):
        try:
            nvd_data = requests.get(url, params=params, headers=headers)

            if nvd_data.status_code == 200:
                print("API connected")
                return nvd_data.json()

            elif nvd_data.status_code in [429, 500, 502, 503, 504]:
                print(f"API failed with {nvd_data.status_code} (temporary). Attempt {attempt}/{max_retries}")
                time.sleep(wait_seconds)
                continue

            else:
                print(f"API failed with {nvd_data.status_code} (not retryable)")
                print(nvd_data.text)
                return None

        except requests.exceptions.ConnectionError as CnxE:
            print(f"Connection error: {CnxE}. Attempt {attempt}/{max_retries}")
            time.sleep(wait_seconds)
            continue

        except requests.exceptions.Timeout as TO:
            print(f"Timeout: {TO}. Attempt {attempt}/{max_retries}")
            time.sleep(wait_seconds)
            continue

        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return None

    print("Stopped: all retries failed")
    return None


# -----------------------------------------------------------------------
# Fetches all CVEs for a given set of params, handling pagination
# -----------------------------------------------------------------------
def get_all_cves(url, params, headers):

    all_cves = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        response = api_requests(url, params, headers)

        if response is None:
            print("Stopped: request failed")
            break

        cves_page = response["vulnerabilities"]
        all_cves.extend(cves_page)

        total_results = response["totalResults"]
        print(f"Downloaded {len(all_cves)} of {total_results}")

        start_index += params["resultsPerPage"]

        if start_index >= total_results:
            break

        time.sleep(1)

    return all_cves


# -----------------------------------------------------------------------
# Generates a list of (start, end) date tuples, each at most window_days long
# -----------------------------------------------------------------------
def generate_date_windows(start_year, end_date=None, window_days=120):

    start = datetime(start_year, 1, 1)
    end = end_date or datetime.now()

    windows = []
    current_start = start

    while current_start < end:
        current_end = min(current_start + timedelta(days=window_days), end)
        windows.append((current_start, current_end))
        current_start = current_end

    return windows


# -----------------------------------------------------------------------
# Downloads all CVEs across multiple date windows and returns a single list
# -----------------------------------------------------------------------
def download_all_cves(url, headers, start_year, results_per_page=1000):

    date_windows = generate_date_windows(start_year)
    all_cves_full = []

    for start, end in date_windows:
        params = {
            "resultsPerPage": results_per_page,
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT00:00:00.000")
        }

        cves_window = get_all_cves(url, params, headers)
        all_cves_full.extend(cves_window)

        print(f"Window {start.date()} - {end.date()}: {len(cves_window)} CVEs. Total so far: {len(all_cves_full)}")

    return all_cves_full


# -----------------------------------------------------------------------
# Extracts and flattens the relevant fields from a single CVE dictionary
# -----------------------------------------------------------------------
def extract_cve_fields(cve_item):

    cve = cve_item["cve"]

    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    vuln_status = cve.get("vulnStatus")

    description = None
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    metrics = cve.get("metrics", {})

    cvss_version = None
    base_score = None
    base_severity = None
    attack_vector = None
    attack_complexity = None
    privileges_required = None
    user_interaction = None
    confidentiality_impact = None
    integrity_impact = None
    availability_impact = None
    exploitability_score = None
    impact_score = None
    vector_string = None

    if "cvssMetricV31" in metrics or "cvssMetricV30" in metrics:
        key = "cvssMetricV31" if "cvssMetricV31" in metrics else "cvssMetricV30"
        metric = metrics[key][0]
        data = metric["cvssData"]

        cvss_version = "3.1" if key == "cvssMetricV31" else "3.0"
        base_score = data.get("baseScore")
        base_severity = data.get("baseSeverity")
        attack_vector = data.get("attackVector")
        attack_complexity = data.get("attackComplexity")
        privileges_required = data.get("privilegesRequired")
        user_interaction = data.get("userInteraction")
        confidentiality_impact = data.get("confidentialityImpact")
        integrity_impact = data.get("integrityImpact")
        availability_impact = data.get("availabilityImpact")
        vector_string = data.get("vectorString")
        exploitability_score = metric.get("exploitabilityScore")
        impact_score = metric.get("impactScore")

    elif "cvssMetricV2" in metrics:
        metric = metrics["cvssMetricV2"][0]
        data = metric["cvssData"]

        cvss_version = "2.0"
        base_score = data.get("baseScore")
        base_severity = metric.get("baseSeverity")
        attack_vector = data.get("accessVector")
        attack_complexity = data.get("accessComplexity")
        confidentiality_impact = data.get("confidentialityImpact")
        integrity_impact = data.get("integrityImpact")
        availability_impact = data.get("availabilityImpact")
        vector_string = data.get("vectorString")
        exploitability_score = metric.get("exploitabilityScore")
        impact_score = metric.get("impactScore")

    cwe = None
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        cwe = weaknesses[0]["description"][0].get("value")

    vendors_products = []
    configurations = cve.get("configurations", [])
    if configurations:
        nodes = configurations[0].get("nodes", [])
        if nodes:
            cpe_matches = nodes[0].get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 5:
                    vendors_products.append((parts[3], parts[4]))

    num_references = len(cve.get("references", []))

    return {
        "cve_id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": cvss_version,
        "base_score": base_score,
        "base_severity": base_severity,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "confidentiality_impact": confidentiality_impact,
        "integrity_impact": integrity_impact,
        "availability_impact": availability_impact,
        "exploitability_score": exploitability_score,
        "impact_score": impact_score,
        "vector_string": vector_string,
        "cwe": cwe,
        "vendors_products": vendors_products,
        "num_references": num_references
    }