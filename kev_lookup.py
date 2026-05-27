import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev():
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        kev_items = data.get("vulnerabilities", [])

        kev_map = {}

        for item in kev_items:
            cve_id = item.get("cveID")

            if cve_id:
                kev_map[cve_id] = {
                    "cve_id": cve_id,
                    "vendor": item.get("vendorProject"),
                    "product": item.get("product"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware": item.get("knownRansomwareCampaignUse"),
                    "required_action": item.get("requiredAction"),
                    "notes": item.get("notes"),
                    "kev_exploited": True,
                }

        return kev_map

    except Exception as e:
        print(f"[KEV ERROR] Failed to fetch CISA KEV catalog: {e}")
        return {}


def check_cve_in_kev(cve_id):
    kev_map = fetch_cisa_kev()
    return kev_map.get(cve_id)
