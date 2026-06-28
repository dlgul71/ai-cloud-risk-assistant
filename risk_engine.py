def calculate_asset_risk(asset):
    score = 0

    if asset.get("public_ip"):
        score += 25

    if asset.get("state") == "running":
        score += 15

    if asset.get("asset_type") == "EC2":
        score += 10

    return score
def calculate_unified_risk(
    base_risk,
    securityhub_count,
    guardduty_count
):
    score = base_risk

    score += securityhub_count * 20
    score += guardduty_count * 30

    return min(score, 100)
