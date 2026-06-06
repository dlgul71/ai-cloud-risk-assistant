def calculate_asset_risk(asset):
    score = 0

    if asset.get("public_ip"):
        score += 25

    if asset.get("state") == "running":
        score += 15

    if asset.get("asset_type") == "EC2":
        score += 10

    return score
