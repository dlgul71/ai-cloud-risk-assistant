from asset_db import get_assets


def get_top_risky_assets(limit=10):
    assets = get_assets()

    sorted_assets = sorted(
        assets,
        key=lambda x: x[6],  # risk_score column
        reverse=True
    )

    return sorted_assets[:limit]


if __name__ == "__main__":
    risky_assets = get_top_risky_assets()

    print("\nTOP RISKY ASSETS")
    print("-" * 60)

    for asset in risky_assets:
        print(asset)
