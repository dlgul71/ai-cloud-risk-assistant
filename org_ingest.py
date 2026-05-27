import boto3


def get_organization_accounts():

    accounts = []

    try:

        org = boto3.client("organizations")

        response = org.list_accounts()

        for acct in response.get("Accounts", []):

            accounts.append({
                "Account ID": acct.get("Id"),
                "Account Name": acct.get("Name"),
                "Email": acct.get("Email"),
                "Status": acct.get("Status"),
            })

        return accounts

    except Exception as e:

        print(f"Organizations ingest error: {e}")

        return []
