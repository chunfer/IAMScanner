from fnmatch import fnmatch
from datetime import datetime
from boto3 import client
from botocore.exceptions import ClientError
from os import getenv
from uuid import uuid4
from json import loads
from threading import Thread
from hashlib import sha256
from base64 import b64encode
from urllib3 import PoolManager


DEFAULT_CONTEXT = getenv("DEFAULT_CONTEXT", "development")
MGMT_CONTEXT = getenv("MGMT_CONTEXT", "management")
SCORES_DB = getenv("SCORES_DB", "scores.json")
ACTIONS_DB = getenv("ACTIONS_DB", "actions.json")
MEMBER_ROLE = getenv("MEMBER_ROLE", "IAMScannerMemberRole")
ROLE_SESSION_NAME = getenv("ROLE_SESSION_NAME", "IAMScannerSession")
SPLUNK_SECRET_NAME = getenv("SPLUNK_SECRET_NAME", "SplunkSecret")
SOURCE_NAME = getenv("SOURCE_NAME", "IAM Scanner")
DEBUG = getenv("DEBUG", "false") == "true"
http = PoolManager(timeout=5.0)

# Open json documents
with open(SCORES_DB) as scores_file:
    scores_db = loads(scores_file.read())

with open(ACTIONS_DB) as actions_file:
    actions_db = loads(actions_file.read())


# Initialize the Organizations and STS clients
org_client = client("organizations")
sts_client = client('sts')


def format_element(element):
    """Turn single string elements from AWS Policy into a list"""
    if isinstance(element, str):
        return [element]
    return element

def get_action_score(action, not_action = False):
    """Retrieve the score for every action"""
    #Check for access to all or none actions
    if action == "*":
        if not_action:
            return 0
        return 1
    # Intialize scores
    type_score = 0
    exception_score = 0

    # Extract the service and the action
    service_name, action_name = action.split(":")
    
    # Determine if the service is privileged
    service_type = "privileged" if service_name in scores_db["actions"]["privilegedServices"] else "nonPrivileged"

    # Obtain the score for the type of action found in the database
    actions_db_categories = actions_db.get(service_name)
    if actions_db_categories:
        for action_category, actions_in_db in actions_db_categories.items():
            action_matched = False
            for action_in_db in actions_in_db:
                # Match Action
                if fnmatch(action_in_db, action_name):
                    type_score = scores_db["actions"][service_type][action_category]
                    action_matched = True
                    break

                # Match NotAction
                elif not_action:
                    type_score = scores_db["actions"][service_type][action_category]
                    action_matched = True
                    break
            
            # Since the scores are sorted by category therefore is not needed to check other categories
            if action_matched: break
    
    # Obtain the score to see if it matched the exceptions
    actions_in_exceptions = scores_db["actions"]["exceptions"].get(service_name)
    if actions_in_exceptions:
        for action_in_exception, action_in_exception_score in actions_in_exceptions.items():
            # Match Action
            if fnmatch(action_in_exception, action_name):
                exception_score = action_in_exception_score
                break # Can break since the scores are sorted
            
            # Match NotAction
            elif not_action:
                exception_score = action_in_exception_score
                break

    # Return the highest value
    if type_score > exception_score:
        return type_score

    return exception_score


def get_policy_score(document, context_score = 0): 
    """Assign the score to the IAM policy"""
    policy_score = 0
    statements = document["Statement"]

    for statement in statements:
        # Extract elements from the statement
        sid = statement.get("Sid")
        effect = statement.get("Effect")
        actions = format_element(statement.get("Action"))
        not_actions = format_element(statement.get("NotAction"))
        resources = format_element(statement.get("Resource"))
        not_resources = format_element(statement.get("NotResource"))
        conditions = "yes" if statement.get("Condition") else "no"
        
        actions_score = 0
        scopes_score = 0

        # Analyze only Allow effect
        if effect == "Allow":
            # Analyze actions 
            if actions:
                for action in actions:
                    action_score = get_action_score(action)
                    if action_score > actions_score:
                        actions_score = action_score

                    # The maximum score for actions can only be 1
                    if actions_score == 1: break
            
            # Analyze not actions
            elif not_actions:
                for not_action in not_actions:
                    not_action_score = get_action_score(not_action, True)
                    if not_action_score > actions_score:
                        actions_score = not_action_score
                    
                    # The maximum score for actions can only be 1
                    if actions_score == 1: break


            # Check Resources and conditions
            # Match element named "Resource"
            if resources:
                for resource in resources:
                    scope_score = 0

                    # Match all the resources
                    if resource == "*": 
                        scope_score = scores_db["scope"][f"all:{conditions}"]
                    # Match some resource
                    elif "*" in resource:
                        scope_score = scores_db["scope"][f"some:{conditions}"]
                    
                    # Match few resource
                    else:
                        scope_score = scores_db["scope"][f"few:{conditions}"]                       

                    # Look for the highest scope score
                    if scope_score > scopes_score: scopes_score = scope_score
                    
                    # The highest scope score can only be 1
                    if scopes_score == 1: break

            # Match element named "NotResource"
            elif not_resources:
                for not_resource in not_resources:
                    scope_score = 0

                    # Match none of the resources
                    if not_resource == "*":
                        scope_score = scores_db["scope"]["none"] 

                    # Match some resources
                    else:
                        scope_score = scores_db["scope"][f"some:{conditions}"]

                    # Look for the lowest scope since its NotResource element
                    if scope_score < scopes_score: scopes_score = scope_score

                    # The lowest scope score can only be 0
                    if scopes_score == 0: break

            statement_score = context_score * scopes_score * actions_score
            statement["RiskScore"] = statement_score

            if statement_score > policy_score:
                policy_score = statement_score
        

        elif DEBUG:
            msg = f"{effect} effect unsupported. Skipping statement"
            if sid: msg = f"{msg} with Sid {sid}"
            print(msg)
        
    return policy_score


def generate_alerts(iam_client, account_data, splunk_data):
    """Get Access Keys for all the users in the account"""
    users_info = iam_client.list_users()
    total_access_keys = 0

    # Remove response metadata
    del users_info["ResponseMetadata"]
    
    for user in users_info["Users"]:
        # Set date to timestamp
        user["CreateDate"] = int(user["CreateDate"].timestamp())

        # Get policies and its permissions
        attached_policies = iam_client.list_attached_user_policies(
            UserName = user["UserName"]
        )
        user_score = 0
        context_score = scores_db["contexts"][account_data["Context"]]

        for attached_policy in attached_policies["AttachedPolicies"]:
            policy_data = iam_client.get_policy(
                PolicyArn = attached_policy["PolicyArn"]
            )

            policy_version = iam_client.get_policy_version(
                PolicyArn = attached_policy["PolicyArn"], 
                VersionId = policy_data["Policy"]["DefaultVersionId"]
            )

            attached_policy["Document"] = policy_version["PolicyVersion"]["Document"]
            attached_policy["RiskScore"] = get_policy_score(attached_policy["Document"], context_score)
            if attached_policy["RiskScore"] > user_score:
                user_score = attached_policy["RiskScore"]

        # Get Access Keys and create a final json
        access_keys = iam_client.list_access_keys(
            UserName = user["UserName"]
        )

        for access_key in access_keys["AccessKeyMetadata"]:
            del access_key["UserName"]
            event_id = str(uuid4())
            alert = {
                "EventId": event_id,
                "AccessKeyDigest": b64encode(sha256(access_key["AccessKeyId"].encode()).hexdigest().encode()).decode(),
            }
            alert.update(access_key)
            alert["AccessKeyId"] = f'{access_key["AccessKeyId"][:4]}****{access_key["AccessKeyId"][-4:]}' # Turn the access key into a snippet to hide sensitive data
            alert["CreateDate"] = int(access_key["CreateDate"].timestamp())
            alert.update(account_data)
            alert["User"] = user
            alert["RiskScore"] = user_score
            alert["Policies"] = attached_policies["AttachedPolicies"]

            if splunk_data:
                body = {
                    "event": alert,
                    "sourcetype": "_json",
                    "time": int(datetime.now().timestamp()),
                    "index": splunk_data["index"],
                    "source": SOURCE_NAME
                }

                headers = {
                    "Authorization": f"Splunk {splunk_data['token']}",
                    "X-Splunk-Request-Channel": splunk_data["channel"],
                    "Content-Type": "application/json"  
                }
                
                http.request(method="POST", url=splunk_data["url"], json=body, headers=headers)

            total_access_keys += 1
    
    print(f"Total AWS Access Keys found in account {account_data['AccountName']}: {total_access_keys}")


def get_ou_name(org_client, ou_id):
    """Retrieves the name of an Organizational Unit."""
    response = org_client.describe_organizational_unit(OrganizationalUnitId=ou_id)
    return response["OrganizationalUnit"]["Name"]


def get_org_structure(accounts_data: list, parent_id: str, management_account: str, context = DEFAULT_CONTEXT, org_path = "/"):
    """Recursively retrieves and prints the AWS Organization structure."""
    
    # List OUs under the current parent
    ous = org_client.list_children(ParentId=parent_id, ChildType="ORGANIZATIONAL_UNIT")["Children"]
    for ou in ous:
        ou_name = get_ou_name(org_client, ou["Id"])
        if ou_name.lower() in scores_db["contexts"]: context = ou_name
        get_org_structure(accounts_data, ou["Id"], management_account, context, f"{org_path}{ou_name}/")

    # List accounts under the current parent
    accounts = org_client.list_children(ParentId=parent_id, ChildType="ACCOUNT")["Children"]
    for account in accounts:
        if account["Id"] == management_account:
            context = MGMT_CONTEXT

        account_details = org_client.describe_account(AccountId=account["Id"])["Account"]
        account_name = account_details["Name"]
        accounts_data.append({
            "AccountName": account_name,
            "AccountId": account["Id"],
            "OrganizationPath": org_path,
            "Context": context
        })


def get_splunk_data():
    """
    The AWS Secret must have the following structure:
    {
        "url": "URL to send the data to",
        "index": "Splunk index that should receive the data"
        "token": "HTTP collector token",
        "channel": "Splunk channel used to send the data"
    }
    """
    if SPLUNK_SECRET_NAME:
        secrets_client = client("secretsmanager")
        return loads(secrets_client.get_secret_value(SecretId=SPLUNK_SECRET_NAME)['SecretString'])
    return None


def handler(event = "", ctx = ""):
    accounts_data = []
    threads = []
    splunk_data = get_splunk_data()

    # Get the root ID of your organization
    roots = org_client.list_roots()["Roots"]

    if not roots:
        print("No AWS Organization root found.")
    else:
        root_id = roots[0]["Id"]

        # Retrieve the Management Account
        organization_details = org_client.describe_organization()["Organization"]
        management_account = organization_details["MasterAccountId"]

        # Obtain existing org structure
        get_org_structure(accounts_data, root_id, management_account)

        # Assume the member roles in the member accounts and generate alerts
        for account_data in accounts_data:
            try:
                assume_role_arn = f"arn:aws:iam::{account_data['AccountId']}:role/{MEMBER_ROLE}"
                assumed_role_object = sts_client.assume_role(
                    RoleArn=assume_role_arn,
                    RoleSessionName=ROLE_SESSION_NAME
                )

                # Extract the temporary credentials
                credentials = assumed_role_object['Credentials']

                # Create an IAM client using the temporary credentials
                iam_client = client(
                    'iam',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )

                # Start a thread to generate the alerts
                account_thread = Thread(target=generate_alerts, args=(iam_client, account_data, splunk_data))
                account_thread.start()

                threads.append(account_thread)
            except ClientError as e:
                print(e)

        for account_thread in threads:
            account_thread.join()
        


if __name__ == "__main__":
    handler()