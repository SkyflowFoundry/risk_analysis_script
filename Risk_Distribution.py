import json
import requests
import re
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter
from tabulate import tabulate

# Define constants

# Change the below constants according to your account
SKYFLOW_VAULT_ENDPOINT = 'https://manage.skyflowapis.com/v1/vaults'
SKYFLOW_SA_ENDPOINT = 'https://manage.skyflowapis.com/v1/serviceAccounts'
SKYFLOW_LISTROLES_ENDPOINT = 'https://manage.skyflowapis.com/v1/roles'
VAULT_OWNER_SA_CREDENTIALS = 'Bearer <bearer_token>'
SKYFLOW_ACCOUNT_ID = '<account-id>'  # Replace Account ID with your Account ID
SKYFLOW_VAULT_ID = '<vault-id>'  # Replace Vault ID with your Vault ID

# Set headers for connection creation request
connection_creation_headers = {
    'X-SKYFLOW-ACCOUNT-ID': SKYFLOW_ACCOUNT_ID,
    'Content-Type': 'application/json',
    'Authorization': VAULT_OWNER_SA_CREDENTIALS
}

GET_RESOURCE_ENDPOINT = SKYFLOW_LISTROLES_ENDPOINT + "?resource.ID=" + SKYFLOW_VAULT_ID + "&resource.type=VAULT"

#print(GET_RESOURCE_ENDPOINT)

# Send request to create connection
response = requests.request("GET", GET_RESOURCE_ENDPOINT,
                            headers=connection_creation_headers,
                            data='')
# Print response
#print(response.text)

# Extract JSON Object
response_json = response.json()
#print(response_json)

# Extract IDs from JSON
ids = [role["ID"] for role in response_json["roles"]]
#print(ids)

# Define the regular expression pattern to match "ON <text>.*"
mediumrisk_pattern = re.compile(r'^[^*]+\.\*$')

# Define the regular expression pattern to match "ON <text>.<text>"
lowrisk_pattern = re.compile(r"ON\s+\S+\.\S+")

# Dictionary for maintaining members to risk
members_risk = {}

for id in ids:
    #print(id)
    GET_MEMBERS_FROM_ROLE_ENDPOINT = SKYFLOW_LISTROLES_ENDPOINT + "/" + id + "/members"
    response_member = requests.request("GET", GET_MEMBERS_FROM_ROLE_ENDPOINT,
                            headers=connection_creation_headers,
                            data='')
    member_response = response_member.json()
    #print(member_response)
    if len(member_response["members"]) != 0:
        GET_POLICY_FROM_ROLE_ENDPOINT = SKYFLOW_LISTROLES_ENDPOINT + "/" + id + "/policies"
        response = requests.request("GET", GET_POLICY_FROM_ROLE_ENDPOINT,
                                headers=connection_creation_headers,
                                data='')
        #print(response.text)
        role_response = response.json()
        #print(role_response)
        for policy in role_response["policies"]:
            # Check if status is "ACTIVE" and print each ruleExpression
            if policy["status"] == "ACTIVE":
                for rule in policy["rules"]:
                    #print(rule["ruleExpression"])
                    if "ON *.*" in rule["ruleExpression"] or "ON *" in rule["ruleExpression"]:
                        risk = "High Risk"
                    elif mediumrisk_pattern.search(rule["ruleExpression"]):
                        risk = "Medium Risk"
                    elif lowrisk_pattern.search(rule["ruleExpression"]):
                        risk = "Low Risk"

                    for member in member_response["members"]:
                        member_id = member["ID"]
                        members_risk[member_id] = risk
                        #print("Member ID:", member_id)
                        #print("------------------------------------")

#print(members_risk)

# Count the occurrences of each risk level
risk_counts = Counter(members_risk.values())

# Create labels and values for the pie chart
labels1 = list(risk_counts.keys())
values1 = list(risk_counts.values())

GET_CURRENT_SCHEMA_ENDPOINT = SKYFLOW_VAULT_ENDPOINT + "/" + SKYFLOW_VAULT_ID + "/versions/CURRENT"

#print(GET_CURRENT_SCHEMA_ENDPOINT)

# Send request to create connection
response = requests.request("GET", GET_CURRENT_SCHEMA_ENDPOINT,
                            headers=connection_creation_headers,
                            data='')
# Extract Vault ID
VAULT_SCHEMA = response.json().get('schemas')

# Print response
# print(response.text)
#print(VAULT_SCHEMA)

# Value to search for in the "skyflow.options.personal_information_type" tag
search_value = "PII"

fields_risk = {}

# Iterate through the data and find the field containing the search value
field_name = None
for item in VAULT_SCHEMA:
    for field in item["fields"]:
        field_name = field["name"]
        table_name = item["name"]
        for tag in field["tags"]:
            if tag["name"] == "skyflow.options.personal_information_type" and search_value in tag["values"]:
                #print(f"The field containing the value '{search_value}' is: {field_name} and table name is: {table_name}")
                fields_risk[field_name] = "Low Risk"
        if field["name"] and field["name"] != "skyflow_id":
            #print(f"The field not containing the value '{search_value}' is: {field_name} and table name is: {table_name}")
            if field_name not in fields_risk:
                fields_risk[field_name] = "High Risk"

#print(fields_risk)

# Count the occurrences of each risk level
risk_counts = Counter(fields_risk.values())

# Create labels and values for the pie chart
labels2 = list(risk_counts.keys())
values2 = list(risk_counts.values())

print("--------------------------------------------------")
#Printing risk distibution fields, risk
table = [[member_id, risk_category] for member_id, risk_category in fields_risk.items()]

# Print tabular format with headers
print(tabulate(table, headers=['Fields', 'Risk Category']))
print("--------------------------------------------------")

# Dictionary mapping labels to colors
color_map = {
    'High Risk': 'red',
    'Medium Risk': 'yellow',
    'Low Risk': 'green'
}

# Create subplots with 1 row and 2 columns
fig = make_subplots(rows=1, cols=2, specs=[[{'type':'domain'}, {'type':'domain'}]], subplot_titles=['Access Review', 'Fields'])

# Add first pie chart to the first column
fig.add_trace(go.Pie(labels=labels1, values=values1, marker=dict(colors=[color_map[labels] for labels in labels1]), name="Risk distribution based on access review"), 1, 1)

# Add second pie chart to the second column
fig.add_trace(go.Pie(labels=labels2, values=values2, marker=dict(colors=[color_map[labels] for labels in labels1]), name="Risk distribution based on fields"), 1, 2)

# Update layout
fig.update_layout(title_text='Risk Distribution')

print("--------------------------------------------------")
#Printing risk distibution members, risk
table = [[member_id, risk_category] for member_id, risk_category in members_risk.items()]

# Print tabular format with headers
print(tabulate(table, headers=['Members ID', 'Risk Category']))
print("--------------------------------------------------")

# Show the plot
fig.show()
