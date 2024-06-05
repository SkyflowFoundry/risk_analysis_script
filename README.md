Risk Distribution for Skyflow Vault

This Python app that generates risk distribution based on 'Access Review' along with 'Fields/columns' based on PII tag for each column/field as a pie-chart. 
App generates two separate charts based on 'Access Review' and 'Fields'.

Pre-Requistes:

Need following python packages:
- json
- request
- plotly
- re

Update following constant in script:
- SKYFLOW_VAULT_ENDPOINT: This expects vault endpoint like 'https://manage.skyflowapis.com/v1/vaults'
- SKYFLOW_SA_ENDPOINT: This expects service account endpoint like 'https://manage.skyflowapis.com/v1/serviceAccounts'
- SKYFLOW_LISTROLES_ENDPOINT: This expects list roles endpoint like 'https://manage.skyflowapis.com/v1/roles'
- VAULT_OWNER_SA_CREDENTIALS (bearer token): This expects bearer token in the format 'bearer <token>'
- SKYFLOW_ACCOUNT_ID: This expects accountID of vault to analyse risk distribution
- SKYFLOW_VAULT_ID: This expects vaultID of vault to analyse risk distribution

