# infa-sfdc-validator
Application validates Informatica and Salesforce objects metadata
There are two versions of the application.
# Version 1
Application name: infa_sfdc_validator.py
It utilizes simple-salesforce SalesforceLogin module for authentication.
Properties file name: infa_sfdc_app_properties.json
The advantage is it does not rely on Salesfoce connected app configuration.

# Version 2
Application name: infa_sfdc_validate.py
It utilizes standard Salesforce OAuth2.0 for authentication and requires connected app configuration.
Properties file name: infa_sfdc_properties.json
