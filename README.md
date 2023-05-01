# AusCERT-Defender-Sync
Sync AusCERT URL feed to MS Defender for Endpoints

## Instructions

This app is based off https://learn.microsoft.com/en-us/graph/tutorials/powershell-app-only?tabs=windows
Please follow the intial steps to create your app registration and certificate details.
API Permissions required: Microsoft Graph -> ThreatIndicators.ReadWrite.OwnedBy

You will need to update the settings.json file with your AusCERT API key and AzureAD tenant details and certificate. 

Tested on Ubuntu 22.04 with Powershell 7.2.4.