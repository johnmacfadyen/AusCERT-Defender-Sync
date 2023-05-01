#!/usr/bin/pwsh

# Download AusCERT Feed and Import into MS Defender for Endpoint
# Author: John MacFadyen john@jjm.id.au
# Date: 28/04/2023
# Version: 1.0
# Initial setup based on Instructions @ https://learn.microsoft.com/en-us/graph/tutorials/powershell-app-only
# API Permissions required: Microsoft Graph -> ThreatIndicators.ReadWrite.OwnedBy

# Install-Module Microsoft.Graph
Import-Module Microsoft.Graph.Security

# Get Config values from settings file.
$settings = Get-Content -Path ./settings.json | ConvertFrom-Json

# AusCERT
$AusCERT_XML_URL = $settings.AusCERT_XML_URL
$AusCERT_API_KEY = $settings.AusCERT_API_KEY
$AusCERT_Daily = $settings.AusCERT_Daily

# Defender
$clientId = $settings.clientId
$tenantId = $settings.tenantId
$certificate = $settings.clientCertificate

# Create headers
$headers = @{}
$headers.add("API-Key", $AusCERT_API_KEY)

# Setup time variables
$timezone = [System.TimeZoneInfo]::Local

# Retrieve daily or weekly feed
if ($AusCERT_Daily -eq "true") {
    $days = 1
} else {
    $days = 7
}

$PhishFeedURL = "$($AusCERT_XML_URL)phishing-$days-xml/"
$MalwareFeedURL = "$($AusCERT_XML_URL)malware-$days-xml/"

$AusCERT_phish_feed = Invoke-RestMethod -uri $PhishFeedURL -headers $headers -Method Get
$AusCERT_malware_feed = Invoke-RestMethod -uri $MalwareFeedURL -headers $headers -Method Get

Select-MgProfile -Name "beta"  # Use beta endpoint
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateName $certificate

foreach ($item in $AusCERT_phish_feed) {
    
    # Drop timezone from pubDate
    $item.pubDate = [System.TimeZoneInfo]::ConvertTimeFromUtc(($item.pubDate -replace "UTC", ""), $timezone)
    
    # Setup Parameters for New-MGSecurityTiIndicator
    $params = @{
        Action = "block"
        Confidence = 50 # Set to your desired confidence level
        Description = "AusCERT Phishing Feed"
        ExpirationDateTime = $item.pubDate.AddDays(7)
        Url = "$($item.uri)"
        TlpLevel = "orange" # Set to your desired TLP level - This seems to be ignored for Defender for Endpoints, untested with sentinel.
        ThreatType = "Phishing" 
        TargetProduct = "Microsoft Defender ATP"
        Severity = 3
        Tags = @("AusCERT")
    }
    
    $retryCount = 5
    
    do {
        try {
            New-MgSecurityTiIndicator -BodyParameter $params -ErrorAction Stop
            $success = $true
        } catch {
            
            if ($_.ErrorDetails.Message -like "*Http request failed with statusCode=429*") {
                # More testing required for error handling
                $waitTime = [int]((($_.ErrorDetails.Message|select-string -Pattern "You can send requests again in (?<wait>[0-9]{2}) seconds").Matches.Groups|where-object {$_.Name -eq "wait"}).Value) + 2
                Write-Error "Too many requests. Throttling."
                Write-Host "Next Attempt in $waitTime seconds"
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Error "Something went wrong"
                Write-Host $_
            }
            
            $retryCount--
            $success = $false
        }
    } while (($retryCount -ge 3) -and ($success -eq $false))
    
}

foreach ($item in $AusCERT_malware_feed) {
    
    # Drop timezone from pubDate
    $item.pubDate = [System.TimeZoneInfo]::ConvertTimeFromUtc(($item.pubDate -replace "UTC", ""), $timezone)
    
    # Setup Parameters for New-MGSecurityTiIndicator
    $params = @{
        Action = "block"
        Confidence = 50 # Set to your desired confidence level
        Description = "AusCERT Malware Feed"
        ExpirationDateTime = $item.pubDate.AddDays(7)
        Url = "$($item.uri)"
        TlpLevel = "orange" # Set to your desired TLP level - This seems to be ignored for Defender for Endpoints, untested with sentinel.
        ThreatType = "MaliciousUrl" 
        TargetProduct = "Microsoft Defender ATP"
        Severity = 3
        Tags = @("AusCERT")
    }
    
    $retryCount = 2
    
    do {
        try {
            New-MgSecurityTiIndicator -BodyParameter $params -ErrorAction Stop
            $success = $true
        } catch {
            
            if ($_.ErrorDetails.Message -like "*Http request failed with statusCode=429*") {
                # More testing required for error handling
                $waitTime = [int]((($_.ErrorDetails.Message|select-string -Pattern "You can send requests again in (?<wait>[0-9]{2}) seconds").Matches.Groups|where-object {$_.Name -eq "wait"}).Value) + 2
                Write-Error "Too many requests. Throttling."
                Write-Host "Next Attempt in $waitTime seconds"
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Error "Something went wrong"
                Write-Host $_
            }
            
            $retryCount--
            $success = $false
        }
    } while (($retryCount -ge 3) -and ($success -eq $false))
}

Disconnect-MgGraph