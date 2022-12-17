function Register-PrivilegedAccessGroupToPIM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GroupObjectID
    )
    
    begin {
        # Check if token is valid
        if(!$pimAPIToken -or $pimAPIToken.ExpiresOn -lt ${Get-Date}) { 
            $pimAPIToken = Get-AzAccessToken -ResourceUrl 'https://api.azrbac.mspim.azure.com' -ErrorAction Stop
        }
        
        # Create authorization header with token
        $headers = @{
            "Authorization" = "Bearer {0}" -f ($($pimAPIToken.Token))
        }
        
        # PIM register Azure AD Group API endpoint
        $pimAPIuri = 'https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources/register'

    }
    
    process {
        # Create JSON payload with group object to be onboarded
        $Body = [PSCustomObject]@{
            externalId = $($GroupObjectID)
        } | ConvertTo-Json -Compress

        # Invoke request towards API
        $PIMonboard = Invoke-WebRequest -Uri $pimAPIuri -Headers $Headers -Method POST -Body $Body -ContentType 'application/json'
        
        if ($PIMonboard.BaseResponse.IsSuccessStatusCode -eq $true) {
            [PSCustomObject]@{
                GroupID = $GroupObjectID
                Status = $($PIMonboard.StatusDescription)
            }
        }
        else {
            Write-Warning "Failed to onboard group, HTTP status $($PIMonboard.StatusCode) - $($PIMonboard.StatusDescription)"
        }
    }
    
    end {
        
    }
}