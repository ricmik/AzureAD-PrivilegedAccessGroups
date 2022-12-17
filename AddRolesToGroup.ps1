#Requires -Version 7
#Requires -Modules Az.Accounts
function Add-AADRoleToPrivilegedAccessGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory, ParameterSetName = "RoleName")]
        [string]$RoleName,
        [Parameter(Mandatory, ParameterSetName = "RoleID")]
        [string]$RoleID,
        [Parameter(Mandatory)]
        [string]$GroupObjectID
    )
    
    begin {
        # Check if Connect-AzAccount is connected
        if ([string]::IsNullOrEmpty($((Get-AzContext).Account))) {
            Write-Output "Connect to Azure using Connect-AzAccount first"
            break
        } else {
            $pimtoken = (Get-AzAccessToken -ResourceUrl 'https://api.azrbac.mspim.azure.com' -ErrorAction Stop).Token
            $Headers = @{
                "Authorization" = "Bearer {0}" -f ($pimtoken)
            }
        }
        # Get all roles from Azure AD
        $azureADRoles = ((Invoke-AzRestMethod -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions').Content | ConvertFrom-Json).Value
        if ([string]::IsNullOrEmpty($($azureADRoles))) {
            Throw "Could not get Azure AD roles from Azure AD."
        }

        if ($RoleName) {
            $RoleID = ($azureADRoles | Where-Object { $_.displayName -eq $RoleName }).id
        }

        # Check if the role exists in Azure AD
        $RoleNameFromAAD = ($azureADRoles | Where-Object { $_.id -eq $RoleID }).displayName
        if ([string]::IsNullOrEmpty($($RoleNameFromAAD))) {
            Throw "The role '$RoleID$RoleName' does not exist in Azure AD. Cannot continue."
        }
        # URI to the PIM API endpoint for adding role assignments
        $AddRolesToGroupURI = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadroles/roleAssignmentRequests"
    }
    
    process {
        $roleObject = [PSCustomObject]@{
            resourceId       = (Get-AzContext).Tenant.Id # Tenant ID
            roleDefinitionId = $RoleID # Role definition ID to add from Azure AD
            subjectId        = $GroupObjectID # Privileged Access Group ID
            assignmentState  = 'Active' # Create active role assignment for the privileged access group
            type             = 'AdminAdd'
            reason           = 'Deployment from script'
            schedule         = @{
                type          = 'Once'
                startDateTime = Get-Date
                endDateTime   = $null
            }
            scopedResourceId = ""
            condition        = $null
            conditionVersion = $null
        } | ConvertTo-Json
        Write-Output "Adding role $RoleNameFromAAD with role ID $RoleID to Azure AD Group with ID $GroupObjectID"
        Invoke-RestMethod -Uri $AddRolesToGroupURI -Headers $Headers -Method POST -Body $roleObject -ContentType 'application/json' 
    }
    
    end {
        
    }
}
