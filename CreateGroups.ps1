#Requires -Version 7
#Requires -Modules Az.Accounts

# Dotsource required functions (can be converted to a module)
. ./CreateGroupAndOnboardPIM.ps1
. ./AddRolesToGroup.ps1
. ./ConfigureGroupPIMSettings.ps1

$newgroupsroles = Import-Csv -Path ./CreateGroups.csv -Delimiter ';'  

$newgroups = $newgroupsroles | select -Unique -Property GroupName, Description
Write-Output "Got $($newgroups.count) group(s) and a total of $($newgroupsroles.Length) role(s) from CSV file"

# Create array list to store all created groups
[System.Collections.ArrayList]$global:CreatedGroups = @()

# Loop through groups from CSV file and create groups in Azure AD
foreach ($group in $newgroups) {

    # Create role assignable group in Azure AD
    $creategroup = New-AzADGroup  -DisplayName $($group.GroupName) -Description $($group.Description) -IsAssignableToRole:$true -SecurityEnabled:$true -MailEnabled:$false -MailNickname $($group.GroupName -replace '\s', '') 
    Write-Output "Created group: $($creategroup.DisplayName) with ID $($creategroup.id)"

    # Add created group to list for onboarding PIM later
    [void]$CreatedGroups.Add($creategroup)

}
Write-Output "Created $($CreatedGroups.Count) group(s) in Azure AD"

# Wait some seconds for the groups to be available in PIM
Write-Output "Waiting 60 seconds for PIM to be ready"
Start-Sleep -Seconds 60

# Create array list to store all PIM enabled groups
[System.Collections.ArrayList]$global:pimEnabledGroups = @()

# Loop through all created groups in Azure AD and onboard to PIM
foreach ($group in $CreatedGroups) {
    # Register group to PIM
    Write-Output "Registering group $($group.DisplayName) - $($group.Id) to PIM"
    $pimenabledgroup = Register-PrivilegedAccessGroupToPIM -GroupObjectID $group.id
    if ($pimenabledgroup) {
        [void]$pimEnabledGroups.Add($pimenabledgroup)
        Write-Output "OK"
    } else {
        Write-Output "Failed"
    }
}
Write-Output "Enabled PIM on $($pimEnabledGroups.count) group(s)"

# Wait some seconds for PIM to be ready to accept configuration
Write-Output "Waiting 15 seconds for PIM to be ready"
Start-Sleep -Seconds 15
Write-Output "Configuring Member and Owner settings in PIM"
foreach ($group in $pimEnabledGroups) {
    Update-PrivilegedAccessGroupRoleSettings -GroupObjectID $group.GroupID
}

Write-Output "Adding roles to the previously created groups"

foreach ($createdgroup in $CreatedGroups) {
    $newgroupsroles | where { $createdgroup.DisplayName -eq $_.GroupName } | ForEach-Object {
        Write-Output "Adding role $($_.RoleName) to group $($createdgroup.DisplayName)"
        Add-AADRoleToPrivilegedAccessGroup -GroupObjectID $createdgroup.id -RoleName $_.RoleName
    }
}