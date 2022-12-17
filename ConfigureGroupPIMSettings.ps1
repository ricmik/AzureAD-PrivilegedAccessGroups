function Get-PrivilegedAccessGroupRoleSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupObjectID
    )

    # Check if token is valid
    if (!$pimAPIToken -or $pimAPIToken.ExpiresOn -lt ${Get-Date}) { 
        $pimAPIToken = Get-AzAccessToken -ResourceUrl 'https://api.azrbac.mspim.azure.com' -ErrorAction Stop
    }
        
    # Create authorization header with token
    $headers = @{
        "Authorization" = "Bearer {0}" -f ($($pimAPIToken.Token))
    }
    # Get group Member and Owner objects needed to configure both member and owner PIM settings
    $groupRoles = Invoke-RestMethod -Uri "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsv2?`$expand=roleDefinition(`$expand=resource)&`$filter=(resource/id+eq+'$GroupObjectID')" -Headers $Headers -Method GET -ContentType 'application/json'

    return $groupRoles.value

}
function Update-PrivilegedAccessGroupRoleSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GroupObjectID
    )

    begin {
        # Check if token is valid
        if (!$pimAPIToken -or $pimAPIToken.ExpiresOn -lt ${Get-Date}) { 
            $pimAPIToken = Get-AzAccessToken -ResourceUrl 'https://api.azrbac.mspim.azure.com' -ErrorAction Stop
        }
        
        # Create authorization header with token
        $headers = @{
            "Authorization" = "Bearer {0}" -f ($($pimAPIToken.Token))
        }
        
        # Configure settings for the MEMBER role on the Privileged Access Group
        $memberSettings = [PSCustomObject]@{
            lifeCycleManagement = @(
                @{
                    ## START ELIGIBLE ASSIGNMENT REGION
                    caller    = "Admin"
                    level     = "Eligible"
                    operation = "ALL"
                    value     = @(
                        @{
                            # Eligible assignment expiration rule
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false # Allow permanent eligible assignments?
                                maximumGrantPeriodInMinutes = 525600 # Expire eligible assignments after 1 year (525600 minutes)
                            } | ConvertTo-Json -Compress # Setting needs to be nested JSON
                        },
                        @{
                            # Notification rule for eligible assignment (Send notifications when members are assigned as eligible to this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to the assigned user (assignee)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Assignee)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role assignment alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ELIGIBLE ASSIGNMENT REGION
                ## START ACTIVE ASSIGNMENT REGION
                @{
                    caller    = "Admin"
                    level     = "Member"
                    operation = "ALL"
                    value     = @(
                        @{
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false # Allow permanent active assignments?
                                maximumGrantPeriodInMinutes = 21600 # Expire active assignments after 15 days (21600 minutes)
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            ruleIdentifier = "MfaRule"
                            setting        = @{
                                mfaRequired = $true # Require MFA when assigning a user as active?
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            ruleIdentifier = "JustificationRule"
                            setting        = @{
                                required = $true # Require justification when assigning a user as active?
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            # Notification rule for active assignment (Send notifications when members are assigned as active to this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to the assigned user (assignee)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Assignee)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role assignment alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ACTIVE ASSIGNMENT REGION
                ## START ELIGIBLE USER ACTIVATING ROLE REGION
                @{
                    caller    = "EndUser"
                    level     = "Member"
                    operation = "ALL"
                    value     = @(
                        @{
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false
                                maximumGrantPeriodInMinutes = 480 # Activation maximum duration 8 hours (480 minutes)
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "MfaRule"
                            setting        = @{
                                mfaRequired = $true # Require MFA when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "JustificationRule"
                            setting        = @{
                                required = $false # Require justification when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "TicketingRule"
                            setting        = @{
                                ticketingRequired = $false # Require ticket number when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "ApprovalRule"
                            setting        = @{
                                enabled   = $false # Require approval when user is activating the role?
                                approvers = $null # List of approvers to notify
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "AcrsRule"
                            setting        = @{
                                acrsRequired = $false
                                acrs         = $null
                            } | ConvertTo-Json -Compress
                        }
                        ,
                        @{
                            # Notification rule when a user is activating an assignment (Send notifications when eligible members activate this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to activated user (requestor)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Requestor)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # MUST be null (custom email addresses not allowed)
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role activation alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ELIGIBLE USER ACTIVATING ROLE REGION
            )
        } | ConvertTo-Json -Depth 10

        # Configure settings for the OWNER role on the Privileged Access Group
        $ownerSettings = [PSCustomObject]@{
            lifeCycleManagement = @(
                @{
                    ## START ELIGIBLE ASSIGNMENT REGION
                    caller    = "Admin"
                    level     = "Eligible"
                    operation = "ALL"
                    value     = @(
                        @{
                            # Eligible assignment expiration rule
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false # Allow permanent eligible assignments?
                                maximumGrantPeriodInMinutes = 525600 # Expire eligible assignments after 1 year (525600 minutes)
                            } | ConvertTo-Json -Compress # Setting needs to be nested JSON
                        },
                        @{
                            # Notification rule for eligible assignment (Send notifications when members are assigned as eligible to this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to the assigned user (assignee)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Assignee)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role assignment alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ELIGIBLE ASSIGNMENT REGION
                ## START ACTIVE ASSIGNMENT REGION
                @{
                    caller    = "Admin"
                    level     = "Member"
                    operation = "ALL"
                    value     = @(
                        @{
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false # Allow permanent active assignments?
                                maximumGrantPeriodInMinutes = 21600 # Expire active assignments after 15 days (21600 minutes)
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            ruleIdentifier = "MfaRule"
                            setting        = @{
                                mfaRequired = $true # Require MFA when assigning a user as active?
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            ruleIdentifier = "JustificationRule"
                            setting        = @{
                                required = $true # Require justification when assigning a user as active?
                            } | ConvertTo-Json -Compress
                        }
                        @{
                            # Notification rule for active assignment (Send notifications when members are assigned as active to this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to the assigned user (assignee)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Assignee)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role assignment alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 2 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ACTIVE ASSIGNMENT REGION
                ## START ELIGIBLE USER ACTIVATING ROLE REGION
                @{
                    caller    = "EndUser"
                    level     = "Member"
                    operation = "ALL"
                    value     = @(
                        @{
                            ruleIdentifier = "ExpirationRule"
                            setting        = @{
                                permanentAssignment         = $false
                                maximumGrantPeriodInMinutes = 60 # Activation maximum duration 1 hour (60 minutes)
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "MfaRule"
                            setting        = @{
                                mfaRequired = $true # Require MFA when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "JustificationRule"
                            setting        = @{
                                required = $true # Require justification when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "TicketingRule"
                            setting        = @{
                                ticketingRequired = $false # Require ticket number when user is activating the role?
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "ApprovalRule"
                            setting        = @{
                                enabled   = $false # Require approval when user is activating the role?
                                approvers = $null # List of approvers to notify
                            } | ConvertTo-Json -Compress
                        },
                        @{
                            ruleIdentifier = "AcrsRule"
                            setting        = @{
                                acrsRequired = $false
                                acrs         = $null
                            } | ConvertTo-Json -Compress
                        }
                        ,
                        @{
                            # Notification rule when a user is activating an assignment (Send notifications when eligible members activate this role)
                            ruleIdentifier = "NotificationRule"
                            setting        = @{
                                policies = @(
                                    @{
                                        deliveryMechanism = "email"
                                        setting           = @(
                                            # Notification type: Notification to activated user (requestor)
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Requestor)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 0
                                            },
                                            # Notification type: Request to approve a role assignment renewal/extension
                                            @{
                                                customreceivers          = $null # MUST be null (custom email addresses not allowed)
                                                isdefaultreceiverenabled = $true # Send to default recipient (Approver)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 1
                                            },
                                            # Notification type: Role activation alert
                                            @{
                                                customreceivers          = $null # Null or array of email addresses
                                                isdefaultreceiverenabled = $true # Send to default recipient (Admin)?
                                                notificationlevel        = 1 #  1 = Critical emails only enabled, 2 = Critical emails only disabled
                                                recipienttype            = 2
                                            }
                                        ) 
                                    }
                                )
                            } | ConvertTo-Json -Depth 5 -Compress # Setting needs to be nested JSON
                        }
                    )
                }
                ## END ELIGIBLE USER ACTIVATING ROLE REGION
            )
        } | ConvertTo-Json -Depth 10
    }

    process {

        $groupRoles = Get-PrivilegedAccessGroupRoleSettings -GroupObjectID $GroupObjectID
        $ownerRole = $groupRoles | where { $_.roleDefinition.displayName -eq "Owner" }
        
        Write-Output "Updating settings for $GroupObjectID - role $($ownerRole.roleDefinition.displayName) ($($ownerRole.id))"
        $ownerUpdateURI = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsV2/$($ownerRole.id)"
        $updateOwnerPIMSettings = Invoke-WebRequest -Uri $ownerUpdateURI -Headers $Headers -Method PATCH -Body $ownerSettings -ContentType 'application/json'
        if ($updateOwnerPIMSettings.BaseResponse.IsSuccessStatusCode -eq $true) {
            Write-Output "OK"
        } else {
            Write-Output "Failed"
        }

        $groupRoles = Get-PrivilegedAccessGroupRoleSettings -GroupObjectID $GroupObjectID
        $memberRole = $groupRoles | where { $_.roleDefinition.displayName -eq "Member" }

        Write-Output "Updating settings for $GroupObjectID - role $($memberRole.roleDefinition.displayName) ($($memberRole.id))"
        $memberUpdateURI = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsV2/$($memberRole.id)"
        $updateMemberPIMSettings = Invoke-WebRequest -Uri $memberUpdateURI -Headers $Headers -Method PATCH -Body $memberSettings -ContentType 'application/json'
        if ($updateMemberPIMSettings.BaseResponse.IsSuccessStatusCode -eq $true) {
            Write-Output "OK"
        } else {
            Write-Output "Failed"
        }
    }

    end {

    }
}