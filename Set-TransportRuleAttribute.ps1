function Set-TransportRuleAttribute
{
    [CmdletBinding()]
    param
    (
        [string]$TransportRuleName,
        [string[]]$AttributeNames,
        [string[]]$ObjectToAdd
    )

    Write-Output ("Adding '{0}' to attribute '{1}' in transport rule '{2}'" -f ($ObjectToAdd -join ", "), ($AttributeNames -join ", "), $TransportRuleName)

    $params = @{
        Identity = $TransportRuleName
    }

    foreach ($Attribute in $AttributeNames)
    {
        if ($Attribute -eq 'HeaderMatchesMessageHeader')
        {
            $params += @{
                $Attribute = $ObjectToAdd[([array]::IndexOf($AttributeNames,$Attribute))]
            }
        }
        else
        {
            $transportRuleAttributeValue = (Get-TransportRule $TransportRuleName).$Attribute
            $transportRuleAttributeValue += $ObjectToAdd[([array]::IndexOf($AttributeNames,$Attribute))]

            $params += @{
                $Attribute = $transportRuleAttributeValue | Select-Object -Unique
            }
        }
    }

    Set-TransportRule @params
}
