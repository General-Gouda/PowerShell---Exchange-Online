<#
.SYNOPSIS
    Sets email security settings for email attacks.
.DESCRIPTION
    Accepts input from user and applies it to specific rules
    and policies within Exchange Online to protect against
    future attacks.
.NOTES
    Created by Matt Marchese
    Version: 2018.03.20
#>

[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)]
    [ValidateSet('Production','Test')]
    [string]$Environment,

    [parameter(Mandatory=$false)]
    [string[]]$EmployeeUsernames,

    [parameter(Mandatory=$false)]
    [string[]]$RevokeAzureAccess,

    [parameter(Mandatory=$false)]
    [string[]]$EmailAddresses,

    [parameter(Mandatory=$false)]
    [string[]]$WhalingEmailAddresses,

    [parameter(Mandatory=$false)]
    [string[]]$WhalingPhrases,

    [parameter(Mandatory=$false)]
    [string[]]$ReplyToAddresses,

    [parameter(Mandatory=$false)]
    [string[]]$Domains,

    [parameter(Mandatory=$false)]
    [string[]]$URLs,

    [parameter(Mandatory=$false)]
    [string[]]$IPAddresses
)

function Import-JsonToObject
{
    [CmdletBinding()]
    param
    (
        [string]$FilePath
    )

    if (Test-Path $FilePath)
    {
        $fileObject = (Get-Content -Path $FilePath) -join "`n" | ConvertFrom-Json
    }
    else
    {
        Throw "Path to JSON file not found."
    }

    return $fileObject
}

function Remove-NullValueProperties
{
    [CmdletBinding()]
    param
    (
        $InputObject
    )

    $InputObject | ForEach-Object {
        $settings = $_
    }

    return (Select-Object -InputObject $settings -Property (($InputObject.psobject.Properties | Where-Object {[string]::IsNullOrWhiteSpace($_.value) -eq $false}).Name))
}

function Get-RandomPassword
{
    Param
    (
        [int]$PasswordLength=31,
        [switch]$Secure
    )

    $ascii = $NULL;For ($a=48;$a -le 122;$a++) {$ascii+=,[char][byte]$a}

    For ($loop=1; $loop -le $PasswordLength; $loop++)
    {
        $randomPassword += ($ascii | Get-Random)
    }

    if ($Secure)
    {
        $randomPassword = ConvertTo-SecureString $randomPassword -AsPlainText -Force
    }

    return $randomPassword
}

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

$emailRecipients = @(
    "admin@domain.com",
    "admin2@domain.com",
    "admin3@domain.com"
)

if ($Environment -eq 'Production')
{
    # Insert code you use to connect to Production Exchange Online here
    # Insert code you use to connect to Production Azure AD here
}
elseif ($Environment -eq 'Test')
{
    # Insert code you use to connect to Test Exchange Online here
    # Insert code you use to connect to Test Azure AD here
}

$currentVerbosePref = $VerbosePreference
$VerbosePreference = "Continue"

$emailHeader = "This information was gleaned from emails deemed as malicious, harmful or annoying by IT Security staff or IT Email Administration.`n`n"
$emailString = $null

if ([string]::IsNullOrWhiteSpace($EmployeeUsernames) -ne $true)
{
    $credentials = Get-Credential

    $emailString += "The following employee's had their password reset:`n"

    foreach ($EmployeeUsername in $EmployeeUsernames)
    {
        $emailString += "- $EmployeeUsername`n"

        try
        {
            Write-Output ("Resetting {0}'s password to random 31 character value." -f $EmployeeUsername)
            $tempPass = Get-RandomPassword -PasswordLength 31 -Secure
            Set-ADAccountPassword -Identity $EmployeeUsername -Reset -NewPassword $tempPass -Credential $credentials -ErrorAction Stop
            Write-Output ("    Password reset successful.")
        }
        catch
        {
            Write-Error "    Error resetting user password. Error: $_"
        }
    }

    $emailRecipients += "helpDeskEmail@domain.com"

    $emailString += "`n"
}

if ([string]::IsNullOrWhiteSpace($RevokeAzureAccess) -ne $true){
    $emailString += "The following employee's had their Azure AD Login Tokens reset:`n"

    foreach ($revoke in $RevokeAzureAccess) {

        $emailString += "- $revoke`n"

        try {
            Write-Output "Revoking $($revoke)'s Azure Access Tokens."
            Revoke-AzureADUserAllRefreshToken -ObjectId "$($revoke)@domain.com" -ErrorAction Stop
            Write-Output "    Access revoked successfully."
        }
        catch {
            Write-Error "    Error revoking Azure Access Tokens. Error: $_"
        }
    }

    $emailString += "`n"
}

if ([string]::IsNullOrWhiteSpace($EmailAddresses) -ne $true)
{
    foreach ($EmailAddress in $EmailAddresses)
    {
        # Add to transport rules Phishing URL and Email Blocking, Block forward to malicious email address, Malicious Reply-To Block Rule
        Set-TransportRuleAttribute -TransportRuleName 'Phishing URL and Email Blocking' -AttributeNames 'SubjectOrBodyMatchesPatterns' -ObjectToAdd $EmailAddress

        # Add to spam email address block sender list
        Write-Output ("Adding '{0}' to BlockSenders list in the Default Content Filter Policy" -f $EmailAddress)
        Set-HostedContentFilterPolicy -Identity 'Default' -BlockedSenders @{Add = $EmailAddress}
    }
}

if ([string]::IsNullOrWhiteSpace($WhalingEmailAddresses) -ne $true)
{
    foreach ($WhalingEmailAddress in $WhalingEmailAddresses)
    {
        # Add to transport rule CEO impersonation attempt redirect
        Set-TransportRuleAttribute -TransportRuleName 'CEO impersonation attempt redirect' -AttributeNames 'From' -ObjectToAdd $WhalingEmailAddress

        # Add to spam email address block sender list
        Write-Output ("Adding '{0}' to BlockSenders list in the Default Content Filter Policy" -f $WhalingEmailAddress)
        Set-HostedContentFilterPolicy -Identity 'Default' -BlockedSenders @{Add = $WhalingEmailAddress}
    }
}

if ([string]::IsNullOrWhiteSpace($WhalingPhrases) -ne $true)
{
    foreach ($WhalingPhrase in $WhalingPhrases)
    {
        # Add to transport rule CEO Whaling Rule
        Set-TransportRuleAttribute -TransportRuleName 'CEO Whaling Rule' -AttributeNames 'SubjectOrBodyMatchesPatterns' -ObjectToAdd $WhalingPhrase
    }
}

if ([string]::IsNullOrWhiteSpace($ReplyToAddresses) -ne $true)
{
    foreach ($ReplyTo in $ReplyToAddresses)
    {
        # Add to transport rules Malicious Reply-To Block Rule, Block forward to malicious email address
        Set-TransportRuleAttribute -TransportRuleName 'Block forward to malicious email address' -AttributeNames 'RecipientAddressMatchesPatterns' -ObjectToAdd $ReplyTo

        Set-TransportRuleAttribute -TransportRuleName 'Malicious Reply-To Block Rule' -AttributeNames 'HeaderMatchesPatterns','HeaderMatchesMessageHeader' -ObjectToAdd $ReplyTo,"Reply-To"
    }
}

if ([string]::IsNullOrWhiteSpace($Domains) -ne $true)
{
    $emailString += "Please add the following Domains to the OpenDNS block list:`n"

    foreach ($Domain in $Domains)
    {
        $emailString += "- $Domain`n"

        # Add to transport rule Quarantine- Domain
        Set-TransportRuleAttribute -TransportRuleName 'Quarantine- Domain' -AttributeNames 'SenderDomainIs' -ObjectToAdd $Domain

        # Add to spam email block domain list
        Write-Output ("Adding '{0}' to BlockedSenderDomains list in the Default Content Filter Policy" -f $Domain)
        Set-HostedContentFilterPolicy -Identity 'Default' -BlockedSenderDomains @{Add = $Domain}
    }

    $emailString += "`n"
}

if ([string]::IsNullOrWhiteSpace($URLs) -ne $true)
{
    $emailString += "Please add the following URLs to the OpenDNS block list:`n"

    foreach ($URL in $URLs)
    {
        $emailString += "- $URL`n"

        # Add to transport rule Phishing URL and Email Blocking
        Set-TransportRuleAttribute -TransportRuleName 'Phishing URL and Email Blocking' -AttributeNames 'SubjectOrBodyMatchesPatterns' -ObjectToAdd $URL
    }

    $emailString += "`n"
}

if ([string]::IsNullOrWhiteSpace($IPAddresses) -ne $true)
{
    $emailString += "Please add the following IP addresses to the firewall black list:`n"

    foreach ($IPAddress in $IPAddresses)
    {
        $emailString += "- $IPAddress`n"
        # Add to Connection Filter IP Block List
        Write-Output ("Adding '{0}' to IPBlockList list in the Default Connection Filter Policy" -f $IPAddress)
        Set-HostedConnectionFilterPolicy -Identity 'Default' -IPBlockList @{Add=$IPAddress}
    }

    $emailString += "`n"
}

if ($emailString -ne $null)
{
    $mailMessageParams = @{
        To = $emailRecipients
        From = "admin@domain.com"
        Subject = "Phishing/Malicious Email information"
        Body = $emailHeader + $emailString
        SmtpServer = "mailrelay.domain.com"
        Credential = Get-Credential
    }

    Send-MailMessage @mailMessageParams
}

$VerbosePreference = $currentVerbosePref

Close-Connections
