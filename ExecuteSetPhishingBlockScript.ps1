$environment = "Production"

<#
List of parameters:
    -Environment
    -EmailAddresses
    -EmployeeUsernames
    -RevokeAzureAccess
    -WhalingEmailAddresses
    -WhalingPhrases
    -ReplyToAddresses
    -Domains
    -URLs
    -IPAddresses
#>

##################################################

$WhalingEmailAddresses = @"

"@

##################################################

$WhalingPhrases = @"

"@

##################################################

$ReplyToAddresses = @"

"@

##################################################

$emailAddressesToBlock = @"

"@

##################################################

$resetPassForEmployeeUsernames = @"

"@

##################################################

$revokeAzureAccess = @"

"@

##################################################

$Domains = @"

"@

##################################################

$URLs = @"

"@

##################################################

$IPAddresses = @"

"@

##################################################

$emailAddressesToBlockArray = $emailAddressesToBlock.split("`n").trim()
$resetPassForEmployeeUsernamesArray = $resetPassForEmployeeUsernames.split("`n").trim()
$WhalingEmailAddressesArray = $WhalingEmailAddresses.split("`n").trim()
$WhalingPhrasesArray = $WhalingPhrases.split("`n").trim()
$ReplyToAddressesArray = $ReplyToAddresses.split("`n").trim()
$DomainsArray = $Domains.split("`n").trim()
$URLsArray = $URLs.split("`n").trim()
$IPAddressesArray = $IPAddresses.split("`n").trim() | Sort-Object -Unique
$revokeAzureAccessArray = $revokeAzureAccess.split("`n").Trim()

& 'C:\LocationOfScript\Set-PhishingBlock.ps1' `
    -Environment $environment `
    -EmployeeUsernames $resetPassForEmployeeUsernamesArray `
    -RevokeAzureAccess $revokeAzureAccessArray `
    -EmailAddresses $emailAddressesToBlockArray `
    -WhalingEmailAddresses $WhalingEmailAddressesArray `
    -WhalingPhrases $WhalingPhrasesArray `
    -ReplyToAddresses $ReplyToAddressesArray `
    -Domains $DomainsArray `
    -URLs $URLsArray `
    -IPAddresses $IPAddressesArray

