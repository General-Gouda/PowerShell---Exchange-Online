[CmdletBinding()]
param
(
    [string]$SenderAddress = "user@domain.com",
    [string]$RecipientAddress,
    [datetime]$StartDate = ((Get-Date).AddDays(-7)),
    [datetime]$EndDate = ((Get-Date)),
    [string]$FromIP,
    [string]$ToIP,
    [string]$Status,
    [string]$FilePath
)

class MessageTraceResults {
    [string]$Received
    [string]$SenderAddress
    [string]$RecipientAddress
    [string]$Subject
    [string]$Status
}

$currentErrorActionPrefs = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

if ($StartDate) {
    $StartDate = $StartDate.ToUniversalTime()
}

if ($EndDate) {
    $EndDate = $EndDate.ToUniversalTime()
}

$cmdletParams = (Get-Command $PSCmdlet.MyInvocation.InvocationName).Parameters.Keys

# Insert code to connect to Office 365 Exchange Online PowerShell session here!

$params = @{}

foreach ($cmdletParam in $cmdletParams) {
    if ($cmdletParam -notmatch "FilePath|Debug|Verbose|ErrorAction|WarningAction|InformationAction|ErrorVariable|WarningVariable|InformationVariable|OutVariable|OutBuffer|PipelineVariable")
    {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $cmdletParam).Value) -ne $true){
            $params.Add($cmdletParam, (Get-Variable -Name $cmdletParam).Value)
        }
    }
}

$counter = 1
$continue = $false
$allMessageTraceResults = New-Object System.Collections.ArrayList

do {
    Write-Output "Checking message trace results on page $counter."
    try {
        $messageTrace = Get-MessageTrace @params -Page $counter

        if ($messageTrace) {
            $messageTrace | ForEach-Object {
                $messageTraceResults = New-Object MessageTraceResults

                $messageTraceResults.Received = $_.Received
                $messageTraceResults.SenderAddress = $_."SenderAddress"
                $messageTraceResults.RecipientAddress = $_."RecipientAddress"
                $messageTraceResults.Subject = $_.Subject
                $messageTraceResults.Status = $_.Status

                $allMessageTraceResults.Add($messageTraceResults) | Out-Null
            }

            $counter++
            Start-Sleep -Seconds 2
        } else {
            Write-Output "`tNo results found on page $counter."
            $continue = $true
        }
    } catch {
        Write-Output "`tException gathering message trace data on page $counter. Trying again in 30 seconds."
        Start-Sleep -Seconds 30
    }
} while ($continue -eq $false)

if ($allMessageTraceResults.count -gt 0) {
    Write-Output "`n$($allMessageTraceResults.count) results returned."
    $allMessageTraceResults | Out-GridView

    if ($FilePath) {
        Write-Output "Writing results to $FilePath"
        $allMessageTraceResults | Export-Csv $FilePath -NoTypeInformation
    }
} else {
    Write-Output "`nNo Results found."
}

$ErrorActionPreference = $currentErrorActionPrefs

Get-PSSession | Remove-PSSession
