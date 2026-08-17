#!/usr/bin/env powershell
<#
.SYNOPSIS
    Sysmon Suspicious Command-Line Detection
.DESCRIPTION
    PowerShell detection for identifying suspicious command-line executions 
    using Sysmon Process Creation events (Event ID 1). Focused on SOC triage.
#>

$patterns = @(
    "-enc", "EncodedCommand",
    "-nop", "NoProfile",
    "-w hidden", "WindowStyle Hidden",
    "IEX", "Invoke-Expression",
    "DownloadString",
    "cmd.exe /c",
    "powershell.exe", "pwsh.exe",
    "rundll32", "regsvr32",
    "mshta", "certutil", "wscript", "cscript"
)

$events = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = 1
} -MaxEvents 500

$results = $events | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Image       = $_.Properties[4].Value
        CommandLine = $_.Properties[10].Value
    }
} | Where-Object {
    $cl = $_.CommandLine
    if ($null -ne $cl) {
        $patterns | Where-Object { $cl -match $_ }
    }
}

$results | Format-Table -AutoSize
