# sysmon-suspicious-cli-detection

PowerShell detection for identifying suspicious command-line executions using Sysmon Process Creation events (Event ID 1). Focused on SOC triage and baseline analysis, not incident response.

## MITRE ATT&CK Mapping

This detection relates to the following ATT&CK techniques:

* **T1059 — Command and Scripting Interpreter**
  * PowerShell and `cmd.exe` execution with suspicious parameters
* **T1218 — Signed Binary Proxy Execution**
  * Abuse of LOLBins such as `rundll32.exe` and `mshta.exe`
* **T1105 — Ingress Tool Transfer**
  * Potential payload download via native utilities (`certutil`, PowerShell)

These techniques are commonly observed during initial access, execution, and post-exploitation phases.

## Usage

Run the detection script in PowerShell:

```powershell
.\detection.ps1
