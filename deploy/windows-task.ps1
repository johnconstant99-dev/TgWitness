# Register only when explicitly executed by the operator. Does not store passwords.
# Runs at logon in the current user's session; this is not an unattended Windows service.
# Windowless startup/server diagnostics are retained in DataPath\logs\server.log.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)][string]$ProjectPath,
    [Parameter(Mandatory=$true)][string]$DataPath,
    [string]$TaskName = 'TgWitness',
    [ValidateRange(1,65535)][int]$Port = 8787
)
$projectRoot = (Resolve-Path -LiteralPath $ProjectPath -ErrorAction Stop).Path
$pythonPath = Join-Path $projectRoot '.venv\Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw 'Prepare the environment with python start.py --setup-only first.'
}
$privateData = [System.IO.Path]::GetFullPath($DataPath)
if ($privateData.Contains('"')) { throw 'DataPath cannot contain a quote.' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $pythonPath -WorkingDirectory $projectRoot -Argument "-m tgwitness --host 127.0.0.1 --port $Port --data-dir `"$privateData`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
if ($PSCmdlet.ShouldProcess($TaskName, 'Register TgWitness logon task (no overwrite)')) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings
}
