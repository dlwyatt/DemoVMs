#requires -Version 4.0
#requires -RunAsAdministrator

Import-Certificate -FilePath $PSScriptRoot\Demo.cer -CertStoreLocation Cert:\CurrentUser\My

$target = 'C:\Program Files\WindowsPowerShell\Modules\ProtectedData'
if (-not (Test-Path -Path $target -PathType Container))
{
    $null = New-Item -Path $target -ItemType Directory -ErrorAction Stop
}

Copy-Item $PSScriptRoot\ProtectedData\* $target\ -Recurse -Force -ErrorAction Stop
