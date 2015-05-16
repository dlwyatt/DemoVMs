Write-Verbose -Verbose 'Starting Demo VM'
$output = (vagrant up) -join "`r`n"
Write-Verbose -Verbose 'Demo VM running.  Setting up PS Session.'

if ($output -match '5985\s*=>\s*(\d+)')
{
    $port = $matches[1]
}
else
{
    $port = Read-Host -Prompt '"vagrant up" output did not contain mapped WinRM port.  Enter port.'
}

$global:DemoPort = $port

function global:Connect-Demo
{
    param (
        [Parameter(Mandatory)]
        [int] $Port
    )

    $credential = New-Object pscredential('vagrant', ('vagrant' | ConvertTo-SecureString -AsPlainText -Force))
    $session = New-PSSession -ComputerName localhost -Port $port -Credential $credential -Authentication Negotiate

    $global:PSDefaultParameterValues['Invoke-Command:Session'] = $session

    Invoke-Command -Session $session { $remoteCert = Get-Item Cert:\CurrentUser\My\A6DDB481705C2AC53BFD6B35503EAD91E87B637E }
    $global:localCert = Get-Item Cert:\CurrentUser\My\A6DDB481705C2AC53BFD6B35503EAD91E87B637E
}

Connect-Demo -Port $port
