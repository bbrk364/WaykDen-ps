
. "$PSScriptRoot/../Private/CertificateHelper.ps1"

function Import-WaykDenCertificate
{
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $CertificateFile,
        [string] $PrivateKeyFile,
        [string] $Password
    )

    $ConfigPath = Find-WaykDenConfig -ConfigPath:$ConfigPath

    $config = Get-WaykDenConfig -ConfigPath:$ConfigPath

    $result = Get-PemCertificate -CertificateFile:$CertificateFile `
        -PrivateKeyFile:$PrivateKeyFile -Password:$Password
        
    $CertificateData = $result.Certificate
    $PrivateKeyData = $result.PrivateKey

    [string[]] $PemChain = Split-PemChain -Label 'CERTIFICATE' -PemData $CertificateData

    if ($PemChain.Count -eq 1) {
        Write-Warning "The certificate chain includes only one certificate (leaf certificate)."
        Write-Warning "The complete chain should also include the intermediate CA certificate."
        Write-Warning "For more information on certificate configuration, refer to:"
        Write-Warning "https://github.com/devolutions/WaykDen-ps#certificate-configuration"
    }

    $TraefikPath = Join-Path $ConfigPath "traefik"
    New-Item -Path $TraefikPath -ItemType "Directory" -Force | Out-Null

    $TraefikPemFile = Join-Path $TraefikPath "den-server.pem"
    $TraeficKeyFile = Join-Path $TraefikPath "den-server.key"

    Set-Content -Path $TraefikPemFile -Value $CertificateData -Force
    Set-Content -Path $TraeficKeyFile -Value $PrivateKeyData -Force
}

function Import-WaykLdapCertificate
{
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $CertificateFile
    )

    $ConfigPath = Find-WaykDenConfig -ConfigPath:$ConfigPath

    $config = Get-WaykDenConfig -ConfigPath:$ConfigPath

    $CertificateData = Get-Content -Path $CertificateFile -Raw -ErrorAction Stop

    $DenServerPath = Join-Path $ConfigPath "den-server"
    New-Item -Path $DenServerPath -ItemType "Directory" -Force | Out-Null

    $LdapRootCaFile = Join-Path $DenServerPath "ldap-root-ca.pem"
    Set-Content -Path $LdapRootCaFile -Value $CertificateData -Force
}

Export-ModuleMember -Function Import-WaykDenCertificate, Import-WaykLdapCertificate
