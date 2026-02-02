# Detect msDS-SupportedEncryptionTypes configuration (AD) and output it to two tables:
# 1) EncValue observed + how many UNIQUE accounts use it + RC4 supported?
# 2) Which accounts use which EncValue (with translation + RC4 supported?)
#
# Requires: RSAT ActiveDirectory module (Get-ADUser/Get-ADComputer/Get-ADServiceAccount)
# Run in a domain context.

Import-Module ActiveDirectory -ErrorAction Stop

# ---- Full mapping (0..31) as provided ----
$encMap = @{
  0  = 'Not defined - defaults to RC4_HMAC_MD5'
  1  = 'DES_CBC_CRC'
  2  = 'DES_CBC_MD5'
  3  = 'DES_CBC_CRC, DES_CBC_MD5'
  4  = 'RC4'
  5  = 'DES_CBC_CRC, RC4'
  6  = 'DES_CBC_MD5, RC4'
  7  = 'DES_CBC_CRC, DES_CBC_MD5, RC4'
  8  = 'AES 128'
  9  = 'DES_CBC_CRC, AES 128'
  10 = 'DES_CBC_MD5, AES 128'
  11 = 'DES_CBC_CRC, DES_CBC_MD5, AES 128'
  12 = 'RC4, AES 128'
  13 = 'DES_CBC_CRC, RC4, AES 128'
  14 = 'DES_CBC_MD5, RC4, AES 128'
  15 = 'DES_CBC_CRC, DES_CBC_MD5, RC4, AES 128'
  16 = 'AES 256'
  17 = 'DES_CBC_CRC, AES 256'
  18 = 'DES_CBC_MD5, AES 256'
  19 = 'DES_CBC_CRC, DES_CBC_MD5, AES 256'
  20 = 'RC4, AES 256'
  21 = 'DES_CBC_CRC, RC4, AES 256'
  22 = 'DES_CBC_MD5, RC4, AES 256'
  23 = 'DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256'
  24 = 'AES 128, AES 256'
  25 = 'DES_CBC_CRC, AES 128, AES 256'
  26 = 'DES_CBC_MD5, AES 128, AES 256'
  27 = 'DES_CBC_CRC, DES_CBC_MD5, AES 128, AES 256'
  28 = 'RC4, AES 128, AES 256'
  29 = 'DES_CBC_CRC, RC4, AES 128, AES 256'
  30 = 'DES_CBC_MD5, RC4, AES 128, AES 256'
  31 = 'DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96'
}

function Test-RC4SupportFromText {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $false }
  return ($s -match '(?i)\bRC4\b' -or $s -match '(?i)defaults?\s+to\s+RC4')
}

# ===== Scope: objects that can realistically participate in Kerberos with msDS-SupportedEncryptionTypes =====
# Users: only those with SPN (typical service accounts) OR you can remove the filter if you want all users.
$users = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties msDS-SupportedEncryptionTypes,servicePrincipalName |
  Select-Object SamAccountName, DistinguishedName, msDS-SupportedEncryptionTypes

# Computers: all domain-joined machines have Kerberos keys; this attribute is often set on computer objects too.
$computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName, DistinguishedName, msDS-SupportedEncryptionTypes

# gMSA (if you use them)
$gmsa = @()
try {
  $gmsa = Get-ADServiceAccount -Filter * -Properties msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName, DistinguishedName, msDS-SupportedEncryptionTypes
} catch {
  # If ADWS doesn't support it / no rights / no gMSA, ignore silently
}

$objects = @()
$objects += $users   | ForEach-Object { $_ | Add-Member -PassThru NoteProperty ObjectClass 'user' }
$objects += $computers | ForEach-Object { $_ | Add-Member -PassThru NoteProperty ObjectClass 'computer' }
$objects += $gmsa    | ForEach-Object { $_ | Add-Member -PassThru NoteProperty ObjectClass 'msDS-GroupManagedServiceAccount' }

# ---- Normalize configuration into parsed rows (no per-object spam) ----
# Important semantic: if msDS-SupportedEncryptionTypes is NOT SET / NULL -> treat as 0 (defaults to RC4)
$parsed = $objects | ForEach-Object {
  $raw = $_.'msDS-SupportedEncryptionTypes'
  if ($null -eq $raw) { $raw = 0 }
  $raw = [int]$raw

  $desc = $encMap[$raw]
  if (-not $desc) { $desc = 'UNKNOWN' }

  [pscustomobject]@{
    ObjectClass  = $_.ObjectClass
    Account      = $_.SamAccountName
    DN           = $_.DistinguishedName
    EncValueDec  = $raw
    EncValueHex  = ('0x{0:X}' -f $raw)
    EncTypes     = $desc
    RC4Supported = if (Test-RC4SupportFromText $desc) { 'YES' } else { 'NO' }
    IsUnset      = if ($_.msDS-SupportedEncryptionTypes -eq $null) { 'YES' } else { 'NO' }
  }
}

# ===== TABLE 1: EncValue -> how many UNIQUE accounts use it (CONFIG view) =====
$encByAccounts = $parsed |
  Group-Object EncValueDec |
  ForEach-Object {
    $dec   = [int]$_.Name
    $first = $_.Group | Select-Object -First 1
    [pscustomobject]@{
      EncValueDec     = $dec
      EncValueHex     = ('0x{0:X}' -f $dec)
      EncTypes        = $first.EncTypes
      RC4Supported    = $first.RC4Supported
      UniqueAccounts  = ($_.Group | Select-Object -Expand Account -Unique | Measure-Object).Count
      UnsetAttribute  = ($_.Group | Where-Object IsUnset -eq 'YES' | Measure-Object).Count
    }
  } |
  Sort-Object `
    @{Expression = { $_.RC4Supported -eq 'YES' }; Descending = $true}, `
    @{Expression = { $_.UniqueAccounts }; Descending = $true}, `
    @{Expression = { $_.UnsetAttribute }; Descending = $true}

$encByAccounts | Format-Table -AutoSize

# ===== TABLE 2: Which accounts use which EncValue (CONFIG view) =====
# One row per AD object (account) since this is configuration, not events.
$accountsByEnc = $parsed |
  Sort-Object `
    @{Expression = { $_.RC4Supported -eq 'YES' }; Descending = $true}, `
    @{Expression = { $_.EncValueDec }; Descending = $false}, `
    @{Expression = { $_.ObjectClass }; Descending = $false}, `
    @{Expression = { $_.Account }; Descending = $false} |
  Select-Object ObjectClass, Account, EncValueDec, EncValueHex, EncTypes, RC4Supported, IsUnset, DN

$accountsByEnc | Format-Table -AutoSize
