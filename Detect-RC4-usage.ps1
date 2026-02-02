# Two tables from 4769:
# 1) Encryption value observed + how many UNIQUE accounts use it + RC4 supported?
# 2) Which accounts use which encryption value (with translation + RC4 supported?)

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

$events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4769 }

$parsed = $events | ForEach-Object {
  $raw  = [int]$_.Properties[8].Value
  $desc = $encMap[$raw]
  if (-not $desc) { $desc = 'UNKNOWN' }

  [pscustomobject]@{
    TimeCreated  = $_.TimeCreated
    Account      = $_.Properties[0].Value
    Service      = $_.Properties[2].Value
    EncValueDec  = $raw
    EncValueHex  = ('0x{0:X}' -f $raw)
    EncTypes     = $desc
    RC4Supported = if (Test-RC4SupportFromText $desc) { 'YES' } else { 'NO' }
  }
}

# ===== TABLE 1: Encryption value -> how many UNIQUE accounts use it =====
$encByAccounts = $parsed |
  Group-Object EncValueDec |
  ForEach-Object {
    $dec   = [int]$_.Name
    $first = $_.Group | Select-Object -First 1
    [pscustomobject]@{
      EncValueDec    = $dec
      EncValueHex    = ('0x{0:X}' -f $dec)
      EncTypes       = $first.EncTypes
      RC4Supported   = $first.RC4Supported
      UniqueAccounts = ($_.Group | Select-Object -Expand Account -Unique | Measure-Object).Count
      Events         = $_.Count
    }
  } |
  Sort-Object `
    @{Expression = { $_.RC4Supported -eq 'YES' }; Descending = $true}, `
    @{Expression = { $_.UniqueAccounts }; Descending = $true}, `
    @{Expression = { $_.Events }; Descending = $true}

$encByAccounts | Format-Table -AutoSize

# ===== TABLE 2: Which accounts use which encryption value =====
$accountsByEnc = $parsed |
  Group-Object Account, EncValueDec |
  ForEach-Object {
    $first = $_.Group | Select-Object -First 1
    [pscustomobject]@{
      Account      = $first.Account
      EncValueDec  = $first.EncValueDec
      EncValueHex  = $first.EncValueHex
      EncTypes     = $first.EncTypes
      RC4Supported = $first.RC4Supported
      Events       = $_.Count
      LastSeen     = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
    }
  } |
  Sort-Object `
    @{Expression = { $_.RC4Supported -eq 'YES' }; Descending = $true}, `
    @{Expression = { $_.EncValueDec }; Descending = $false}, `
    @{Expression = { $_.Account }; Descending = $false}

$accountsByEnc | Format-Table -AutoSize
