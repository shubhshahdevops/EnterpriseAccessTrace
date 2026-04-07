param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$TargetsCsv = "",

    [switch]$IncludeRoot,
    [switch]$RunDriftAnalysis
)

$Targets = @()
if (-not [string]::IsNullOrWhiteSpace($TargetsCsv)) {
    $Targets = $TargetsCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
}

$ErrorActionPreference = "Stop"

function Ensure-OutputFolder {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Safe-GetAcl {
    param([string]$Path)
    try {
        return Get-Acl -Path $Path
    } catch {
        return $null
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )
    $Data | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

Ensure-OutputFolder -Path $OutputPath

$aclRecords = @()
$accessPaths = @()
$driftFindings = @()
$logs = New-Object System.Collections.Generic.List[string]

$items = @()

if ($IncludeRoot) {
    if (Test-Path $RootPath) {
        $rootItem = Get-Item $RootPath -Force
        $items += $rootItem
    }
}

if (Test-Path $RootPath) {
    $items += Get-ChildItem -Path $RootPath -Recurse -Force -ErrorAction SilentlyContinue
} else {
    throw "RootPath does not exist: $RootPath"
}

foreach ($item in $items) {
    $logs.Add("Scanning: $($item.FullName)")
    $acl = Safe-GetAcl -Path $item.FullName

    if ($null -eq $acl) {
        $logs.Add("Failed to read ACL: $($item.FullName)")
        continue
    }

    foreach ($access in $acl.Access) {
        $record = [PSCustomObject]@{
            Path             = $item.FullName
            ItemType         = if ($item.PSIsContainer) { "Folder" } else { "File" }
            Identity         = [string]$access.IdentityReference
            Rights           = [string]$access.FileSystemRights
            AccessType       = [string]$access.AccessControlType
            Inherited        = [bool]$access.IsInherited
            InheritanceFlags = [string]$access.InheritanceFlags
            PropagationFlags = [string]$access.PropagationFlags
        }

        $aclRecords += $record

        if ($Targets.Count -gt 0) {
            $identityText = [string]$access.IdentityReference
            foreach ($target in $Targets) {
                $targetLower = $target.ToLower()
                $identityLower = $identityText.ToLower()

                if (
                    $identityLower -eq $targetLower -or
                    $identityLower -like "*\$targetLower" -or
                    $identityLower -like "*$targetLower*"
                ) {
                    $accessPaths += [PSCustomObject]@{
                        Target        = $target
                        Path          = $item.FullName
                        IdentityMatch = $identityText
                        Rights        = [string]$access.FileSystemRights
                        AccessType    = [string]$access.AccessControlType
                        Reason        = "Matched target against ACL identity in scanned scope"
                    }
                }
            }
        }
    }
}

if ($RunDriftAnalysis) {
    $grouped = $aclRecords | Group-Object Path

    foreach ($group in $grouped) {
        $broadAccess = $group.Group | Where-Object {
            $_.Identity -match "Everyone|Users|Authenticated Users"
        }

        if ($broadAccess.Count -gt 0) {
            $driftFindings += [PSCustomObject]@{
                Severity    = "Medium"
                Category    = "Broad Access"
                Path        = $group.Name
                Description = "Broad access identity found on this path"
            }
        }
    }
}

$summary = [PSCustomObject]@{
    RootPath           = $RootPath
    ScanTimeUtc        = (Get-Date).ToUniversalTime().ToString("o")
    TotalAclRecords    = $aclRecords.Count
    TotalAccessPaths   = $accessPaths.Count
    TotalDriftFindings = $driftFindings.Count
    Targets            = $Targets
}

$aclCsv = Join-Path $OutputPath "acl_records.csv"
$aclJson = Join-Path $OutputPath "acl_records.json"
$accessCsv = Join-Path $OutputPath "access_paths.csv"
$accessJson = Join-Path $OutputPath "access_paths.json"
$driftJson = Join-Path $OutputPath "drift_findings.json"
$summaryJson = Join-Path $OutputPath "summary.json"
$logsTxt = Join-Path $OutputPath "logs.txt"

$aclRecords | Export-Csv -Path $aclCsv -NoTypeInformation -Encoding UTF8
Write-JsonFile -Path $aclJson -Data $aclRecords

$accessPaths | Export-Csv -Path $accessCsv -NoTypeInformation -Encoding UTF8
Write-JsonFile -Path $accessJson -Data $accessPaths

Write-JsonFile -Path $driftJson -Data $driftFindings
Write-JsonFile -Path $summaryJson -Data $summary

$logs | Set-Content -Path $logsTxt -Encoding UTF8

Write-Host "Scan complete. Results saved to $OutputPath"