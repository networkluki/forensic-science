# Windows commands

Target: Windows 11 with Windows PowerShell 5.1 or PowerShell 7. `Get-WinEvent` requires Windows. Run these examples in PowerShell on an analysis host; the example files must already exist.

## File-content hash — working copy

```powershell
Get-FileHash -LiteralPath 'C:\Analysis\case-001\working\sample.bin' -Algorithm SHA256 -ErrorAction Stop
```

Compare the reported hash with the independently recorded acquisition hash. A match checks content consistency, not origin. Avoid files that are changing while being read.

## Filesystem metadata — working copy

```powershell
Get-Item -LiteralPath 'C:\Analysis\case-001\working\sample.bin' -Force -ErrorAction Stop |
    Select-Object -Property FullName, Length, Attributes, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc
```

This describes the working-copy filesystem, not necessarily the original file's metadata. `-Force` includes hidden items; it does not bypass access controls. Check for links/reparse points before interpreting the result. Read access may affect access timestamps depending on the filesystem and host settings.

## Copied event log — offline

```powershell
Get-WinEvent -Path 'C:\Analysis\case-001\working\System.evtx' -MaxEvents 200 -ErrorAction Stop |
    Select-Object -Property TimeCreated, Id, RecordId, ProviderName, LevelDisplayName, Message
```

This returns up to 200 newest records from the copied EVTX file. `-Path` supports wildcards; use a known filename without wildcard characters. `TimeCreated` is displayed using the analysis host's time context, so record that timezone. Message rendering can be unavailable when provider resources are missing. The selected fields are an analysis view; preserve the EVTX file separately.

## Local System log — live, last 24 hours

```powershell
$queryEnd = Get-Date
$queryStart = $queryEnd.AddHours(-24)
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    StartTime = $queryStart
    EndTime = $queryEnd
} -MaxEvents 200 -ErrorAction Stop |
    Select-Object -Property TimeCreated, Id, RecordId, ProviderName, LevelDisplayName, Message
```

Record `$queryStart`, `$queryEnd` and the host timezone with the output. This is a capped live query, not a complete collection. No matching events, inaccessible logs and other failures must be recorded and distinguished; do not interpret an error as a clean result. Begin without elevation and request only the access justified by the investigation.

## Verify available commands

```powershell
$PSVersionTable.PSVersion
Get-Command -Name Get-FileHash, Get-Item, Get-WinEvent -ErrorAction Stop
```

## Official references

- [Microsoft Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Microsoft Get-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item?view=powershell-5.1)
- [Microsoft Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)

Return to the [command index](../README.md).
