# Strict schema v2. Dot-source to load validation and detection functions.
function ConvertTo-FailedLogonRecords {
    param([AllowEmptyCollection()][object[]]$Records = @())
    $seen = @{}
    $clean = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $Records) {
        if ($null -eq $record) { throw 'Null event record.' }
        foreach ($name in @('TimeUTC','RecordID','Computer','Channel','EventID','Domain','Account','SourceIP')) {
            if ($null -eq $record.PSObject.Properties[$name] -or
                [string]::IsNullOrWhiteSpace([string]$record.$name)) {
                throw "Missing required field: $name. Recollect legacy CSV with the v2 reader."
            }
        }
        $id = 0L
        if (-not [long]::TryParse([string]$record.RecordID, [ref]$id) -or $id -le 0) {
            throw 'RecordID must be a positive integer.'
        }
        if ([string]$record.EventID -ne '4625' -or [string]$record.Channel -ine 'Security') {
            throw 'Only Security EventID 4625 records are supported.'
        }
        if ($record.TimeUTC -is [datetimeoffset]) {
            $stamp = $record.TimeUTC.UtcDateTime
        } elseif ($record.TimeUTC -is [datetime]) {
            if ($record.TimeUTC.Kind -eq [DateTimeKind]::Unspecified) {
                throw 'Timestamp must include timezone information.'
            }
            $stamp = $record.TimeUTC.ToUniversalTime()
        } else {
            $text = [string]$record.TimeUTC
            if ($text -notmatch '^\d{4}-\d{2}-\d{2}T.+(Z|[+-]\d{2}:\d{2})$') {
                throw 'Timestamp must be ISO 8601 with explicit timezone.'
            }
            try {
                $stamp = [datetimeoffset]::Parse($text, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
            } catch { throw 'Invalid timestamp.' }
        }
        $ip = $null
        if (-not [Net.IPAddress]::TryParse(([string]$record.SourceIP).Trim(), [ref]$ip)) {
            throw 'SourceIP must be a valid IP address; missing local sources need separate analysis.'
        }
        $item = [pscustomobject]@{
            TimeUTC = $stamp.ToString('o')
            RecordID = $id
            Computer = ([string]$record.Computer).Trim()
            Channel = 'Security'
            EventID = 4625
            Domain = ([string]$record.Domain).Trim()
            Account = ([string]$record.Account).Trim()
            SourceIP = $ip.ToString()
            LogonType = [string]$record.LogonType
            Status = [string]$record.Status
            SubStatus = [string]$record.SubStatus
        }
        # Timestamp guards against record-ID reuse after log clear/reset.
        $identity = ConvertTo-Json -InputObject @(
            $item.Computer.ToLowerInvariant(), $item.Channel, $item.RecordID, $item.TimeUTC
        ) -Compress
        $payload = ConvertTo-Json -InputObject @(
            $item.Domain.ToLowerInvariant(), $item.Account.ToLowerInvariant(),
            $item.SourceIP, $item.LogonType, $item.Status.ToLowerInvariant(),
            $item.SubStatus.ToLowerInvariant()
        ) -Compress
        if ($seen.ContainsKey($identity)) {
            if ($seen[$identity] -ne $payload) { throw 'Conflicting duplicate event identity.' }
            continue
        }
        $seen[$identity] = $payload
        $clean.Add($item)
    }
    $clean | Sort-Object TimeUTC, Computer, RecordID
}

function Find-RepeatedFailures {
    param(
        [AllowEmptyCollection()][object[]]$Records = @(),
        [ValidateRange(2, 1000000)][int]$Threshold = 5,
        [ValidateRange(1, 10080)][int]$WindowMinutes = 5
    )
    $recordsClean = @(ConvertTo-FailedLogonRecords -Records $Records)
    $groups = @{}
    foreach ($record in $recordsClean) {
        $key = ConvertTo-Json -InputObject @(
            $record.Computer.ToLowerInvariant(), $record.Domain.ToLowerInvariant(),
            $record.Account.ToLowerInvariant(), $record.SourceIP
        ) -Compress
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = New-Object 'System.Collections.Generic.List[object]'
        }
        $groups[$key].Add($record)
    }
    foreach ($key in @($groups.Keys | Sort-Object)) {
        $ordered = $groups[$key]
        $end = 0
        for ($start = 0; $start -lt $ordered.Count; $start++) {
            $limit = ([datetimeoffset]$ordered[$start].TimeUTC).AddMinutes($WindowMinutes)
            if ($end -lt $start) { $end = $start }
            while ($end -lt $ordered.Count -and
                [datetimeoffset]$ordered[$end].TimeUTC -le $limit) { $end++ }
            if (($end - $start) -ge $Threshold) {
                $first = $ordered[$start]
                [pscustomobject]@{
                    Computer = $first.Computer
                    Domain = $first.Domain
                    Account = $first.Account
                    SourceIP = $first.SourceIP
                    Failures = $end - $start
                    FirstUTC = $first.TimeUTC
                    LastUTC = $ordered[$end - 1].TimeUTC
                    RecordIDs = @($ordered.GetRange($start, $end - $start) | ForEach-Object { $_.RecordID })
                }
                break
            }
        }
    }
}
