function Find-RepeatedFailures {
    param(
        [object[]]$Records,
        [int]$Threshold = 5,
        [int]$WindowMinutes = 5
    )
    $Records | Group-Object Account, SourceIP | ForEach-Object {
        $ordered = @($_.Group | Sort-Object { [datetime]$_.TimeUTC })
        for ($i = 0; $i -lt $ordered.Count; $i++) {
            $windowStart = [datetime]$ordered[$i].TimeUTC
            $windowEnd = $windowStart.AddMinutes($WindowMinutes)
            $matches = @($ordered | Where-Object {
                ([datetime]$_.TimeUTC -ge $windowStart) -and
                ([datetime]$_.TimeUTC -le $windowEnd)
            })
            if ($matches.Count -ge $Threshold) {
                [pscustomobject]@{
                    Account = $ordered[$i].Account
                    SourceIP = $ordered[$i].SourceIP
                    Failures = $matches.Count
                    FirstUTC = $windowStart.ToString('o')
                    LastUTC = ([datetime]$matches[-1].TimeUTC).ToString('o')
                }
                break
            }
        }
    }
}
