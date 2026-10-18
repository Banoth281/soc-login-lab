# Run in elevated Windows PowerShell. Reads logs; does not change audit policy.
param(
    [ValidateRange(1, 720)][int]$Hours = 1,
    [string]$Account = 'SOC_Lab_Test_User'
)
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-$Hours)
} -ErrorAction Stop
foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $fields[$item.Name] = [string]$item.'#text'
    }
    if ($fields['TargetUserName'] -eq $Account) {
        [pscustomobject]@{
            TimeUTC = $event.TimeCreated.ToUniversalTime().ToString('o')
            RecordID = $event.RecordId
            Account = $fields['TargetUserName']
            SourceIP = $fields['IpAddress']
            LogonType = $fields['LogonType']
            Status = $fields['Status']
            SubStatus = $fields['SubStatus']
        }
    }
}
