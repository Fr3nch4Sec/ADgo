# pkg/rpc/enum_rpc.ps1
Write-Output "Enumerating RPC services..."
Get-Service | Where-Object {$_.DisplayName -like "*RPC*"} | Format-Table -AutoSize
