$interfaces = Get-NetAdapter -Name * -Physical
$ULIGBits = 0, 4, 8, "C"

function genRandMAC {
	for($i = 0; $i -lt 12; $i++){
		if($i -eq 1){
			$MAC += "{0:X}" -f (Get-Random $ULIGBits)
		}
		else{
			$MAC += "{0:X}" -f (Get-Random -min 0 -max 16)
		}
	}
	return $MAC
}

foreach ($interface in $interfaces)
{
    do{
        $randMAC = genRandMAC
        Set-NetAdapter -Name $interface.Name -MacAddress $randMAC -Confirm:0
    } while($randMAC -eq $interface.MacAddress)

    if ($interface.MacAddress -eq (Get-NetAdapter -Name $interface.Name).MacAddress){
        throw
    }
    Write-Host -NoNewline (Get-NetAdapter -Name $interface.Name).MacAddress
}