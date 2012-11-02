
rule sandboxdetect_misc : sandboxdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Sandbox detection tricks"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		// CWSandbox
		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}

