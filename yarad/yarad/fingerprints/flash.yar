rule flash_cws
{
	strings:
		$0 = "CWS"

	condition:
		$0 at 0
}
