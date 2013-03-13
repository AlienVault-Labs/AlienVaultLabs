rule APT_NGO_wuaclt
{
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
	$d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
	$e = "0l23kj@nboxu"
	
	$f = "%%s.asp?id=%%d&Sid=%%d"
	$g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
	$h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}
