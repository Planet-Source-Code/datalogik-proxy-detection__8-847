<div align="center">

## Proxy Detection


</div>

### Description

This will detect any suspicious open socket that the user is running and if found in an array, it will not let the user proceed to the website, with the ability to allow certain hosts to pass the scan, and disallowing certain hosts completely. You can define a redirect page to redirect the user to upon open socket.
 
### More Info
 


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[datalogik](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/datalogik.md)
**Level**          |Intermediate
**User Rating**    |3.7 (11 globes from 3 users)
**Compatibility**  |PHP 3\.0, PHP 4\.0
**Category**       |[Security](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/security__8-14.md)
**World**          |[PHP](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/php.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/datalogik-proxy-detection__8-847/archive/master.zip)





### Source Code

```
<?php
	/*
	Title:
	 Proxy Detection
	Version:
	 v2.0
	Description:
	 This will detect any suspicious open socket
	 that the user is running and if found in an
	 array, it will not let the user proceed to
	 the website, and the ability to allow certain
	 hosts to pass the scan.
	Author:
	 Jonathan Anders
	 datalogik@datalogik.org
	 http://www.datalogik.org
	Usage:
	 Just include this page in any webpage you want protected.
	Notes:
	 If you like this code and use it, I would like to inform you of a much larger
	 project that I am working on named 'phpPPS - Protection Suite' which uses the
	 same concept but in a much larger, multiple-user oriented way.
	*/
	/* Modify these next few lines to whatever you like. */
	$Ports = array('1080', '8080', '8000', '3128', '8888', '23', '80', '8081'); 	// To hold the list of ports.
	$AllowedHosts = array('localhost', 'allowedhost.com'); 				// To hold the list of allowed hosts.
	$DisallowedHosts = array('127.0.0.1.poo.com', 'something.msn.com'); 		// To hold the list of disallowed hosts.
	$Redirect = "http://www.unixcon.net/~datalogik/scripts/";			// Redirect page
	$SocketTimeout = 1;								// Higher the number, the longer it takes.
	/* End of modification. */
	if ((!in_array ($REMOTE_ADDR, $AllowedHosts)) && (!in_array ($REMOTE_ADDR, $DisallowedHosts)))
	{
		$x = 0;
		while ($Ports[$x])
		{
			$fSockPointer = fsockopen($REMOTE_ADDR, $Ports[$x], $errno, $errstr, $SocketTimeout);
			if ($fSockPointer)
			{
				header ("Location: $Redirect");
				fclose($fSockPointer);
			}
			$x++;
		}
	} else {
		if (in_array ($REMOTE_ADDR, $AllowedHosts))
		{
			die();
		} else {
			header ("Location: $Redirect");
			die();
		}
	}
?>
```

