<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostSignBlock')) {	
	$fn='1M';
	$cn='user';
	$content = file_get_contents($fn.'.dat');
	$b64content = base64_encode($content);
	if ( $resOneSign=gostSignBlock($b64content, 'Максимов Сергей Вадимович', 0) ) {
		echo 'OK';
		if ( file_put_contents($fn.'.signAtt1', $resOneSign) )
			echo ' SAVED';
		else
			echo ' SAVE ERR';
	} else
		echo 'ERR:'.gostGetLastError();

	if ( $resTwoSign=gostSignBlock($resOneSign, 'Довереннов Петр Сергеевич', 0) ) {
		echo 'OK';
		if ( file_put_contents($fn.'.signAtt', $resTwoSign) )
			echo ' SAVED';
		else
			echo ' SAVE ERR';
	} else
		echo 'ERR:'.gostGetLastError();

} else
	echo 'Function not present.';
echo "\r\n";	
?>