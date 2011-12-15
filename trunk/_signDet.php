<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostSignBlock')) {	
	$fn='1M';
	$cn='user';
	$content = file_get_contents($fn.'.dat');
	$b64content = base64_encode($content);
	file_put_contents($fn.'.b64', $b64content);
	if ( $res=gostSignBlock($b64content, 'Максимов Сергей Вадимович') ) {
		echo 'OK';
		if ( file_put_contents($fn.'.sign', $res) )
			echo ' SAVED';
		else
			echo ' SAVE ERR';
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>