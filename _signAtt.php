<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostSignBlock')) {	
	$fn='1M';
	$cn='user';
	$content = file_get_contents($fn.'.dat');
	$b64content = base64_encode($content);
	if ( $res=gostSignBlock($b64content, 'Максимов Сергей Вадимович', 0) ) {
		echo 'OK';
		if ( file_put_contents($fn.'.signAtt', $res) )
			echo ' SAVED';
		else
			echo ' SAVE ERR';
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>