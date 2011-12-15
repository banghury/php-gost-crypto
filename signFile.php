<?php

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostSignFile')) {	
	$fn='1M';
	if ( $res=gostSignFile($fn.'.dat', $fn.'.sign', 'Максимов Сергей Вадимович') ) {
		echo 'OK';
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>