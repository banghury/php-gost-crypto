<?php

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostDecryptFile')) {	
	$fn='99M';
	
	if ( $res=gostDecryptFile($fn.'.enc', $fn.'.dec') )
		echo 'OK';
	else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>