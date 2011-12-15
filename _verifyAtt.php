<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostVerifyBlock')) {	
	$fn='1M';
	$cn='user';
	$content = file_get_contents($fn.'.signAtt');
	
	if ( $res=gostVerifyBlock ($content)) {
		echo 'OK';
		print_r($res);
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>