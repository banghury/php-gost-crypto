<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostVerifyBlock')) {	
	$fn='1M';
	$cn='user';
	$content = file_get_contents($fn.'.dat');
	$b64Content = base64_encode($content);

	$b64ContentSign = file_get_contents($fn.'.sign');
	
	if ( $res=gostVerifyBlock ($b64Content, $b64ContentSign)) {
		echo 'OK';
		print_r($res);
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>