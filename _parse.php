
<?php
$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostParseCertificate')) {	
	$cn='077-001';
	$pflog = gostPathFileLog ('c:\PHP5\logfile.txt');
	echo $pflog;
	$content = file_get_contents($cn.'.cer');
	$b64content = base64_encode($content);
	file_put_contents($cn.'.cont', $b64content);
	if ( $res=gostParseCertificate( $b64content, 1 ) ) { 
		echo '$res';
		print_r ($res);
		
		$cn_value =  $res['name'];
		echo $cn_value;
		
		//$ext_value =  $res['extensions']['1.2.3.4.5.6'];
		//echo $ext_value;
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	

?>