<?php

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostEncryptFile')) {	
	$fn='99M';
	
// шифруем для двух получателей. Закрытый ключ будет выбран из первого сертификата - Максимов Сергей Вадимович
	if ( $res=gostEncryptFile($fn.'.dat', $fn.'.enc', 'Максимов Сергей Вадимович,e3fc21aa0bdec345b91dc50aa56434491f95fddd') ) { 
		echo 'OK';
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>