<?php

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostEncryptFile')) {	
	$fn='99M';
	
// ������� ��� ���� �����������. �������� ���� ����� ������ �� ������� ����������� - �������� ������ ���������
	if ( $res=gostEncryptFile($fn.'.dat', $fn.'.enc', '�������� ������ ���������,e3fc21aa0bdec345b91dc50aa56434491f95fddd') ) { 
		echo 'OK';
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";	
?>