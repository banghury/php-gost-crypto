<?php

// gostEncryptBlock  (string $sB64DataSrc, string $ sIDCerts)
// sB64DataSrc - ������ ��� ���������� �������������� � Base64. 
// sIDCerts - ������ ������������ (CN ��� Thumb) ����������� ����� ������ ",". 
// ��� ���������� ����� ���� �������� ���� ������� ����������� �� ������ sIDCerts.
// ������������ ��������: 
// � ������ ������ - string ���������� ������������� ������ � ��������� Base64
// � ������ ������� - bool false. ������� ������ ����� ������ ������ ������� gostGetLastError()

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";
	
if (function_exists('gostEncryptBlock')) echo 'IN: '.@$argv[1].' -> FUNC:'.gostEncryptBlock(
'dGV4dCBmb3IgdGVzdA==', 
'29d95ebe67a0bcbdc0f80e25f402e1be6114520b,���������� ���� ���������').'.';
else
	echo 'Func not found!';
	
echo "\nLastError: ".gostGetLastError()."\n";
?>