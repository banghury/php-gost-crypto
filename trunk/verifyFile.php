<?php

/* 
gostVerifyBlock  ( string $sB64Data, string $ sB64Sign = "")
// sB64Data - ������ ��� �������� ������� �������������� � Base64. ���� ��� ������ �������� � ���� �������, �� ��������� �������� sB64Sign ������ ���� ����� ������ ������. 
// sB64Sign - �������� �������. ���� sB64Data �������� � ���� �������, �� sB64Sign = ""
// ������������ ��������: 
// � ������ ������� - bool false. ������� ������ ����� ������ ������ ������� gostGetLastError()
// � ������ ������ - string � ������� xml ���������� �������� �������� ���������� ����������� �������. ��������:
<?xml version="1.0" encoding="windows-1251"?>
<Sign>
<Subject>OID.1.2.643.3.131.1.1=7729633131, E=ee@garant.ru, C=RU, S=77 ������, L=�. ������, O=��� ����������� ��������, OU=0, CN=�������� ������ ���������, T=���������� ����������� ��������� ������ �6</Subject>
<DateTimeSign>09.11.2011 16:36:05</DateTimeSign>
<Thumb>29d95ebe67a0bcbdc0f80e25f402e1be6114520b</Thumb>
<OID>1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.131.1000.0.2</OID>
</Sign>
<Sign>
<Subject>OID.1.2.643.3.131.1.1=7729633131, E=ee@garant.ru, C=RU, S=77 ������, L=�. ������, O=��� ����������� ��������, OU=0, CN=������ ������� �������, T=������������ ������ �6</Subject>
<DateTimeSign>17.11.2011 09:47:00</DateTimeSign>
<Thumb>4639d5c0551562fdb4e6079c739ace77ed4a3fb6</Thumb>
<OID>1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.131.1000.0.2</OID>
</Sign>
<Sign>
<Subject>OID.1.2.643.3.141.1.2=7718, OID.1.2.643.3.141.1.1=7718041395, T=���������� �������������, CN=���������� ���� ���������, OID.1.2.643.3.131.1.1=7729633131, OU=0, O=�������� ��� ����������� ��������, L=�. ������, S=77 ������, C=RU, E=dover@nomail.ru</Subject>
<DateTimeSign>17.11.2011 09:39:27</DateTimeSign>
<Thumb>e3fc21aa0bdec345b91dc50aa56434491f95fddd</Thumb>
<OID>1.2.643.2.2.34.6 1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.130.2.3.4.1 1.2.643.3.130.2.3.5.1 1.2.643.3.130.2.3.3.1 1.2.643.3.131.1067.0.3.3.1</OID>
</Sign>
*/

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostVerifyFile')) {	
	$fn='1M';
	if ( $res=gostVerifyFile($fn.'.dat', $fn.'.sign') ) {
		echo $res;
	} else
		echo 'ERR:'.gostGetLastError();
} else
	echo 'Function not present.';
echo "\r\n";
?>
?>