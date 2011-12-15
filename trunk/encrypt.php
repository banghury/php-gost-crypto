<?php

// gostEncryptBlock  (string $sB64DataSrc, string $ sIDCerts)
// sB64DataSrc - данные для шифрования закодированные в Base64. 
// sIDCerts - список сертификатов (CN или Thumb) получателей через символ ",". 
// При шифровании будет взят закрытый ключ первого сертификата из списка sIDCerts.
// возвращаемые значения: 
// В случае успеха - string содержащая зашифрованные данные в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";
	
if (function_exists('gostEncryptBlock')) echo 'IN: '.@$argv[1].' -> FUNC:'.gostEncryptBlock(
'dGV4dCBmb3IgdGVzdA==', 
'29d95ebe67a0bcbdc0f80e25f402e1be6114520b,Довереннов Петр Сергеевич').'.';
else
	echo 'Func not found!';
	
echo "\nLastError: ".gostGetLastError()."\n";
?>