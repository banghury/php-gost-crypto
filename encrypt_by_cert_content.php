<?php

// gostEncryptBlockByCertContent (string $ sB64DataSrc,  string $ sB64CertContentRec)
// sB64DataSrc - ������ ��� ���������� �������������� � Base64. 
// sB64CertContentRec - ������ ����������� ������������ ����������� ����� ������ " ". 
// ��� ���������� ����� ���� �������� ���� ������� ����������� �� ������ sB64CertContentRec.
// ������������ ��������: 
// � ������ ������ - string ���������� ������������� ������ � ��������� Base64
// � ������ ������� - bool false. ������� ������ ����� ������ ������ ������� gostGetLastError()

$pflog = gostPathFileLog ('logfile.txt');
echo $pflog; 
echo "\r\n";

if (function_exists('gostEncryptBlockByCertContent')) echo 'IN: '.@$argv[1].' -> FUNC:'.gostEncryptBlockByCertContent(
'dGV4dCBmb3IgdGVzdA==', 
'MIIEoTCCBE6gAwIBAgIKSeGb5QABAAAS2TAKBgYqhQMCAgMFADCByDEbMBkGCSqG
SIb3DQEJARYMdWNAZ2FyYW50LnJ1MQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQ
vtGB0LrQstCwMTcwNQYDVQQKDC7QntCe0J4g0K3Qu9C10LrRgtGA0L7QvdC90YvQ
uSDRjdC60YHQv9GA0LXRgdGBMTAwLgYDVQQLDCfQo9C00L7RgdGC0L7QstC10YDR
j9GO0YnQuNC5INGG0LXQvdGC0YAxGjAYBgNVBAMMEdCj0KYg0JPQkNCg0JDQndCi
MB4XDTExMDYxMDA5MzgwMFoXDTEyMDYxMDA5NDgwMFowggF1MRIwEAYIKoUDA4EN
AQIMBDc3MTgxGDAWBggqhQMDgQ0BAQwKNzcxODA0MTM5NTE4MDYGA1UEDAwv0LTQ
vtCy0LXRgNC10L3QvdGL0Lkg0L/RgNC10LTRgdGC0LDQstC40YLQtdC70YwxOTA3
BgNVBAMMMNCU0L7QstC10YDQtdC90L3QvtCyINCf0LXRgtGAINCh0LXRgNCz0LXQ
tdCy0LjRhzEYMBYGCCqFAwOBAwEBDAo3NzI5NjMzMTMxMQowCAYDVQQLDAEwMUgw
RgYDVQQKDD/QotC10YHRgtC+0LLQvtC1INCe0J7QniDQrdC70LXQutGC0YDQvtC9
0L3Ri9C5INCt0LrRgdC/0YDQtdGB0YExGTAXBgNVBAcMENCzLiDQnNC+0YHQutCy
0LAxGDAWBgNVBAgMDzc3INCc0L7RgdC60LLQsDELMAkGA1UEBhMCUlUxHjAcBgkq
hkiG9w0BCQEWD2RvdmVyQG5vbWFpbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiQA
BgcqhQMCAh4BA0MABEAeW+qNy7Ks1QdpmZjVtbM2bF2XN25GHx8zXXtoDpTm9dF1
luNvQfqzz4ih6r9HA3aSPG5/TnXa1ANMrj5BVzjVo4IBZDCCAWAwDgYDVR0PAQH/
BAQDAgTwMCYGA1UdJQQfMB0GByqFAwICIgYGCCsGAQUFBwMEBggrBgEFBQcDAjAd
BgNVHQ4EFgQUpuR9Mvsc7tZcAnZU9VKi0RH5ukYwHwYDVR0jBBgwFoAU/bZWSZgh
bNMU2qboXcr5WTFQDKcwYQYDVR0fBFowWDBWoFSgUoYjaHR0cDovL2NhLmdhcmFu
dC5ydS9jZHAvZ2FyYW50Mi5jcmyGK2h0dHA6Ly93d3cuZ2FyYW50ZXhwcmVzcy5y
dS9jZHAvZ2FyYW50Mi5jcmwwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzAChiJo
dHRwOi8vY2EuZ2FyYW50LnJ1L2NhL2dhcmFudDIuY2VyMEMGA1UdIAQ8MDowDAYK
KoUDA4ECAgMEATAMBgoqhQMDgQICAwUBMAwGCiqFAwOBAgIDAwEwDgYMKoUDA4ED
iCsAAwMBMAoGBiqFAwICAwUAA0EAElKYGuPx7+v3KvKSEUThWiMoYXt+GP+rzEHW
WiOC7Avwjle7sCex79c1MYi16akyc9rNxzCY8r/WEiqQewxgxg== MIIEfzCCBCygAwIBAgIKEgjjegAAAABW2zAKBgYqhQMCAgMFADCBwDEeMBwGCSqG
SIb3DQEJARYPdWNpbmZvQGduaXZjLnJ1MQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM
0JzQvtGB0LrQstCwMTAwLgYDVQQKDCfQpNCT0KPQnyDQk9Cd0JjQktCmINCk0J3Q
oSDQoNC+0YHRgdC40LgxMDAuBgNVBAsMJ9Cj0LTQvtGB0YLQvtCy0LXRgNGP0Y7R
idC40Lkg0YbQtdC90YLRgDEWMBQGA1UEAxMNR05JVkMgRk5TIFJVUzAeFw0xMDEy
MjkxMzAxMDBaFw0xMTEyMjkxMzEwMDBaMIIBVDEYMBYGCCqFAwOBAwEBDAo3NzI5
NjMzMTMxMRswGQYJKoZIhvcNAQkBFgxlZUBnYXJhbnQucnUxCzAJBgNVBAYTAlJV
MRgwFgYDVQQIDA83NyDQnNC+0YHQutCy0LAxGTAXBgNVBAcMENCzLiDQnNC+0YHQ
utCy0LAxNzA1BgNVBAoMLtCe0J7QniDQrdC70LXQutGC0YDQvtC90L3Ri9C5INGN
0LrRgdC/0YDQtdGB0YExCjAIBgNVBAsMATAxOTA3BgNVBAMMMNCc0LDQutGB0LjQ
vNC+0LIg0KHQtdGA0LPQtdC5INCS0LDQtNC40LzQvtCy0LjRhzFZMFcGA1UEDAxQ
0KHQv9C10YbQuNCw0LvQuNGB0YIg0YLQtdGF0L3QuNGH0LXRgdC60L7QuSDQv9C+
0LTQtNC10YDQttC60Lgg0L7RgtC00LXQu9CwIOKEljYwYzAcBgYqhQMCAhMwEgYH
KoUDAgIkAAYHKoUDAgIeAQNDAARAPGv+0OR0lixpXOptXGKL61O+hx9bvslXlrYE
0AY9/NEKqyWmqNzLAbuY0Z0ITYHpNB0Ji2YN2HLDFzSGDx0e7KOCAWswggFnMA4G
A1UdDwEB/wQEAwIE8DAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYD
VR0OBBYEFA4ggY6LmPoQFp/E2WGyzRVv2SzrMB8GA1UdIwQYMBaAFBMQt5JPv+ei
D7j1nYkVJssQ6/RfMGIGA1UdHwRbMFkwV6BVoFOGJmh0dHA6Ly93d3cuZ25pdmMu
cnUvdWMvR05JVkNGTlNSVVMuY3JshilodHRwOi8vYzAwMDAtYXBwMDA1L2duaXZj
L0dOSVZDRk5TUlVTLmNybDB5BggrBgEFBQcBAQRtMGswMgYIKwYBBQUHMAKGJmh0
dHA6Ly93d3cuZ25pdmMucnUvdWMvR05JVkNGTlNSVVMuY3J0MDUGCCsGAQUFBzAC
hilodHRwOi8vYzAwMDAtYXBwMDA1L2duaXZjL0dOSVZDRk5TUlVTLmNydDAXBgNV
HSAEEDAOMAwGCiqFAwOBA4doAAIwCgYGKoUDAgIDBQADQQD+2ePH3z64gVFITIrb
ogFR5e5v1X+3yzpOTE1lGmulAnPzHwfyNNYyk41UxoJnNtvu12Pqr2j/Mn8f6cK+
O2hA MIIEUzCCBACgAwIBAgIKd5a7hQAAAABVOjAKBgYqhQMCAgMFADCBwDEeMBwGCSqGSIb3DQEJARYPdWNpbmZvQGduaXZjLnJ1MQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMTAwLgYDVQQKDCfQpNCT0KPQnyDQk9Cd0JjQktCmINCk0J3QoSDQoNC+0YHRgdC40LgxMDAuBgNVBAsMJ9Cj0LTQvtGB0YLQvtCy0LXRgNGP0Y7RidC40Lkg0YbQtdC90YLRgDEWMBQGA1UEAxMNR05JVkMgRk5TIFJVUzAeFw0xMDEyMDIxNTQ5MDBaFw0xMTEyMDIxNTU4MDBaMIIBKDEYMBYGCCqFAwOBAwEBDAo3NzI5NjMzMTMxMRswGQYJKoZIhvcNAQkBFgxlZUBnYXJhbnQucnUxCzAJBgNVBAYTAlJVMRgwFgYDVQQIDA83NyDQnNC+0YHQutCy0LAxGTAXBgNVBAcMENCzLiDQnNC+0YHQutCy0LAxNzA1BgNVBAoMLtCe0J7QniDQrdC70LXQutGC0YDQvtC90L3Ri9C5INGN0LrRgdC/0YDQtdGB0YExCjAIBgNVBAsMATAxMzAxBgNVBAMMKtCf0LDQstC70L7QsiDQndC40LrQvtC70LDQuSDQrtGA0YzQtdCy0LjRhzEzMDEGA1UEDAwq0KDRg9C60L7QstC+0LTQuNGC0LXQu9GMINC+0YLQtNC10LvQsCDihJY2MGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgEDQwAEQF+DJFagIAbP8oBsGdmcvPMFCvpA3K4M1wQpdQdoxKtXLc5iejgwCDG5iQjBcpsK8Fgxf/4X/1Htbdy0q42aeIijggFrMIIBZzAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMB0GA1UdDgQWBBRXvDjCtFCuO+OQWEylyDkgb3fNpzAfBgNVHSMEGDAWgBQTELeST7/nog+49Z2JFSbLEOv0XzBiBgNVHR8EWzBZMFegVaBThiZodHRwOi8vd3d3LmduaXZjLnJ1L3VjL0dOSVZDRk5TUlVTLmNybIYpaHR0cDovL2MwMDAwLWFwcDAwNS9nbml2Yy9HTklWQ0ZOU1JVUy5jcmwweQYIKwYBBQUHAQEEbTBrMDIGCCsGAQUFBzAChiZodHRwOi8vd3d3LmduaXZjLnJ1L3VjL0dOSVZDRk5TUlVTLmNydDA1BggrBgEFBQcwAoYpaHR0cDovL2MwMDAwLWFwcDAwNS9nbml2Yy9HTklWQ0ZOU1JVUy5jcnQwFwYDVR0gBBAwDjAMBgoqhQMDgQOHaAACMAoGBiqFAwICAwUAA0EAwDbfXdaL2lUI/AsuSUo1z8BDVIBUvaFxN70vkJmxjhpWBoZOSIOMWKQ6egOZZfPm+YnDgbBhwDq1STpC+4yjAQ=='
).'.';
else
	echo 'Func not found!';

echo "\nLastError: ".gostGetLastError()."\n";
?>