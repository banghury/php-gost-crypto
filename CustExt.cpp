#include "stdafx.h"
# include <afx.h>
#include "zend_config.w32.h" 

// Важно!!! 
// В файле config.w32.h (в директории php) необходимо закомментировать строку: #define _USE_32BIT_TIME_T

#include <php.h>
#include <WinCrypt.h>
#include "PHPCrypto.h"

ZEND_FUNCTION(DoubleUp);

ZEND_FUNCTION(gostSignBlock);
ZEND_FUNCTION(gostVerifyBlock);
ZEND_FUNCTION(gostEncryptBlock);
ZEND_FUNCTION(gostEncryptBlockByCertContent);
ZEND_FUNCTION(gostDecryptBlock);
ZEND_FUNCTION(gostParseCertificate);
ZEND_FUNCTION(gostGetLastError);
ZEND_FUNCTION(gostSignFile);
ZEND_FUNCTION(gostVerifyFile);
ZEND_FUNCTION(gostEncryptFile);
ZEND_FUNCTION(gostEncryptFileByCertContent);
ZEND_FUNCTION(gostDecryptFile);
ZEND_FUNCTION(gostPathFileLog);

/* compiled function list so Zend knows what's in this module */
zend_function_entry CustomExtModule_functions[] = {
	ZEND_FE(DoubleUp, NULL)

	ZEND_FE(gostSignBlock,	NULL)
    ZEND_FE(gostVerifyBlock, NULL)
    ZEND_FE(gostEncryptBlock, NULL)
    ZEND_FE(gostEncryptBlockByCertContent, NULL)	
	ZEND_FE(gostDecryptBlock, NULL)
	ZEND_FE(gostSignFile,	NULL)
    ZEND_FE(gostVerifyFile, NULL)
    ZEND_FE(gostEncryptFile, NULL)
    ZEND_FE(gostEncryptFileByCertContent, NULL)	
	ZEND_FE(gostDecryptFile, NULL)
    ZEND_FE(gostParseCertificate, NULL)    
    ZEND_FE(gostGetLastError, NULL)
    ZEND_FE(gostPathFileLog, NULL)	
    
    {NULL, NULL, NULL},
};

/* compiled module information */
zend_module_entry CustomExtModule_module_entry = {
    STANDARD_MODULE_HEADER,
    "CustomExt Module",
    CustomExtModule_functions,
    NULL, NULL, NULL, NULL, NULL,
    NO_VERSION_YET, STANDARD_MODULE_PROPERTIES
};

/* implement standard "stub" routine to introduce ourselves to Zend */
ZEND_GET_MODULE(CustomExtModule)

/* DoubleUp function */
/* This method takes 1 parameter, a long value, returns
   the value multiplied by 2 */
ZEND_FUNCTION(DoubleUp){
    long theValue = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &theValue) == FAILURE)
        RETURN_STRING("Bad parameters!", true);
    theValue *= 2;
    RETURN_LONG(theValue);
}

BOOL InitPhpString (char *ptrData, DWORD dwDataSize, CString& sResult)
{
	char* ptrDst = new char [dwDataSize + 1];
	if (ptrDst == NULL || ptrData == NULL || !strncpy (ptrDst, ptrData, dwDataSize))
		return FALSE;

	*(ptrDst + dwDataSize) = '\0';
	sResult = ptrDst;
	return TRUE;
}


static CString g_sPFLog;	// global var contenting PathFileLog
static CString g_sLastError; // global var contenting LastError
/*
gostGetLastError()
// возвращаемые значения: 
// string - описание последней ошибки на англ.языке
*/
ZEND_FUNCTION(gostGetLastError)
{
	RETURN_STRING ((LPTSTR)(LPCTSTR)g_sLastError, true);
}

/* gostPathFileLog
// sPathFileLog - путь к файлу журнала работы. Если значение пусто, то возвращается имеющееся значение.
// возвращаемые значения: 
// string - путь к файлу журнала работы.
*/

ZEND_FUNCTION(gostPathFileLog)
{
	char *cPFLog = NULL;
	DWORD dwPFLog = 0;
	try {
		if (ZEND_NUM_ARGS() == 1)
		{
			if (zend_parse_parameters (ZEND_NUM_ARGS() TSRMLS_CC, "s", &cPFLog, &dwPFLog) == FAILURE)
				throw (CString)"Bad param in call gostPathFileLog.";
		} else
			throw (CString)"Bad number param in call gostPathFileLog.";
		
		if (dwPFLog == 0)
			RETURN_STRING ((LPTSTR)(LPCTSTR)g_sPFLog, true);

		CString sPFLog;
		if (!InitPhpString (cPFLog, dwPFLog, sPFLog))
			throw (CString)"gostPathFileLog not read param sPathFileLog.";
		
		if (!CFileMng::IsFileExist (sPFLog) && !CStringProc::fWrite (sPFLog, "")) 
			throw (CString)"gostPathFileLog pathfile is not correct : " + sPFLog;

		g_sPFLog = sPFLog;
		RETURN_STRING ((LPTSTR)(LPCTSTR)g_sPFLog, true);
	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostPathFileLog : Unkown error";	}

	RETURN_LONG (FALSE);
}

/* 
gostParseCertificate (string $ sB64CertContent)
// sB64CertContent - бинарное содержимое сертификата в кодировке Base64
// возвращаемые значения: 
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
// В случае успеха - string содержащая ключевые параметры сертификата в следующем xml формате:
<Certificate>
<Type>DER (or ASN)</Type> - формат сертификата DER или ASN
<OID>1.2.643.3.131.1.1</OID>
<Thumb>29d95ebe67a0bcbdc0f80e25f402e1be6114520b</Thumb>
<CN>Максимов Сергей Вадимович</CN>
<Subject>E=ee@garant.ru, C=RU, S=77 Москва, L=г. Москва, O=ООО Электронный экспресс, OU=0, CN=Максимов Сергей Вадимович, T=Специалист технической поддержки отдела №6</Subject>	
<Issue>ГНИВЦ</Issue>
<ValidFrom>28.10.2011 08:53:27</ValidFrom>
<ValidTo>28.10.2012 08:53:27</ValidTo>
</Certificate>
*/

ZEND_FUNCTION(gostParseCertificate)
{
	char *cB64Data = NULL;
	DWORD dwB64Data = 0;
	long bXmlRes = FALSE;
	try {
		if (ZEND_NUM_ARGS() == 1)
		{
			if (zend_parse_parameters (ZEND_NUM_ARGS() TSRMLS_CC, "s", &cB64Data, &dwB64Data) == FAILURE)
				throw (CString)"Bad param in call gostParseCertificate.";
		} else if (ZEND_NUM_ARGS() == 2)
		{
			if (zend_parse_parameters (ZEND_NUM_ARGS() TSRMLS_CC, "sl", &cB64Data, &dwB64Data,
					&bXmlRes) == FAILURE)
				throw (CString)"Bad param in call gostParseCertificate.";
		}	else 
			throw (CString)"Bad number param in call gostParseCertificate.";
	
		CString sB64Data, sXmlCert;
		if (!InitPhpString (cB64Data, dwB64Data, sB64Data))
			throw (CString)"gostParseCertificate not read param sB64CertContent.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.ParseCertificate (sB64Data, sXmlCert))
		{	
			if (bXmlRes)
				RETURN_STRING ((LPTSTR)(LPCTSTR)sXmlCert, true);
/*
			zval* sub_array1; //_subject;
			zval* sub_array2;
			array_init (return_value);

			CString str = _T("name");
			CString strRes = _T("name_result");
			add_assoc_string (return_value, (LPSTR)(LPCSTR)str, (LPSTR)(LPCSTR)strRes, 1);
			
			MAKE_STD_ZVAL (sub_array1);
			array_init (sub_array1);
			CString sSubject = _T("subject");
			CString sValue = _T("Electronic Express");
			CString sOU = _T("OU");
			add_assoc_string (sub_array1, (LPSTR)(LPCSTR)sOU, (LPSTR)(LPCSTR)sValue, 1);
			// add_next_index_zval (return_value, sub_array1);
			add_assoc_zval (return_value, (LPSTR)(LPCSTR)sSubject, sub_array1);
//				add_next_index_string (return_value, (LPSTR)(LPCSTR)str, 1);
*/

// create array for comfortable parsing
			zval* sub_array_subject;
			zval* sub_array_issuer;
			zval* sub_array_ext;
			array_init (return_value);
// Name
			CString sName = _T("name");
			CString sSubjValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_SUBJECT);
			CStringArrayEx saSubjects;
			saSubjects.FillFromString (sSubjValue, ", ");
			sSubjValue = saSubjects.GetAsString ("/", FALSE);
			if (!sSubjValue.IsEmpty ())
				add_assoc_string (return_value, (LPSTR)(LPCSTR)sName, (LPSTR)(LPCSTR)sSubjValue, 1);

// Subject
			MAKE_STD_ZVAL (sub_array_subject);
			array_init (sub_array_subject);
			FOR_ALL_CONST_STR (pStrSubject, saSubjects)
			{
				CString sSubjectField = CStringProc::GetStrBefore (*pStrSubject, '=');
				CString sSubjectValue = CStringProc::GetStrAfter (*pStrSubject, '=');
				add_assoc_string (sub_array_subject, (LPSTR)(LPCSTR)sSubjectField, (LPSTR)(LPCSTR)sSubjectValue, 1);
			}
			CString sSubject = _T("subject");
			add_assoc_zval (return_value, (LPSTR)(LPCSTR)sSubject, sub_array_subject);

// Issuer
			CString sIssuerValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_ISSUER);
			CStringArrayEx saIssuer;
			saIssuer.FillFromString (sIssuerValue, ", ");
			MAKE_STD_ZVAL (sub_array_issuer);
			array_init (sub_array_issuer);
			FOR_ALL_CONST_STR (pStrIssuer, saIssuer)
			{
				CString sIssuerField = CStringProc::GetStrBefore (*pStrIssuer, '=');
				CString sIssuerValue = CStringProc::GetStrAfter (*pStrIssuer, '=');
				add_assoc_string (sub_array_issuer, (LPSTR)(LPCSTR)sIssuerField, (LPSTR)(LPCSTR)sIssuerValue, 1);
			}
			CString sIssuer = _T("issuer");
			add_assoc_zval (return_value, (LPSTR)(LPCSTR)sIssuer, sub_array_issuer);

// extension
			CString sExtValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_EXTENSION);
			CStringArrayEx saExtension (sExtValue, ' ');
			MAKE_STD_ZVAL (sub_array_ext);
			array_init (sub_array_ext);
			FOR_ALL_CONST_STR (pStrExt, saExtension)
			{
				CString sExtField = CStringProc::GetStrBefore (*pStrExt, '=');
				CString sExtValue = CStringProc::GetStrAfter (*pStrExt, '=');
				if (!sExtValue.IsEmpty ())
					add_assoc_string (sub_array_ext, (LPSTR)(LPCSTR)sExtField, (LPSTR)(LPCSTR)sExtValue, 1);
			}
			CString sExtensions = _T("extensions");
			if (saExtension.GetSize () > 0)
				add_assoc_zval (return_value, (LPSTR)(LPCSTR)sExtensions, sub_array_ext);

//   [version] => 2
			CString sVersion = _T("version");
			CString sVersionValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_CERT_VERSION);
			DWORD nVersion = 0;
			if (!sVersionValue.IsEmpty() && 1 == sscanf ((LPCSTR)sVersionValue + 1, "%u", &nVersion)) // parse from "V3"
				add_assoc_long (return_value, (LPSTR)(LPCSTR)sVersion, --nVersion, 1);

//    [serialNumber] => 1
			CString sSerial = _T("serialNumber");
			CString sSerialValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_SERIAL_NUMBER);
			if (!sSerialValue.IsEmpty ())
				add_assoc_string (return_value, (LPSTR)(LPCSTR)sSerial, (LPSTR)(LPCSTR)sSerialValue, 1);

//    [validFrom_time_t] => 1259051018
			CString sValidFrom = _T("validFrom_time_t");
			CString sValidFromValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_CERT_NOT_BEFORE_LTIME);
			DWORD nTimeTFrom = 0;
			if (!sValidFromValue.IsEmpty() && 1 == sscanf ((LPCSTR)sValidFromValue, "%u", &nTimeTFrom))
				add_assoc_long (return_value, (LPSTR)(LPCSTR)sValidFrom, nTimeTFrom, 1);

//    [validTo_time_t] => 1290587018
			CString sValidTo = _T("validTo_time_t");
			CString sValidToValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_CERT_NOT_AFTER_LTIME);
			DWORD nTimeTTo = 0;
			if (!sValidToValue.IsEmpty() && 1 == sscanf ((LPCSTR)sValidToValue, "%u", &nTimeTTo))
				add_assoc_long (return_value, (LPSTR)(LPCSTR)sValidTo, nTimeTTo, 1);

//    [thumb]
			CString sThumb = _T("thumb");
			CString sThumbValue = CStringProc::GetTagValue (sXmlCert, STR_TAG_THUMB);
			if (!sThumbValue.IsEmpty ())
				add_assoc_string (return_value, (LPSTR)(LPCSTR)sThumb, (LPSTR)(LPCSTR)sThumbValue, 1);

		}	else	{
			throw (CString)"gostParseCertificate : " + phpCrypto.GetLastError ();
		}
	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostSignBlock : Unkown error";	}
	
	if (bXmlRes)
		RETURN_LONG (FALSE);
}

/*
gostSignBlock  ( string $sB64Data, string $ sIDCert, long bSignDetached = 1 );
// sB64Data - данные для подписи закодированные в Base64
// sIDCert - ИД сертификата подписи (CN или Thumb)
// bSignDetached - (1 - подпись откреплена от подписываемых данных, 0 - подпись содержит подписываемые данные)
// возвращаемые значения: 
// В случае успеха - string содержащая значение подписи в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/

ZEND_FUNCTION(gostSignBlock)
{
	char *cB64Data = NULL, *cIDCert = NULL;
	DWORD dwB64Data = 0, dwIDCert = 0;

	long bSignDetached = TRUE;
	try {
		if (ZEND_NUM_ARGS() == 3)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl",
					&cB64Data, &dwB64Data,
					&cIDCert, &dwIDCert,
					&bSignDetached) == FAILURE)
				throw (CString)"Bad param in call gostSignBlock.";
		} else if (ZEND_NUM_ARGS() == 2)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cB64Data, &dwB64Data,
					&cIDCert, &dwIDCert) == FAILURE)
				throw (CString)"Bad param in call gostSignBlock.";
		} else 
			throw (CString)"Bad number of param in call gostSignBlock.";
	
		CString sB64Data, sIDCert, sB64Sign;
		if (!InitPhpString (cB64Data, dwB64Data, sB64Data))
			throw (CString)"gostSignBlock not read param sB64Data.";
		if (!InitPhpString (cIDCert, dwIDCert, sIDCert))
			throw (CString)"gostSignBlock not read param sIDCert.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.SignDataB64 (sB64Data, sIDCert, bSignDetached, sB64Sign))
		{	
			RETURN_STRING ((LPTSTR)(LPCTSTR)sB64Sign, true);
		}	else	{
			throw (CString)"gostSignBlock : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostSignBlock : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/*
gostSignFile  ( string $sPathFileSrc, string $sPathFileDst, string $ sIDCert, long bSignDetached = 1 );
// sPathFileSrc - путь к файлу с данными для подписи
// sPathFileDst - путь к файлу с результатом подписи
// sIDCert - ИД сертификата подписи (CN или Thumb)
// bSignDetached - (1 - подпись откреплена от подписываемых данных, 0 - подпись содержит подписываемые данные)
// возвращаемые значения: 
// В случае успеха - bool true
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/

ZEND_FUNCTION(gostSignFile)
{
	char *cPFSrc = NULL, *cPFDst = NULL, *cIDCert = NULL;
	DWORD dwPFSrc = 0, dwPFDst = 0, dwIDCert = 0;

	long bSignDetached = TRUE;
	try {
		if (ZEND_NUM_ARGS() == 4)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sssl",
					&cPFSrc, &dwPFSrc,
					&cPFDst, &dwPFDst,
					&cIDCert, &dwIDCert,
					&bSignDetached) == FAILURE)
				throw (CString)"Bad param in call gostSignFile!";
		} else if (ZEND_NUM_ARGS() == 3)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
					&cPFSrc, &dwPFSrc,
					&cPFDst, &dwPFDst,
					&cIDCert, &dwIDCert) == FAILURE)
				throw (CString)"Bad param in call gostSignFile!";
		} else 
			throw (CString)"Bad number of param in call gostSignFile.";
	
		CString sPFSrc, sPFDst, sIDCert;
		if (!InitPhpString (cPFSrc, dwPFSrc, sPFSrc))
			throw (CString)"gostSignFile not read param sPFSrc.";
		if (!InitPhpString (cPFDst, dwPFDst, sPFDst))
			throw (CString)"gostSignFile not read param sPFDst.";
		if (!InitPhpString (cIDCert, dwIDCert, sIDCert))
			throw (CString)"gostSignFile not read param sIDCert.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.SignFile (sPFSrc, sPFDst, sIDCert, bSignDetached))
		{	
			RETURN_LONG (TRUE);
		}	else	{
			throw (CString)"gostSignFile : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostSignFile : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/* 
gostVerifyBlock  ( string $sB64Data, string $ sB64Sign = "")
// sB64Data - данные для проверки подписи закодированные в Base64. Если эти данные содержат в себе подпись, то следующий параметр sB64Sign должен быть равен пустой строке. 
// sB64Sign - значение подписи. Если sB64Data содержат в себе подпись, то sB64Sign = ""
// возвращаемые значения: 
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
// В случае успеха - string в формате xml содержащая значение ключевых параметров сертификата подписи. Например:
<?xml version="1.0" encoding="windows-1251"?>
<Sign>
<Subject>OID.1.2.643.3.131.1.1=7729633131, E=ee@garant.ru, C=RU, S=77 Москва, L=г. Москва, O=ООО Электронный экспресс, OU=0, CN=Максимов Сергей Вадимович, T=Специалист технической поддержки отдела №6</Subject>
<DateTimeSign>09.11.2011 16:36:05</DateTimeSign>
<Thumb>29d95ebe67a0bcbdc0f80e25f402e1be6114520b</Thumb>
<OID>1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.131.1000.0.2</OID>
</Sign>
<Sign>
<Subject>OID.1.2.643.3.131.1.1=7729633131, E=ee@garant.ru, C=RU, S=77 Москва, L=г. Москва, O=ООО Электронный экспресс, OU=0, CN=Павлов Николай Юрьевич, T=Руководитель отдела №6</Subject>
<DateTimeSign>17.11.2011 09:47:00</DateTimeSign>
<Thumb>4639d5c0551562fdb4e6079c739ace77ed4a3fb6</Thumb>
<OID>1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.131.1000.0.2</OID>
</Sign>
<Sign>
<Subject>OID.1.2.643.3.141.1.2=7718, OID.1.2.643.3.141.1.1=7718041395, T=доверенный представитель, CN=Довереннов Петр Сергеевич, OID.1.2.643.3.131.1.1=7729633131, OU=0, O=Тестовое ООО Электронный Экспресс, L=г. Москва, S=77 Москва, C=RU, E=dover@nomail.ru</Subject>
<DateTimeSign>17.11.2011 09:39:27</DateTimeSign>
<Thumb>e3fc21aa0bdec345b91dc50aa56434491f95fddd</Thumb>
<OID>1.2.643.2.2.34.6 1.3.6.1.5.5.7.3.4 1.3.6.1.5.5.7.3.2 1.2.643.3.130.2.3.4.1 1.2.643.3.130.2.3.5.1 1.2.643.3.130.2.3.3.1 1.2.643.3.131.1067.0.3.3.1</OID>
</Sign>
*/
ZEND_FUNCTION(gostVerifyBlock)
{
	char *cB64Data = NULL, *cB64Sign = NULL;
	DWORD dwB64Data = 0, dwB64Sign = 0;

	try {
		if (ZEND_NUM_ARGS() == 2)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cB64Data, &dwB64Data,
					&cB64Sign, &dwB64Sign) == FAILURE)
				throw (CString)"Bad param in call gostVerifyBlock.";
		} else if (ZEND_NUM_ARGS() == 1)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
					&cB64Data, &dwB64Data) == FAILURE)
				throw (CString)"Bad param in call gostVerifyBlock.";
		} else 
			throw (CString)"Bad number of param in call gostVerifyBlock.";
	
		CString sB64Data, sB64Sign, sSignInfo;
		if (!InitPhpString (cB64Data, dwB64Data, sB64Data))
			throw (CString)"gostVerifyBlock not read param sB64Data.";
		if (ZEND_NUM_ARGS() == 2)
			if (!InitPhpString (cB64Sign, dwB64Sign, sB64Sign))
				throw (CString)"gostVerifyBlock not read param sB64Sign.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.VerifyDataB64(sB64Data, sB64Sign, sSignInfo))
		{
			sSignInfo = phpCrypto.ParseSignInfo (sSignInfo);
			RETURN_STRING ((LPTSTR)(LPCTSTR)sSignInfo, true);
		}	else	{
			throw (CString)"gostVerifyBlock : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostVerifyBlock : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/* 
gostVerifyFile ( string $sPFSrc, string $ sPFSign = "")
// sPFSrc – путь к файлу, содержащий данные для проверки подписи. 
// sPFSign – путь к файлу, содержащему открепленную подпись. Если это значение равно пустой строке, то это означает, что в параметре sPFSrc содержатся данные + подпись.
// Возвращаемые значения: 
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
//  В случае успеха - string содержащая значение ключевых параметров сертификата подписи, в аналогичном формате, описанному в функции gostVerifyBlock.
*/
ZEND_FUNCTION(gostVerifyFile)
{
	char *cPFSrc = NULL, *cPFSign = NULL;
	DWORD dwPFSrc = 0, dwPFSign = 0;

	try {
		if (ZEND_NUM_ARGS() == 2)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cPFSrc, &dwPFSrc,
					&cPFSign, &dwPFSign) == FAILURE)
				throw (CString)"Bad param in call gostVerifyFile!";
		} else if (ZEND_NUM_ARGS() == 1)
		{
			if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
					&cPFSrc, &dwPFSrc) == FAILURE)
				throw (CString)"Bad param in call gostVerifyFile!";
		} else 
			throw (CString)"Bad number of param in call gostVerifyFile!";
	
		CString sPFSrc, sPFSign, sSignInfo;
		if (!InitPhpString (cPFSrc, dwPFSrc, sPFSrc))
			throw (CString)"gostVerifyFile not read param sPFSrc.";
		if (ZEND_NUM_ARGS() == 2)
			if (!InitPhpString (cPFSign, dwPFSign, sPFSign))
				throw (CString)"gostVerifyFile not read param sPFSign.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.VerifyFile (sPFSrc, sPFSign, sSignInfo))
		{
			sSignInfo = phpCrypto.ParseSignInfo (sSignInfo);
			RETURN_STRING ((LPTSTR)(LPCTSTR)sSignInfo, true);
		}	else	{
			throw (CString)"gostVerifyFile : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostVerifyFile : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/* 
gostEncryptBlock  (string $sB64DataSrc, string $ sIDCerts)
// sB64DataSrc - данные для шифрования закодированные в Base64. 
// sIDCerts - список сертификатов (CN или Thumb) получателей через символ ",". 
// При шифровании будет взят закрытый ключ первого сертификата из списка sIDCerts.
// возвращаемые значения: 
// В случае успеха - string содержащая зашифрованные данные в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/
ZEND_FUNCTION(gostEncryptBlock)
{
	char *cB64DataSrc = NULL, *cIDCerts = NULL;
	DWORD dwB64DataSrc = 0, dwIDCerts = 0;

	try {
		if (ZEND_NUM_ARGS() != 2 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cB64DataSrc, &dwB64DataSrc,
					&cIDCerts, &dwIDCerts) == FAILURE)
			throw (CString)"Bad param in call gostEncryptBlock!";
	
		CString sB64DataSrc, sB64DataEnc, sIDCerts;
		if (!InitPhpString (cB64DataSrc, dwB64DataSrc, sB64DataSrc))
			throw (CString)"gostEncryptBlock not read param sB64DataSrc.";
		if (!InitPhpString (cIDCerts, dwIDCerts, sIDCerts))
			throw (CString)"gostEncryptBlock not read param sIDCerts.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.EncryptDataB64 (sB64DataSrc, sIDCerts, sB64DataEnc))
		{
			RETURN_STRING ((LPTSTR)(LPCTSTR)sB64DataEnc, true);
		}	else	{
			throw (CString)"gostEncryptBlock : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostEncryptBlock : Unkown error";	}
	
	RETURN_LONG (FALSE);
}
/*
// gostEncryptFile ( string $sPathFileSrc, string $sPathFileDst,  string $ sIDCertPublic )
// sPathFileSrc – путь к файлу, содержащий данные для шифрования. 
// sPathFileDst – путь к результирующему файлу, который будет содержать зашифрованные данные.
// sIDCertPublic - ИД сертификатов получателей (CN или Thumb), через запятую. Закрытый ключ будет выбран на основании первого в списке сертификата.
// Возвращаемые значения: 
// В случае успеха – bool true.
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/
ZEND_FUNCTION(gostEncryptFile)
{
	char *cPFSrc = NULL, *cPFDst = NULL, *cIDCerts = NULL;
	DWORD dwPFSrc = 0, dwPFDst = 0, dwIDCerts = 0;

	try {
		if (ZEND_NUM_ARGS() != 3 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
					&cPFSrc, &dwPFSrc,
					&cPFDst, &dwPFDst,
					&cIDCerts, &dwIDCerts) == FAILURE)
			throw (CString)"Bad param in call gostEncryptFile!";
	
		CString sPFSrc, sPFDst, sIDCerts;
		if (!InitPhpString (cPFSrc, dwPFSrc, sPFSrc))
			throw (CString)"gostEncryptFile not read param sPFSrc.";
		if (!InitPhpString (cPFDst, dwPFDst, sPFDst))
			throw (CString)"gostEncryptFile not read param sPFDst.";
		if (!InitPhpString (cIDCerts, dwIDCerts, sIDCerts))
			throw (CString)"gostEncryptFile not read param sIDCerts.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.EncryptFile (sPFSrc, sPFDst, sIDCerts))
		{
			RETURN_LONG (TRUE);
		}	else	{
			throw (CString)"gostEncryptFile : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostEncryptFile : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/* 
gostEncryptBlockByCertContent (string $ sB64DataSrc,  string $ sB64CertContentRec)
// sB64DataSrc - данные для шифрования закодированные в Base64. 
// sB64CertContentRec - список содержимого сертификатов получателей через символ " ". 
// При шифровании будет взят закрытый ключ первого сертификата из списка sB64CertContentRec.
// возвращаемые значения: 
// В случае успеха - string содержащая зашифрованные данные в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/
ZEND_FUNCTION(gostEncryptBlockByCertContent)
{
	char *cB64DataSrc = NULL, *cIDCertPvt = NULL, *cCertsCont = NULL;
	DWORD dwB64DataSrc = 0, dwIDCertPvt = 0, dwCertsCont = 0;

	try {
		if (ZEND_NUM_ARGS() != 2 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cB64DataSrc, &dwB64DataSrc,
//					&cIDCertPvt, &dwIDCertPvt,
					&cCertsCont, &dwCertsCont) == FAILURE)
			throw (CString)"Bad param in call gostEncryptBlockByCertContent.";
//			throw (CString)"Bad param in call gostEncryptBlockByCertContent! Must be: gostEncryptBlockByCertContent (string $ sB64DataSrc,  string $ sIDCertPrivate,  string $ sB64DataEncRet)";
	
		CString sB64DataSrc, sB64DataEnc, sCertsCont, sIDCertPvt;
		if (!InitPhpString (cB64DataSrc, dwB64DataSrc, sB64DataSrc))
			throw (CString)"gostEncryptBlockByCertContent not read param sB64DataSrc.";
//		if (!InitPhpString (cIDCertPvt, dwIDCertPvt, sIDCertPvt))
//			throw (CString)"gostEncryptBlockByCertContent not read param sIDCertPrivate. Must be: gostEncryptBlockByCertContent (string $ sB64DataSrc,  string & sArrB64CertsRcpt, string $ sB64DataEncRet)";
		if (!InitPhpString (cCertsCont, dwCertsCont, sCertsCont))
			throw (CString)"gostEncryptBlockByCertContent not read param sB64CertContentRec.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.EncryptDataB64ByCertContent (sB64DataSrc, sCertsCont, sB64DataEnc))
		{
			RETURN_STRING ((LPTSTR)(LPCTSTR)sB64DataEnc, true);
		}	else	{
			throw (CString)"gostEncryptBlockByCertContent : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostEncryptBlockByCertContent : Unkown error";	}
	
	RETURN_LONG (FALSE);
}
/*
// gostEncryptFileByCertContent ( string $sPathFileSrc, string $sPathFileDst,  string $ sB64CertContentRec )
// sPathFileSrc – путь к файлу, содержащий данные для шифрования. 
// sPathFileDst – путь к результирующему файлу, который будет содержать зашифрованные данные.
// sB64CertContentRec - список содержимого сертификатов получателей в кодировке Base64, через запятую. 
// При шифровании будет взят закрытый ключ первого сертификата из списка sB64CertContentRec.
// Возвращаемые значения: 
// В случае успеха - string содержащая зашифрованные данные в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError().
*/
ZEND_FUNCTION(gostEncryptFileByCertContent)
{
	char *cPFSrc = NULL, *cPFDst = NULL, *cCertsCont = NULL;
	DWORD dwPFSrc = 0, dwPFDst = 0, dwCertsCont = 0;

	try {
		if (ZEND_NUM_ARGS() != 3 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
					&cPFSrc, &dwPFSrc,
					&cPFDst, &dwPFDst,
					&cCertsCont, &dwCertsCont) == FAILURE)
			throw (CString)"Bad param in call gostEncryptFileByCertContent!";
	
		CString sPFSrc, sPFDst, sCertsCont;
		if (!InitPhpString (cPFSrc, dwPFSrc, sPFSrc))
			throw (CString)"gostEncryptFileByCertContent not read param sPFSrc.";
		if (!InitPhpString (cPFDst, dwPFDst, sPFDst))
			throw (CString)"gostEncryptFileByCertContent not read param sPFDst.";
		if (!InitPhpString (cCertsCont, dwCertsCont, sCertsCont))
			throw (CString)"gostEncryptFileByCertContent not read param sCertsCont.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.EncryptFileByCertContent (sPFSrc, sPFDst, sCertsCont))
		{
			RETURN_LONG (TRUE);
		}	else	{
			throw (CString)"gostEncryptFileByCertContent : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostEncryptFileByCertContent : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/* 
gostDecryptBlock  (string $sB64DataEnc)
// sB64DataEnc - данные для шифрования закодированные в Base64. 
// возвращаемые значения: 
// В случае успеха - string содержащая расшифрованные данные в кодировке Base64
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/
ZEND_FUNCTION(gostDecryptBlock)
{
	char *cB64DataEnc = NULL;
	DWORD dwB64DataEnc = 0;

	try {
		if (ZEND_NUM_ARGS() != 1 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
					&cB64DataEnc, &dwB64DataEnc) == FAILURE)
			throw (CString)"Bad param in call gostDecryptBlock.";
	
		CString sB64DataEnc, sB64DataDec;
		if (!InitPhpString (cB64DataEnc, dwB64DataEnc, sB64DataEnc))
			throw (CString)"gostDecryptBlock not read param sB64DataSrc.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.DecryptDataB64 (sB64DataEnc, sB64DataDec))
		{	
			RETURN_STRING ((LPTSTR)(LPCTSTR)sB64DataDec, true);
		}	else	{
			throw (CString)"gostDecryptBlock : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostDecryptBlock : Unkown error";	}
	
	RETURN_LONG (FALSE);
}

/*
// gostDecryptFile  ( string $sPathFileSrc, string $sPathFileDst )
// sPathFileSrc – путь к файлу, содержащий зашифрованные данные. 
// sPathFileDst – путь к результирующему файлу, который будет содержать расшифрованные данные.
// Возвращаемые значения: 
// В случае успеха – bool true.
// В случае неудачи - bool false. Причину ошибки можно узнать вызвав функцию gostGetLastError()
*/
ZEND_FUNCTION(gostDecryptFile)
{
	char *cPFSrc = NULL, *cPFDst = NULL;
	DWORD dwPFSrc = 0, dwPFDst = 0;

	try {
		if (ZEND_NUM_ARGS() != 2 || zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
					&cPFSrc, &dwPFSrc,
					&cPFDst, &dwPFDst) == FAILURE)
			throw (CString)"Bad param in call gostDecryptFile!";
	
		CString sPFSrc, sPFDst;
		if (!InitPhpString (cPFSrc, dwPFSrc, sPFSrc))
			throw (CString)"gostDecryptFile not read param sPFSrc.";
		if (!InitPhpString (cPFDst, dwPFDst, sPFDst))
			throw (CString)"gostDecryptFile not read param sPFDst.";

		CPhpCrypto phpCrypto(g_sPFLog);
		if (TRUE == phpCrypto.DecryptFile (sPFSrc, sPFDst))
		{	
			RETURN_LONG (TRUE);
		}	else	{
			throw (CString)"gostDecryptFile : " + phpCrypto.GetLastError ();
		}

	} catch (CString sThrow)	
	{	g_sLastError = sThrow;	}
	catch (...)	
	{	g_sLastError = "gostDecryptFile : Unkown error";	}
	
	RETURN_LONG (FALSE);
}