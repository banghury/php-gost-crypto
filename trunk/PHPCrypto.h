#pragma once;

#ifndef PHP_CRYPTO_H
#define PHP_CRYPTO_H

#if _MSC_VER > 1000
	#pragma once
#endif // _MSC_VER > 1000

#include <vector>
#include <afxtempl.h>
// #include "ICPCrypto.h"
#include "LogFile.h"
#include "BinData.h"
#include "StringArrayEx.h"
#include "FileMng.h"
#include "CBase64Utils.h"
#include "IniMng.h"

// My additionals
class ICPCrypto {};
#define CCPC_NoError 0
#define ICPCryptoCallBack void
#define KILL_STREAM_INTERFACE

#define STR_TAG_CERT		_T("Certificate")
#define STR_TAG_ALL			_T("All")
#define STR_TAG_THUMB		_T("Thumb")
#define STR_TAG_OID			_T("OID")
#define STR_TAG_COMMON_NAME	_T("CommonName")
#define STR_TAG_DT_SIGN		_T("DateTimeSign")
#define STR_TAG_CERT_NOT_BEFORE_TIME	_T("NotBeforeTimeXml")
#define STR_TAG_CERT_NOT_BEFORE_LTIME	_T("NotBeforeTimeLong")
#define STR_TAG_CERT_NOT_AFTER_TIME		_T("NotAfterTimeXml")
#define STR_TAG_CERT_NOT_AFTER_LTIME	_T("NotAfterTimeLong")
#define STR_TAG_SERIAL_NUMBER			_T("SerialNumber")
#define STR_TAG_CERT_VERSION			_T("Version")
#define STR_TAG_CERT_ENCODING			_T("Encoding")
#define STR_TAG_SIGN_ALG				_T("SignatureAlgorithm")
#define STR_TAG_ISSUER					_T("Issuer")
#define STR_TAG_SUBJECT					_T("Subject")
#define STR_TAG_EXTENSION				_T("Extension")

#define CERT_IN_BASE64_BEGIN	_T("-----BEGIN CERTIFICATE-----")
#define CERT_IN_BASE64_END		_T("-----END CERTIFICATE-----")

class CPhpCrypto
{
protected:
	CString m_sLastError;
	CString m_sPFLog;

public:
	CPhpCrypto (CString sPFLog) : m_sPFLog(sPFLog) {};

	enum { NUM_SUBJECT = 0, NUM_DT_SIGN, NUM_THUMB, NUM_OID };
	BOOL SignDataB64	(const CString& sB64Data, const CString& sIDCert, const BOOL bSignDetached, CString& sB64SignRet);
	BOOL VerifyDataB64	(const CString& sB64Data, CString& sB64Sign, CString& sSignInfoRet);
	BOOL EncryptDataB64	(const CString& sB64DataSrc, const CString& sArrIDCerts, CString& sB64DataEncRet);
	BOOL EncryptDataB64ByCertContent (const CString& sB64DataSrc, const CString& sArrIDCertsContent, CString& sB64DataEncRet);
	BOOL DecryptDataB64	(const CString& sB64DataEnc, CString& sB64DataDecRet);
	BOOL ParseCertificate (const CString& sB64DataCert, CString& sXmlCertRet);
	CString ParseSignInfo (const CString& sSignInfo);

	BOOL SignFile	(const CString& sPFSrc, const CString& sPFDst, const CString& sIDCert, BOOL bSignDetached);
	BOOL VerifyFile	(const CString& sPFSrc, const CString& sPFSign, CString& sSignInfoRet);
	BOOL EncryptFile(const CString& sPFSrc, const CString& sPFDst, const CString& sArrIDCerts);
	BOOL EncryptFileByCertContent (const CString& sPFSrc, const CString& sPFDst, const CString& sArrIDCertsContent);
	BOOL DecryptFile(const CString& sPFSrc, const CString& sPFDst);
	
	BOOL GetCertProperty (PCCERT_CONTEXT pCertContext, DWORD dwParam, CBinData& bnRet);

	CString GetLastError () { return m_sLastError; };
};
#endif