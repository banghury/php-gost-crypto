#include "stdafx.h"
# include <afx.h>
#include "PHPCrypto.h"
#include <winsock.h>
#include "ICPCryptoImpl.h"

#include <WinCrypt.h>
#pragma comment(lib,"Crypt32.lib")

BOOL CPhpCrypto::SignFile	(const CString& sPFSrc, const CString& sPFDst, const CString& sIDCert, BOOL bSignDetached)
{
	try {
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (bSignDetached)
		{
			if (CCPC_NoError != cpImpl.SignFileD (sIDCert, sPFSrc, sPFDst))
				throw cpImpl.GetLastCryptoError ();
		}	else	{
			if (!CopyFile (sPFSrc, sPFDst, FALSE))
				throw (CString)"Can't copy file from " + sPFSrc + " to " + sPFDst;
			if (CCPC_NoError != cpImpl.SignFileA (sIDCert, sPFDst))
				throw cpImpl.GetLastCryptoError ();
		}
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"SignFile error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"SignFile error: Unknown";
	}
	return FALSE;
}

BOOL CPhpCrypto::VerifyFile	(const CString& sPFSrc, const CString& sPFSign, CString& sSignInfoRet)
{
	sSignInfoRet = "";
	try {
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

// write sign for verify
		if (sPFSign != "")
		{
// Verify data as detached sign			
			if (CCPC_NoError != cpImpl.CheckFileD (sPFSrc, sPFSign, sSignInfoRet))
				throw cpImpl.GetLastCryptoError ();
		}	else	{
// Verify data as attached sign
			if (CCPC_NoError != cpImpl.CheckFileA (sPFSrc, sSignInfoRet))
				throw cpImpl.GetLastCryptoError ();
		}
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"VerifyFile error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"VerifyFile error: Unknown";
	}
	return FALSE;
}

BOOL CPhpCrypto::EncryptFile(const CString& sPFSrc, const CString& sPFDst, const CString& sArrIDCerts)
{
	try {
		CStringArrayEx saIDCerts (sArrIDCerts, ',');
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (CCPC_NoError != cpImpl.EncryptFile (sPFSrc, sPFDst, saIDCerts))
			throw cpImpl.GetLastCryptoError ();
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"EncryptFile error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"EncryptFile error: Unknown";
	}
	return FALSE;
}

BOOL CPhpCrypto::EncryptFileByCertContent (const CString& sPFSrc, const CString& sPFDst, const CString& sArrIDCertsContent)
{
	CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;

	try {
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;
		CStringArrayEx saCertsContent (sArrIDCertsContent, ',');
		std::list<CBinData> lsBNDataCert;
		CStringArrayEx saTemp;
		FOR_ALL_CONST_STR (pStrCertContent, saCertsContent)
		{
			lsBNDataCert.push_front (CBinData());
			if (!CBase64Utils::DecodeFromB64 (*pStrCertContent, lsBNDataCert.front()))
				throw CString ("Certificate content data is not Base64!");

			if (CCPC_NoError != cpImpl.CryptDataBlobFromFile ("", NULL, &(lsBNDataCert.front()) ))
				throw cpImpl.GetLastCryptoError ();
	// Преобразуем сертификат в описатель
			PCCERT_CONTEXT pCertContext = ::CertCreateCertificateContext (X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
				lsBNDataCert.front().BufUC(), lsBNDataCert.front().Size());
			
			if (pCertContext == NULL)
				throw (CString)"Failed to create the handle of the certificate binary data : " + CStringProc::GetSystemError();

			saTemp.Add (cpImpl.CertNameBlob2Str(&pCertContext->pCertInfo->Subject));
			arrCertRcpt.Add(pCertContext);
		}
//		sB64DataEncRet = saTemp.GetAsString ("\r\n");
//		return TRUE;

		if (CCPC_NoError != cpImpl.EncryptFileEx (sPFSrc, sPFDst, CStringArray (), &arrCertRcpt))
			throw cpImpl.GetLastCryptoError ();

		ICPCryptoImpl::FreeCertsArray (arrCertRcpt);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"EncryptDataB64ByCertContent error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"EncryptDataB64ByCertContent error: Unknown";
	}

	ICPCryptoImpl::FreeCertsArray (arrCertRcpt);
	return FALSE;
}

BOOL CPhpCrypto::DecryptFile(const CString& sPFSrc, const CString& sPFDst)
{
	try {
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (CCPC_NoError != cpImpl.DecryptFile (sPFSrc, sPFDst))
			throw cpImpl.GetLastCryptoError ();
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"DecryptFile error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"DecryptFile error: Unknown";
	}
	return FALSE;
}

BOOL CPhpCrypto::GetCertProperty (PCCERT_CONTEXT pCertContext, DWORD dwParam, CBinData& bnRet)
{
	try {
		DWORD dwVersion = pCertContext->pCertInfo->dwVersion;

		if (pCertContext == NULL || pCertContext->pCertInfo == NULL)
			throw (CString)"Bad context pointer.";
// Thumb
		DWORD nLenData = 0;
		if (!CertGetCertificateContextProperty(pCertContext, dwParam /* = CERT_SHA1_HASH_PROP_ID */, NULL, &nLenData))
		{
			CString sPropErr;
			sPropErr.Format ("Bad size for property %d ", dwParam);
			throw sPropErr + CStringProc::GetSystemError ();
		}

// Получили длину, выделим память под него и считаем само значение
		if (!bnRet.AllocMem (nLenData))
			throw (CString)"Not enought memory";
		
		if (!CertGetCertificateContextProperty (pCertContext, dwParam /* CERT_SHA1_HASH_PROP_ID */, bnRet.Buf (), &nLenData))
		{
			CString sPropErr;
			sPropErr.Format ("Bad size for property %d ", dwParam);
			throw sPropErr + CStringProc::GetSystemError ();
		}

		return TRUE;
	} 
	catch (CString sThrow)	{		m_sLastError = (CString)"GetCertProperty : " + sThrow;	}
	catch (...)				{		m_sLastError = (CString)"GetCertProperty : Unknown";	}
	return FALSE;
}

/*
OID.1.2.643.3.131.1.1=7729633131, E=ee@garant.ru, C=RU, S=77 Москва, L=г. Москва, O=ООО Электронный экспресс, OU=0, CN=Максимов Сергей Вадимович, T=Специалист технической поддержки отдела №6	
28.10.2011 08:53:27
29d95ebe67a0bcbdc0f80e25f402e1be6114520b	
OID:1.3.6.1.5.5.7.3.4;1.3.6.1.5.5.7.3.2;1.2.643.3.131.1000.0.2.
*/
CString CPhpCrypto::ParseSignInfo (const CString& sSignInfo)
{
	CStringArrayEx saFields;
	saFields.FillFromString (sSignInfo, "###");
	saFields.RemoveEmptyString ();

	CString sXmlSignInfo, sXmlOneSign, sCommonName;
	sXmlSignInfo = "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\r\n";
	FOR_ALL_STR(pStr, saFields)
	{
		CStringArrayEx saSignFields (*pStr, '\t');
		sXmlSignInfo += "<Sign>\r\n";
		sXmlOneSign = "";
		if (saSignFields.GetSize () == NUM_OID + 1)
		{
			CStringProc::SetTagValue (sXmlOneSign, STR_TAG_SUBJECT, saSignFields[NUM_SUBJECT]);
			sXmlOneSign += "\r\n";
			CStringProc::SetTagValue (sXmlOneSign, STR_TAG_DT_SIGN, saSignFields[NUM_DT_SIGN]);
			sXmlOneSign += "\r\n";
			CStringProc::SetTagValue (sXmlOneSign, STR_TAG_THUMB, saSignFields[NUM_THUMB]);
			sXmlOneSign += "\r\n";
			CString sOIDs = CStringProc::GetStrAfter (saSignFields[NUM_OID], "OID:");
			sOIDs.Replace (';', ' ');
			CStringProc::SetTagValue (sXmlOneSign, STR_TAG_OID, sOIDs); 
			sXmlOneSign += "\r\n";
		}	else
			sXmlOneSign = (CString)"Not correct number of fields in: " + *pStr;

		sXmlSignInfo += sXmlOneSign;
		sXmlSignInfo += "</Sign>\r\n";
	}
	return sXmlSignInfo;
}

BOOL CPhpCrypto::ParseCertificate (const CString& sB64DataCert, CString& sXmlCertRet)
{
	sXmlCertRet = "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\r\n<Certificate>\r\n";
	PCCERT_CONTEXT pCertContext = NULL;
	try {
		CBinData bnDataCert;
		if (!CBase64Utils::DecodeFromB64 (sB64DataCert, bnDataCert))
			throw CString ("Certificate content data is not Base64!");

		BOOL bTypeIsASN = bnDataCert.Find (_T("MII")) == 0;

		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (CCPC_NoError != cpImpl.CryptDataBlobFromFile ("", NULL, &bnDataCert))
			throw cpImpl.GetLastCryptoError ();
		CStringProc::SetStrForTag (sXmlCertRet, "Type", bTypeIsASN ? "ASN" : "DER");
		sXmlCertRet += "\r\n";
/*
		DWORD                       dwVersion;
		CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
		CERT_NAME_BLOB              Issuer;
		CERT_NAME_BLOB              Subject;
		CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;
		CRYPT_BIT_BLOB              IssuerUniqueId;
		CRYPT_BIT_BLOB              SubjectUniqueId;
		DWORD                       cExtension;
		PCERT_EXTENSION             rgExtension;

		дата,  отпечаток, серийный,  и до EKU и CP
		FILETIME                    NotBefore;
		FILETIME                    NotAfter;
		CRYPT_INTEGER_BLOB          SerialNumber;
*/

// Преобразуем сертификат в описатель
		PCCERT_CONTEXT pCertContext = ::CertCreateCertificateContext (X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
			bnDataCert.BufUC(), bnDataCert.Size());
		if (pCertContext == NULL)
			throw (CString)"Failed to create the handle of the certificate binary data : " + CStringProc::GetSystemError();
// Subject
		{
			CString strSubject = cpImpl.CertNameBlob2Str(&pCertContext->pCertInfo->Subject);
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_SUBJECT, strSubject);
			sXmlCertRet += "\r\n";
		}
	
// Issuer
		{
			CString strIssuer = cpImpl.CertNameBlob2Str(&pCertContext->pCertInfo->Issuer);
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_ISSUER, strIssuer);
			sXmlCertRet += "\r\n";
		}

// Thumb
		CBinData bnThumb;
		if (GetCertProperty (pCertContext, CERT_SHA1_HASH_PROP_ID, bnThumb))
		{
			CString sHex;
			bnThumb.Encode2Hex (sHex);
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_THUMB, sHex);
		}
		sXmlCertRet += "\r\n";
		
// Datetime
		CTime tmNotBefore (pCertContext->pCertInfo->NotBefore);
		CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_NOT_BEFORE_TIME, tmNotBefore.Format( "%Y-%m-%dT%H:%M:%S"));
		CString sTMLong;
		sTMLong.Format ("%u", tmNotBefore);
		CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_NOT_BEFORE_LTIME, sTMLong);
		sXmlCertRet += "\r\n";

		CTime tmNotAfter (pCertContext->pCertInfo->NotAfter);
		CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_NOT_AFTER_TIME, tmNotAfter.Format( "%Y-%m-%dT%H:%M:%S"));
		sTMLong.Format ("%u", tmNotAfter);
		CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_NOT_AFTER_LTIME, sTMLong);
		sXmlCertRet += "\r\n";

// Serial number
		if (pCertContext->pCertInfo->SerialNumber.pbData && pCertContext->pCertInfo->SerialNumber.cbData)
		{
			CBinData bnSerial (pCertContext->pCertInfo->SerialNumber.pbData, pCertContext->pCertInfo->SerialNumber.cbData);
			// Invert Data
			for (int i = 0; i < bnSerial.Size () / 2; i++)
			{
				UCHAR ucSwap = *(bnSerial.BufUC () + i);
				*(bnSerial.BufUC () + i) = *(bnSerial.BufUC () + bnSerial.Size () - i - 1);
				*(bnSerial.BufUC () + bnSerial.Size () - i - 1) = ucSwap;
			}
			CString sHex;
			bnSerial.Encode2Hex (sHex);
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_SERIAL_NUMBER, sHex);
			sXmlCertRet += "\r\n";
		}	

// Version
		{
			CString sVersion;
			sVersion.Format ("V%u", pCertContext->pCertInfo->dwVersion + 1);
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_VERSION, sVersion);
			sXmlCertRet += "\r\n";
		}

// dwCertEncodingType
		{
            CString sTemp;
			sTemp.Format ("%u", pCertContext->dwCertEncodingType) ;
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_CERT_ENCODING, sTemp);
			sXmlCertRet += "\r\n";
		}

// SignatureAlgorithm
        {
			CString sSignAlg = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId;
            // 2011/09/05 Check that Parameter-data-size is greater than 0.         
            if (pCertContext->pCertInfo->SignatureAlgorithm.Parameters.cbData > 0) 
			{
				CBinData bnSignParam (pCertContext->pCertInfo->SignatureAlgorithm.Parameters.pbData,
                    pCertContext->pCertInfo->SignatureAlgorithm.Parameters.cbData);
				CString sHex;
				bnSignParam.Encode2Hex (sHex);
				CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_SIGN_ALG, sSignAlg + "=" + sHex);
				sXmlCertRet += "\r\n";
            }
		}

// rgExtension
		{
			BYTE* pbDecoded;            // result
			DWORD cbDecoded;    // result length
			DWORD ExtCount = pCertContext->pCertInfo->cExtension;
			CString sCertExt;
			for (int i = 0; i < ExtCount; i++) // перебор все расширений сертификата
			{
				 // Get length needed to buffer;
				if (!CryptDecodeObject(
						pCertContext->dwCertEncodingType,
						pCertContext->pCertInfo->rgExtension[i].pszObjId,
						pCertContext->pCertInfo->rgExtension[i].Value.pbData,
						pCertContext->pCertInfo->rgExtension[i].Value.cbData,
						NULL,
						NULL,
						&cbDecoded) || cbDecoded == 0)
					continue;
				CBinData bnExt (cbDecoded);
				// Call again to
				if (!CryptDecodeObject(
						pCertContext->dwCertEncodingType,
						pCertContext->pCertInfo->rgExtension[i].pszObjId,
						pCertContext->pCertInfo->rgExtension[i].Value.pbData,
						pCertContext->pCertInfo->rgExtension[i].Value.cbData,
						NULL,
						bnExt.Buf (),
						&cbDecoded))
					continue;
				
				CString sTemp;
				sTemp.Format ("%s", pCertContext->pCertInfo->rgExtension[i].pszObjId);
				sCertExt += sTemp;
				bnExt.Encode2Hex (sTemp); 
				if (sTemp != "")
					sCertExt += (CString)'=' + sTemp;
				sCertExt += " ";

				// далее по названию расширения пытаюсь получить его значение
//				if (!strcmp(pCertContext->pCertInfo->rgExtension[i].pszObjId, szOID_KEY_USAGE))
//				{
//					CRYPT_BIT_BLOB pKeyAtt;
//					pKeyAtt= (CRYPT_BIT_BLOB) pbDecoded;
//					// PCERT_KEY_ATTRIBUTES_INFO pKeyAtt;
//					// pKeyAtt= (PCERT_KEY_ATTRIBUTES_INFO) pbDecoded;
//					if (*pKeyAtt->IntendedKeyUsage.pbData & CERT_DIGITAL_SIGNATURE_KEY_USAGE) // строка генерирует access violation
//						fprintf(fout, "CERT_DIGITAL_SIGNATURE_KEY_USAGE");       // вывод значения - CERT_DIGITAL_SIGNATURE_KEY_USAGE
//				}
			}
			sCertExt.TrimRight ();
			CStringProc::SetStrForTag (sXmlCertRet, STR_TAG_EXTENSION, sCertExt);
			sXmlCertRet += "\r\n";
		}
/*
		CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;
		CRYPT_BIT_BLOB              IssuerUniqueId;
		CRYPT_BIT_BLOB              SubjectUniqueId;
		DWORD                       cExtension;
		PCERT_EXTENSION             rgExtension;
*/
		if (pCertContext)
			::CertFreeCertificateContext (pCertContext);

		sXmlCertRet += "</Certificate>";
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"ParseCertificate error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"ParseCertificate error: Unknown";
	}

	if (pCertContext)
		::CertFreeCertificateContext (pCertContext);

	return FALSE;
}

BOOL CPhpCrypto::SignDataB64 (const CString& sB64Data, const CString& sIDCert, const BOOL bSignDetached, CString& sB64SignRet)
{
	sB64SignRet = "";
	CString sPFSrc, sPFSign;
	try {
		CString sDirTemp = CFileMng::GetDirTemp ();
		if (sDirTemp.IsEmpty() || !CFileMng::IsDirExist (sDirTemp))
			throw CString ("Temp Dir not exist!");

		sPFSrc = sDirTemp + CFileMng::GetUnicName ();
		sPFSign = sDirTemp + CFileMng::GetUnicName ();
		CBinData bnData;
		if (!CBase64Utils::DecodeFromB64 (sB64Data, bnData))
			throw CString ("Data for sign is not Base64!");

		if (!bnData.fWrite (sPFSrc))
			throw CString ("Can't write data to temp dir: " + sDirTemp);

		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (bSignDetached)
		{
			if (CCPC_NoError != cpImpl.SignFileD (sIDCert, sPFSrc, sPFSign))
				throw cpImpl.GetLastCryptoError ();
		}	else	{
			if (CCPC_NoError != cpImpl.SignFileA (sIDCert, sPFSrc))
				throw cpImpl.GetLastCryptoError ();
			sPFSign = sPFSrc;
		}

		CBinData bnSign;
		if (!bnSign.fRead (sPFSign))
			throw CString ("Can't read sign data in temp dir: " + sPFSign);
		sB64SignRet = CBase64Utils::EncodeToB64 (bnSign);

// SMU: Clean temp files
		CFileMng::DeleteFileA (sPFSrc);
		CFileMng::DeleteFileA (sPFSign);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"SignData error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"SignData error: Unknown";
	}

	if (!sPFSrc.IsEmpty ())
		CFileMng::DeleteFileA (sPFSrc);
	if (!sPFSign.IsEmpty ())
		CFileMng::DeleteFileA (sPFSign);

	return FALSE;
}

BOOL CPhpCrypto::VerifyDataB64	(const CString & sB64Data, CString& sB64Sign, CString& sSignInfoRet)
{
	sSignInfoRet = "";
	CString sPFSrc, sPFSign;
	try {
		CString sDirTemp = CFileMng::GetDirTemp ();
		if (sDirTemp.IsEmpty() || !CFileMng::IsDirExist (sDirTemp))
			throw CString ("Temp Dir not exist!");
		sPFSrc = sDirTemp + CFileMng::GetUnicName ();
		sPFSign = sDirTemp + CFileMng::GetUnicName ();
		
		CBinData bnData, bnSign;
// write data for verify
		if (!CBase64Utils::DecodeFromB64 (sB64Data, bnData))
			throw CString ("Data for verify sign is not Base64!");

		if (!bnData.fWrite (sPFSrc))
			throw CString ("Can't write verify data to temp dir: " + sDirTemp);

		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

// write sign for verify
		if (sB64Sign != "")
		{
			if (!CBase64Utils::DecodeFromB64 (sB64Sign, bnSign))
				throw CString ("Data for verify sign is not Base64!");

			if (!bnSign.fWrite (sPFSign))
				throw CString ("Can't write verify sign to temp dir: " + sDirTemp);
// Verify data as detached sign			
			if (CCPC_NoError != cpImpl.CheckFileD (sPFSrc, sPFSign, sSignInfoRet))
				throw cpImpl.GetLastCryptoError ();
		}	else	{
// Verify data as attached sign
			if (CCPC_NoError != cpImpl.CheckFileA (sPFSrc, sSignInfoRet))
				throw cpImpl.GetLastCryptoError ();
		}

// SMU: Clean temp files
		CFileMng::DeleteFileA (sPFSrc);
		CFileMng::DeleteFileA (sPFSign);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"VerifyData error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"VerifyData error: Unknown";
	}

	if (!sPFSrc.IsEmpty ())
		CFileMng::DeleteFileA (sPFSrc);
	if (!sPFSign.IsEmpty ())
		CFileMng::DeleteFileA (sPFSign);
	
	return FALSE;
}

BOOL CPhpCrypto::EncryptDataB64	(const CString& sB64DataSrc, const CString& sArrIDCerts, CString& sB64DataEncRet)
{
	sB64DataEncRet = "";
	CString sPFSrc, sPFEnc;
	try {
		CString sDirTemp = CFileMng::GetDirTemp ();
		if (sDirTemp.IsEmpty() || !CFileMng::IsDirExist (sDirTemp))
			throw CString ("Temp Dir not exist!");

		sPFSrc = sDirTemp + CFileMng::GetUnicName ();
		sPFEnc = sDirTemp + CFileMng::GetUnicName ();
		CBinData bnData;
		if (!CBase64Utils::DecodeFromB64 (sB64DataSrc, bnData))
			throw CString ("Data for encrypt is not Base64!");

		if (!bnData.fWrite (sPFSrc))
			throw CString ("Can't write data to temp dir: " + sDirTemp);

		CStringArrayEx saIDCerts (sArrIDCerts, ',');
/*				
		CString sTemp;
		for (int i = 0; i < saIDCerts.GetSize (); i++)
			sTemp += (CString)"\nCert : " + saIDCerts[i] + "\n";
		sB64DataEncRet = sTemp;
		return TRUE;
*/
		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		if (CCPC_NoError != cpImpl.EncryptFile (sPFSrc, sPFEnc, saIDCerts))
			throw cpImpl.GetLastCryptoError ();

		CBinData bnDataEnc;
		if (!bnDataEnc.fRead (sPFEnc))
			throw CString ("Can't read encrypt data in temp dir: " + sPFEnc);
		sB64DataEncRet = CBase64Utils::EncodeToB64 (bnDataEnc);

// SMU: Clean temp files
		CFileMng::DeleteFileA (sPFSrc);
		CFileMng::DeleteFileA (sPFEnc);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"EncryptData error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"EncryptData error: Unknown";
	}

	if (!sPFSrc.IsEmpty ())
		CFileMng::DeleteFileA (sPFSrc);
	if (!sPFEnc.IsEmpty ())
		CFileMng::DeleteFileA (sPFEnc);

	return FALSE;
}

BOOL CPhpCrypto::EncryptDataB64ByCertContent (const CString& sB64DataSrc, // const CString sIDCertPvt, 
											  const CString& sArrIDCertsContent, CString& sB64DataEncRet)
{
	sB64DataEncRet = "";
	CString sPFSrc, sPFEnc;

	CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;

	try {
		CString sDirTemp = CFileMng::GetDirTemp ();
		if (sDirTemp.IsEmpty() || !CFileMng::IsDirExist (sDirTemp))
			throw CString ("Temp Dir not exist!");

		sPFSrc = sDirTemp + CFileMng::GetUnicName ();
		sPFEnc = sDirTemp + CFileMng::GetUnicName ();
		CBinData bnData;
		if (!CBase64Utils::DecodeFromB64 (sB64DataSrc, bnData))
			throw CString ("Data for encrypt is not Base64!");

		if (!bnData.fWrite (sPFSrc))
			throw CString ("Can't write data to temp dir: " + sDirTemp);

		ICPCryptoImpl cpImpl;
			cpImpl.m_Log.m_sPFNLog = m_sPFLog;

		CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;
		CStringArrayEx saCertsContent (sArrIDCertsContent, ',');
		std::list<CBinData> lsBNDataCert;
		CStringArrayEx saTemp;
		FOR_ALL_CONST_STR (pStrCertContent, saCertsContent)
		{
			lsBNDataCert.push_front (CBinData());
			if (!CBase64Utils::DecodeFromB64 (*pStrCertContent, lsBNDataCert.front()))
				throw CString ("Certificate content data is not Base64!");

			if (CCPC_NoError != cpImpl.CryptDataBlobFromFile ("", NULL, &(lsBNDataCert.front()) ))
				throw cpImpl.GetLastCryptoError ();
	// Преобразуем сертификат в описатель
			PCCERT_CONTEXT pCertContext = ::CertCreateCertificateContext (X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
				lsBNDataCert.front().BufUC(), lsBNDataCert.front().Size());
			
			if (pCertContext == NULL)
				throw (CString)"Failed to create the handle of the certificate binary data : " + CStringProc::GetSystemError();

			saTemp.Add (cpImpl.CertNameBlob2Str(&pCertContext->pCertInfo->Subject));
			arrCertRcpt.Add(pCertContext);
		}
//		sB64DataEncRet = saTemp.GetAsString ("\r\n");
//		return TRUE;

		if (CCPC_NoError != cpImpl.EncryptFileEx (sPFSrc, sPFEnc, CStringArray (), &arrCertRcpt))
			throw cpImpl.GetLastCryptoError ();

		CBinData bnDataEnc;
		if (!bnDataEnc.fRead (sPFEnc))
			throw CString ("Can't read encrypt data in temp dir: " + sPFEnc);
		sB64DataEncRet = CBase64Utils::EncodeToB64 (bnDataEnc);

// SMU: Clean temp files
		CFileMng::DeleteFileA (sPFSrc);
		CFileMng::DeleteFileA (sPFEnc);
		ICPCryptoImpl::FreeCertsArray (arrCertRcpt);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"EncryptDataB64ByCertContent error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"EncryptDataB64ByCertContent error: Unknown";
	}

	if (!sPFSrc.IsEmpty ())
		CFileMng::DeleteFileA (sPFSrc);
	if (!sPFEnc.IsEmpty ())
		CFileMng::DeleteFileA (sPFEnc);
	ICPCryptoImpl::FreeCertsArray (arrCertRcpt);
	return FALSE;
}

BOOL CPhpCrypto::DecryptDataB64	(const CString& sB64DataEnc, CString& sB64DataDecRet)
{
	sB64DataDecRet = "";
	CString sPFEnc, sPFDec;
	try {
		CString sDirTemp = CFileMng::GetDirTemp ();
		if (sDirTemp.IsEmpty() || !CFileMng::IsDirExist (sDirTemp))
			throw CString ("Temp Dir not exist!");

		sPFEnc = sDirTemp + CFileMng::GetUnicName ();
		sPFDec = sDirTemp + CFileMng::GetUnicName ();
		CBinData bnData;
		if (!CBase64Utils::DecodeFromB64 (sB64DataEnc, bnData))
			throw CString ("Data for decrypt is not Base64!");

		if (!bnData.fWrite (sPFEnc))
			throw CString ("Can't write data to temp dir: " + sDirTemp);

		ICPCryptoImpl cpImpl;
		cpImpl.m_Log.m_sPFNLog = m_sPFLog;
		if (CCPC_NoError != cpImpl.DecryptFile (sPFEnc, sPFDec))
			throw cpImpl.GetLastCryptoError ();

		CBinData bnDataDec;
		if (!bnDataDec.fRead (sPFDec))
			throw CString ("Can't read decrypt data in temp dir: " + sPFDec);
		sB64DataDecRet = CBase64Utils::EncodeToB64 (bnDataDec);

// SMU: Clean temp files
		CFileMng::DeleteFileA (sPFEnc);
		CFileMng::DeleteFileA (sPFDec);
		return TRUE;
	} 
	catch (CString sThrow)
	{
		m_sLastError = (CString)"DecryptData error: " + sThrow;
	}
	catch (...)
	{
		m_sLastError = (CString)"DecryptData error: Unknown";
	}

	if (!sPFEnc.IsEmpty ())
		CFileMng::DeleteFileA (sPFEnc);
	if (!sPFDec.IsEmpty ())
		CFileMng::DeleteFileA (sPFDec);

	return FALSE;
}
