#include "stdafx.h"
#include "ICPCryptoImpl.h"

#pragma warning( disable : 4018 )

#define	STR_TAG_CERT_THUMB	_T("CERT_THUMB")
#define	STR_TAG_CERT_CN		_T("CERT_CN")
#define	STR_TAG_CERT_EMAIL	_T("CERT_EMAIL")

#ifdef _DEBUG
	#undef THIS_FILE
	static char THIS_FILE[]=__FILE__;
	#define new DEBUG_NEW
#endif

//**********************************************************
//NMS : ������
//**********************************************************

/*virtual*/ int ICPCryptoImpl::ViewStore(CStringArray& saResult)
{	
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

	//WriteToLog("����� ICPCryptoImpl::ViewStore");	

	//NMS : ��������
	saResult.RemoveAll();	

	//NMS : ��������� ������ SST	
	int nResult=CertOpenStore(CST_SST);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ������� ����� ��������� SST
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : ���������� �����������	
	CString s;
	int iCert=0;
	PCCERT_CONTEXT pCert = NULL;
	char* pbuff = NULL;
	DWORD dwbuffsz=0;
	CString sStrToAdd, strSubject;
	
	do 
	{
#ifdef CTHREAD_UPDATE_CRL
		if (m_pCPCryptoCallBack!=NULL)
		{
			BOOL bResolved = m_pCPCryptoCallBack->OnCertFindEx(NULL,pCert);
			if (bResolved==FALSE) break;
		}
		else
#endif //
		{

		
		
		pCert=CertFindCertificateInStore(hSST,
										 X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
										 0,
										 CERT_FIND_ANY,
										 NULL,pCert);
		}
		if (pCert==NULL)
		{
			break;
		}
		
		iCert++;
		//NMS : ������
		sStrToAdd.Empty();

		//NMS : ������ �������� ����� ����������� 
		CString sCertSerial;
		for (int iS=0; iS<pCert->pCertInfo->SerialNumber.cbData; iS++)
		{
			CString st2;
			st2.Format("%.2X",pCert->pCertInfo->SerialNumber.pbData[iS]);
			sCertSerial=st2+sCertSerial;
		}
		sStrToAdd+=sCertSerial+_T("\t");
		//NMS : ������ subject
		strSubject=CertNameBlob2Str(&pCert->pCertInfo->Subject);
		if (!strSubject.IsEmpty())
		{
			sStrToAdd+=strSubject;
			sStrToAdd+=CertGetEKUs(pCert);
			sStrToAdd+=_T("\t");
		}
		else
		{
			sStrToAdd+=_T("\t");
		}		
		//NMS : ������ ��� ������� ����������
		CString strIssuer=CertNameBlob2Str(&pCert->pCertInfo->Issuer);
		sStrToAdd+=strIssuer+_T("\t");
		//NMS : ������ ����
		CTime tm;
		tm=pCert->pCertInfo->NotBefore;
		sStrToAdd+=tm.Format("%d.%m.%Y %H:%M:%S")+_T("\t");
		tm=pCert->pCertInfo->NotAfter;
		sStrToAdd+=tm.Format("%d.%m.%Y %H:%M:%S")+_T("\t");
		//NMS : ��������� �� ����������		
		CERTVALIDPARAM ValidParam;
		if (TRUE) //CertIsValid(pCert,&ValidParam))
		{
			sStrToAdd+="Valid";
		}
		else
		{
			sStrToAdd+="Not valid";
		}
// SMU: Add thumb as xml field
		CRYPT_DATA_BLOB thumb;
		if (CertGetThumb (pCert, &thumb))
		{
			CBinData bnThumb (thumb.pbData, thumb.cbData);
			CString sHexThumb, sForAdd;
			bnThumb.Encode2Hex (sHexThumb);
			if (!sHexThumb.IsEmpty ()) 
			{
				CStringProc::SetTagValue (sForAdd, STR_TAG_CERT_THUMB, sHexThumb);
				sStrToAdd += '\t' + sForAdd;
			}
			// AKV: ������� thumb::pbData, ������� ���������� � CertGetThumb
			delete[] thumb.pbData;
		}
// SMU: Add only subject
		{
			CString sForAdd;
			CStringProc::SetTagValue (sForAdd, STR_TAG_CERT_CN, strSubject);
			sStrToAdd += '\t' + sForAdd;
		}
		//NMS : ������� ������ � �������������� ������		
		saResult.Add(sStrToAdd);
	}
	while(pCert!=NULL);	
	//NMS : ���������� ����� !
	return m_LastErrorCode = CCPC_NoError;
}

/*virtual*/ int ICPCryptoImpl::UpdateCRLs()
{	
	//NMS : ��������� CRLs ��� CST_SST
#ifdef CTHREAD_UPDATE_CRL
	return m_LastErrorCode = CertUpdateCRLs();
#else
	return m_LastErrorCode = CCPC_NoError;
#endif //
}

/*virtual*/ int	ICPCryptoImpl::AddCertToFile(CString sFile, CString sCertFile)
{
	CRYPT_DATA_BLOB cert;
	ZeroMemory(&cert,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCertFile,&cert);
	if (nResult==CCPC_NoError)
	{
		nResult=AddCertToFile(sFile,&cert);
	}
	if (cert.pbData!=NULL)
	{
		free(cert.pbData);
		cert.pbData=NULL;
	}
	return m_LastErrorCode = nResult;
}

/*virtual*/ int	ICPCryptoImpl::AddCertToFile(CString sFile,CRYPT_DATA_BLOB* pCert)
{
	ASSERT(pCert!=NULL);
	return m_LastErrorCode = AddCertOrCRLToFile(sFile,pCert,CMSG_CTRL_ADD_CERT);	
}

/*virtual*/ int	ICPCryptoImpl::AddCRLToFile(CString sFile, CString sCRLFile)
{
	CRYPT_DATA_BLOB CRL;
	ZeroMemory(&CRL,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCRLFile,&CRL);
	if (nResult==CCPC_NoError)
	{
		nResult=AddCRLToFile(sFile,&CRL);
	}
	if (CRL.pbData!=NULL)
	{
		free(CRL.pbData);
		CRL.pbData=NULL;
	}
	return m_LastErrorCode = nResult;
}

/*virtual*/ int	ICPCryptoImpl::AddCRLToFile(CString sFile, CRYPT_DATA_BLOB* pCRL)
{
	ASSERT(pCRL!=NULL);
	return m_LastErrorCode = AddCertOrCRLToFile(sFile,pCRL,CMSG_CTRL_ADD_CRL);	
}

/*virtual*/ int	ICPCryptoImpl::AddCertToStore(CString sCertFile)
{
	//NMS : �������� �� �����
	CRYPT_DATA_BLOB cert;
	ZeroMemory(&cert,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCertFile,&cert);
	CCertAutoBytePtr certPtr(cert.pbData);
	if (nResult==CCPC_NoError)
	{
		//NMS : ������� � ���������
		nResult=AddCertToStore(&cert);
	}	
	return m_LastErrorCode = nResult;
}

/*virtual*/ int	ICPCryptoImpl::AddCertToStore(CRYPT_DATA_BLOB* pCert)
{
	ASSERT(pCert!=NULL);

	return m_LastErrorCode = AddCertOrCRLToStore(pCert, CMSG_CTRL_ADD_CERT);
}

/*virtual*/ int	ICPCryptoImpl::AddCRLToStore(CString sCRLFile)
{
	//NMS : �������� �� �����
	CRYPT_DATA_BLOB CRL;
	ZeroMemory(&CRL,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCRLFile,&CRL);
	CCertAutoBytePtr CRLPtr(CRL.pbData);
	if (nResult==CCPC_NoError)
	{
		//NMS : ������� � ���������
		nResult=AddCRLToStore(&CRL);
	}	
	return m_LastErrorCode = nResult;	
}

/*virtual*/ int	ICPCryptoImpl::AddCRLToStore(CRYPT_DATA_BLOB* pCRL)
{
	ASSERT(pCRL!=NULL);
	return m_LastErrorCode = AddCertOrCRLToStore(pCRL,CMSG_CTRL_ADD_CRL);
}

std::string ICPCryptoImpl::getLastError()
{
    std::string str(GetLastCryptoError());
    return str;
}
/*virtual*/ CString ICPCryptoImpl::GetLastCryptoError()
{
	switch(m_LastErrorCode)	
	{
	case CCPC_NoError: return				"Operation finished successfully"; //"�������� ��������� �������";
	case CCPC_NotInitialized: return		"Initialization crypto error."; //������ ������������� �������������";
	case CCPC_CantLoadCSP: return			"CSP not found"; //�� ������� �������� CSP";
	case CCPC_OutOfMemory: return			"Not enought memory";//������. ������������ ������";
	case CCPC_FileNotSigned: return			"Verifications sign error " + m_strLastError; //������ ��������� ������� �� �����. "+ m_strLastError;
	case CCPC_VerifyFailed: return			"Certificates validation error " + m_strLastError; //�� ������� ��������� ���������������� �����������." + m_strLastError;
	case CCPC_InternalError: return			"Internal system error."; //�������� ��������� ������. ���������� � �������������";
	case CCPC_CantUnLoadCSP: return			"CSP upload error."; //�� ������� ��������� CSP";
	case CCPC_InvalidAltFileFormat: return	"Invalid data in alt-file " + m_strLastError; //�� ������� �������� ������ �� �����. " +m_strLastError;
	case CCPC_InvalidFileFormat: return		"Invalid data in file " + m_strLastError; //�� ������� �������� ������ �� �����. " +m_strLastError;
	case CCPC_CertNotValid: return			"Certificate is not valid " + m_strLastError; //���������� �� �����������. "+m_strLastError;
	case CCPC_CantCloseStore: return		"Can't close cert store"; //�������� ��������� �� ������� �������";
	case CCPC_CantFindCRLInStore: return	"Can't find CRL in cert store"; //�� ������� �������� CRL �� ���������";
	case CCPC_CantAddCRLInStore: return		"Can't add CRL to cert store"; //�� ������� �������� CRL � ���������";
	case CCPC_CantAddCertInStore: return	"Can't add certificate to cert store"; //�� ������� �������� ���������� � ���������";
	case CCPC_NoSender: return				"Uncorrect signers certificate"; // �� ������ ���������� �����������";
	case CCPC_CantDeleteCertFromStore:return "Uncorrect parametres for delete certificate in cert store"; //������� ������ ��������� ����������� ��� ��������";
	default: return m_strLastError;	
	}
	
	return m_strLastError;	
}

//NMS : ���������� ���� � ���������� �����
CString ICPCryptoImpl::GetTempFilePath(void)
{
	//NMS : ������� ������, ���� ��������� ������ ������ 100,
	//		�����, ������� ������ 50 ������
	const long nFiles=m_saTempFiles.GetSize();
	if (nFiles>100)
	{
		CStringArray saLastFiles;
		for (int nFile=0;nFile<nFiles;nFile++)
		{
			const CString& strFilePath=m_saTempFiles[nFile];
			if (nFile>50)
			{
				saLastFiles.Add(strFilePath);
			}
			else
			{
				CFileMng::DeleteFile(strFilePath);
			}
		}
		m_saTempFiles.RemoveAll();
		m_saTempFiles.Copy(saLastFiles);
	}
	CString strPath;
	char szTempPath[MAX_PATH]={0};
	GetTempPath (MAX_PATH-1,&szTempPath[0]);
	strPath=szTempPath;
	strPath.TrimRight("\\");
	CFileMng::CreatePaper(strPath);
	CFileFind ff;
	if (!ff.FindFile(strPath))
	{
		strPath=_T("");
	}
	ZeroMemory(&szTempPath[0],sizeof(szTempPath));	
	::GetTempFileName((LPCSTR)strPath,_T("taxcom"),0,&szTempPath[0]);
	CString sTempFileName=&szTempPath[0];
	m_saTempFiles.Add(sTempFileName);
	return sTempFileName;
}

//NMS : ������� ��� ��������� ����� � ������� ������
void ICPCryptoImpl::DeleteAllTempFiles(void)
{	
	const long nFiles=m_saTempFiles.GetSize();
	for (int nFile=0;nFile<nFiles;nFile++)
	{
		const CString& strFilePath=m_saTempFiles[nFile];
		CFileMng::DeleteFile(strFilePath);
	}
	m_saTempFiles.RemoveAll();
}

//NMS : �������� OID ��� �����������
bool ICPCryptoImpl::CertCheckOID(PCCERT_CONTEXT pCertContext,CString strOID)
{
	ASSERT(pCertContext!=NULL);
	//NMS : ���� OID ������, ����� �������
	if (strOID.IsEmpty())
	{
		return true;
	}
	bool bResult=false;	
	//NMS : �������, � ���� �� ����� oid � ��������
	FOR_ALL_STR(pOid,m_arrOIDPrefix)
	{
		WriteToLog(_T("���� � OID \"%s\" ��������� �� �������� \"%s\" ..."),strOID,*pOid);
		if (strOID.Find(*pOid)>=0)
		{
			WriteToLog(_T("�����."));
			bResult=true;
			break;
		}
	}
	if (bResult==false)
	{
		WriteToLog(_T("�� �����."));
		return false;
	}
	//NMS : ���������� ���������
	bResult=false;
	//NMS : ������ ������
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : �������� ������
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : ���������� � �������������
		CCertAutoBytePtr pUsagePtr((BYTE*)pUsage);
		if (::CertGetEnhancedKeyUsage(pCertContext,0,pUsage,&dwSize))
		{
			CString strOIDNow;
			for (int nItem=0;nItem<pUsage->cUsageIdentifier;nItem++)
			{
				strOIDNow=pUsage->rgpszUsageIdentifier[nItem];
				WriteToLog(_T("������ OID : %s."),(LPCTSTR)strOIDNow);
				if (strOIDNow==strOID)
				{
					WriteToLog(_T("OID \"%s\" �������� �������������� !"),strOID);
					bResult=true;
					break;
				}
			}
		}
	}
	else
	{
		WriteToLog(_T("�� ������� �������� ������ ������ OID, ������� : %s !"),CStringProc::GetSystemError());		
	}
	if (bResult==false)
	{
		WriteToLog(_T("OID \"%s\" �� �������� �������������� !"),strOID);
	}
	return bResult;
}
bool ICPCryptoImpl::CertGetOIDs(HCRYPTMSG hMsg, PCCERT_CONTEXT pCertContext,CStringArray& saOIDs)
{
	// �������� �� ������� ����
	//NMS : ������ ������
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : �������� ������
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : ���������� � �������������
		CCertAutoBytePtr pUsagePtr((BYTE*)pUsage);
		if (::CertGetEnhancedKeyUsage(pCertContext,0,pUsage,&dwSize))
		{
			CString strOIDOldFormat;
			for (int nItem=0;nItem<pUsage->cUsageIdentifier;nItem++)
			{
				strOIDOldFormat=pUsage->rgpszUsageIdentifier[nItem];
				saOIDs.Add(strOIDOldFormat);

			}
		}
	}
	
	// ������� �� ������ ����

	for (int iE=0;iE<pCertContext->pCertInfo->cExtension; iE++)
	{
		CString strObjId=pCertContext->pCertInfo->rgExtension[iE].pszObjId;
		if (strObjId!=szOID_CERT_POLICIES) // �������� ������������
		{
			
			continue;
		}
		CERT_POLICIES_INFO* pCPI=NULL;
		DWORD dwCPISize=0;
		//KAA : ������ ������ ������ ��� ����������
		if (!::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			strObjId,
			pCertContext->pCertInfo->rgExtension[iE].Value.pbData,
			pCertContext->pCertInfo->rgExtension[iE].Value.cbData,
			0,
			NULL,
			&dwCPISize))
		{
			continue;
		}
		pCPI=(CERT_POLICIES_INFO*)malloc(dwCPISize);

		CCertAutoBytePtr pCPIPtr((BYTE*)pCPI);
		
		//KAA : ��������� ���� ������
		if (!::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			strObjId,
			pCertContext->pCertInfo->rgExtension[iE].Value.pbData,
			pCertContext->pCertInfo->rgExtension[iE].Value.cbData,
			0,
			pCPI,
			&dwCPISize))
		{
			pCPIPtr.Free();
			continue;
		}
		for (int i= 0; i< pCPI->cPolicyInfo;i++)
		{
			saOIDs.Add(pCPI->rgPolicyInfo[i].pszPolicyIdentifier);
		}
		//NMS : ������� ������ ��� CRL_DIST_POINTS_INFO
	}
	return TRUE;
	
}
//NMS : ��������� ��������, ������ ������������ ������ ��� ����������� OID's
CString ICPCryptoImpl::CertGetEKUs(PCCERT_CONTEXT pCertContext)
{
	ASSERT(pCertContext!=NULL);
	WriteToLog(_T("�������� EKUs ��� �����������"));
	CString strResult;
	//NMS : ������ ������
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : �������� ������
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : ���������� � �������������
		CCertAutoBytePtr pUsagePtr((BYTE*)pUsage);
		if (::CertGetEnhancedKeyUsage(pCertContext,0,pUsage,&dwSize))
		{
			CString strOIDNow;
			for (int nItem=0;nItem<pUsage->cUsageIdentifier;nItem++)
			{
				strOIDNow=pUsage->rgpszUsageIdentifier[nItem];
				WriteToLog(_T("������ EKU : %s"),(LPCTSTR)strOIDNow);
				strResult+=_T(", EKU=")+strOIDNow;
			}
		}
	}
	return strResult;
}

//NMS : ��������� �������� ����� �������
CString ICPCryptoImpl::GetSignTime(HCRYPTMSG hMsg,DWORD dwSigner)
{
	ASSERT(hMsg!=NULL);
	//NMS : ������ ������
	DWORD dwSize=0x00;
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_AUTH_ATTR_PARAM,dwSigner,NULL,&dwSize))
	{
		WriteToLog(_T("ICPCryptoImpl::GetSignTime => CryptMsgGetParam ������� FALSE !"));
		return CString();
	}
	//NMS : �������� ������
	PCRYPT_ATTRIBUTES pattrs=(PCRYPT_ATTRIBUTES)malloc(dwSize);
	ASSERT(pattrs!=NULL);
	//NMS : ������ �������������
	CCertAutoBytePtr PattrsPtr((BYTE*)pattrs);
	//NMS : �������� ������
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_AUTH_ATTR_PARAM,dwSigner,pattrs,&dwSize))
	{
		WriteToLog(_T("ICPCryptoImpl::GetSignTime => CryptMsgGetParam ������� FALSE !"));
		return CString();
	}
	//NMS : ����������� �����
	CString strResult;
	for (int iA=0;iA<pattrs->cAttr;iA++)
	{
		if (strcmp(pattrs->rgAttr[iA].pszObjId,"1.2.840.113549.1.9.5")==0 &&
			pattrs->rgAttr[iA].cValue==1)
		{
			//NMS : �������� ������, ������ ������ ��������������� ������� ��������� FILETIME
			dwSize=0x00;			
			if (::CryptDecodeObject(X509_ASN_ENCODING,
									szOID_RSA_signingTime,
									pattrs->rgAttr[iA].rgValue[0].pbData,
									pattrs->rgAttr[iA].rgValue[0].cbData,
									0,
									NULL,
									&dwSize) &&
				dwSize==sizeof(FILETIME))
			{
				//NMS : ������� �����
				FILETIME ft;
				if (::CryptDecodeObject(X509_ASN_ENCODING,
										szOID_RSA_signingTime,
										pattrs->rgAttr[iA].rgValue[0].pbData,
										pattrs->rgAttr[iA].rgValue[0].cbData,
										0,
										&ft,
										&dwSize))
				{
					//NMS : ������������� �����
					SYSTEMTIME stZ,st;
					FileTimeToSystemTime(&ft,&stZ);
					TIME_ZONE_INFORMATION tz;
					GetTimeZoneInformation(&tz);
					SystemTimeToTzSpecificLocalTime(&tz,&stZ,&st);
					//NMS : ������������� ���������
					strResult.Format(_T("%.2d.%.2d.%.4d %.2d:%.2d:%.2d"),
									 st.wDay,st.wMonth,st.wYear,st.wHour,
									 st.wMinute,st.wSecond);
					break;
				}
			}
		}
	}
	//NMS : ���������� ���������
	return strResult;
}

//NMS : � ������� ���
int ICPCryptoImpl::CertDeleteFromStore(const LPCERTFINDPARAM lpCertFindParam)
{
	ASSERT(lpCertFindParam!=NULL);
	if (lpCertFindParam==NULL &&
		lpCertFindParam->dwFindInStore==0x00 &&
		(lpCertFindParam->strCN.IsEmpty() || (!lpCertFindParam->IsSetThumb())))
	{
		return m_LastErrorCode = CCPC_CantDeleteCertFromStore;
	}
	//WriteToLog("����� ICPCryptoImpl::CertDeleteFromStrote");	
	
	//NMS : ��������� ������ SST	
	int nResult=CertOpenStore(lpCertFindParam->dwFindInStore);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}	
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ���� ���������� � ���� ����� ������� ��� �� ���������
	PCCERT_CONTEXT pCertForDel=NULL;	

//	nResult=CertFind(lpCertFindParam,&pCertForDel);
	DWORD ptr = (DWORD)lpCertFindParam;
	nResult=CertFind((LPCERTFINDPARAM)ptr,&pCertForDel);
	
	if (nResult==CCPC_NoError)
	{
		if (::CertDeleteCertificateFromStore(pCertForDel))
		{
			nResult=CCPC_NoError;
		}
	}
	else
	{
		WriteToLog(_T("�� ������� ����� ���������� \"%s\" ��� �������� !"),
				   lpCertFindParam->strCN);

	}
	//NMS : ��������� ��������� � ����
	if (nResult==CCPC_NoError)
	{
		m_strLastError.Empty();
		nResult=SaveSSTInFile();
	}
	//NMS : ���������� ���������
	return m_LastErrorCode = nResult;
}

/*virtual*/ int ICPCryptoImpl::DelCertFromStore(CString strCN)
{
	ASSERT(strCN.IsEmpty()==FALSE);	
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

	CERTFINDPARAM FindParam;
	FindParam.dwFindInStore=CST_SST;
	FindParam.strCN=strCN;
	FindParam.bSkipCertIsValid=TRUE;
	int Result = CertDeleteFromStore(&FindParam);
#ifdef CTHREAD_UPDATE_CRL
	if (m_pCPCryptoCallBack!=NULL)
	{
		Result = m_pCPCryptoCallBack->OnDelCertFromStore(strCN,Result);
	}
#endif //
	return m_LastErrorCode = Result;
}

//NMS : ��������� �������� ���������� �� ��������� �� subject,email,thumb
/*virtual*/ int ICPCryptoImpl::GetCertFromStore(CString strSubjectOrEmail,CRYPT_DATA_BLOB* pCertBlob)
{
	ASSERT(strSubjectOrEmail.IsEmpty()==FALSE);	
	ASSERT(pCertBlob!=NULL);
	if (strSubjectOrEmail.IsEmpty() || pCertBlob==NULL)
	{
		return CCPC_InternalError;
	}
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}
    const LONG nStorageType=CST_ALL;
    const LONG nOpenStroreResult=CertOpenStore(nStorageType);
    if (nOpenStroreResult!=CCPC_NoError)
    {
        return m_LastErrorCode = nOpenStroreResult;
    }
	ZeroMemory(pCertBlob,sizeof(CRYPT_DATA_BLOB));
	CERTFINDPARAM FindParam;
	FindParam.dwFindInStore=nStorageType;
	FindParam.strCN=strSubjectOrEmail;
	FindParam.bSkipCertIsValid=TRUE;
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ���� ���������� � ���� ����� ������� ��� �� ���������
	PCCERT_CONTEXT pCertResult=NULL;	
	int nResult=CertFind(&FindParam,&pCertResult);
	if (nResult==CCPC_NoError)
	{
		pCertBlob->cbData=pCertResult->cbCertEncoded;
		pCertBlob->pbData=(LPBYTE)malloc(pCertBlob->cbData);
		if (pCertBlob->pbData!=NULL)
		{
			CopyMemory(pCertBlob->pbData,pCertResult->pbCertEncoded,
			pCertBlob->cbData);
			//NMS : �������
			nResult=CCPC_NoError;
		}
		else
		{
			nResult=CCPC_OutOfMemory;
		}
		//NMS : ������� �����������
		FindParam.ClearArrCerts();
	}
	return m_LastErrorCode = nResult;
}

//NMS : ��������� ������ SST � ����
int ICPCryptoImpl::SaveSSTInFile(HCERTSTORE hStore/*=NULL*/)
{
	int nResult=CCPC_CantSaveStore;
	if (hStore==NULL)
	{
		hStore=CertGetHandleStoreByType(CST_SST);
	}	
//	ASSERT(hStore!=NULL);	
	//NMS : ����� ��������� ���������� ������
		//NMS : ���������� ���� � �����, ���� � ���������� � ���� ���� ����������,
		//		��� ����������� CertOpenStore(CST_SST)
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : �������� ��������� ����
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif//
	ASSERT(!m_strRootPath.IsEmpty());
	CString strCertStorePath;
	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : ��������� ��������� � ����
	if (hStore!=NULL)
	{
		if (::CertSaveStore(hStore,
							PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							CERT_STORE_SAVE_AS_STORE,
							CERT_STORE_SAVE_TO_FILENAME_A,
							(void*)(LPCSTR)strCertStorePath,
							0)==FALSE)
		{
			nResult=CCPC_CantSaveStore;
			WriteToLog(_T("�� ������� ��������� ������ � ��������� certstore.sst, ���� \"%s\", ������� : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
		else
		{
			nResult=CCPC_NoError;
		}
	}
	//NMS : ���������� ���������
	return m_LastErrorCode = nResult;
}

/*virtual*/ int ICPCryptoImpl::FindCertificate(LPCTSTR szThumbprint, PCCERT_CONTEXT& pCertContext)
{

	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

    const LONG nStorageType=CST_ALL;
    const LONG nOpenStroreResult=CertOpenStore(nStorageType);
    if (nOpenStroreResult!=CCPC_NoError)
    {
        return m_LastErrorCode = nOpenStroreResult;
    }

	CERTFINDPARAM FindParam;
	FindParam.dwFindInStore=nStorageType;
	FindParam.strCN="";

	if (!ICPCryptoImpl::GetThumbFromStr(szThumbprint,&FindParam.cdbThumb))
		return m_LastErrorCode = CCPC_InternalError;

	FindParam.bSkipCertIsValid=TRUE;
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ���� ����������
	PCCERT_CONTEXT pCertResult=NULL;	
	int nResult=CertFind(&FindParam,&pCertResult);

	if (nResult==CCPC_NoError)
	{
			pCertContext = pCertResult;
			//NMS : �������
			nResult=CCPC_NoError;
	}
	else
	{
		pCertContext=NULL;
	}
		
	return m_LastErrorCode = nResult;

}

//KAA : ��������� ���������� �� ���������� ��� ��� �������� ��� ����������, ���������� CCPC_NoError ��� ��� ������
/*virtual*/ int ICPCryptoImpl::CheckCertificate(const PCCERT_CONTEXT pCertContext)
{
	//NMS : �������� ���������� �� ����������, � ��� �� 
	//		�������� ������� �����������		
	CERTVALIDPARAM ValidParam;
	if (!CertIsValid(pCertContext,&ValidParam))
	{
		return m_LastErrorCode = ValidParam.nResultCode;
	}
	return m_LastErrorCode = CCPC_NoError;
}

#ifdef CTHREAD_UPDATE_CRL
//KAA : �������� ��������� ������������ (� ������� HEX), �������������� ��� ���������� �� 141, ���������� CCPC_NoError ��� ��� ������
/*virtual*/ int ICPCryptoImpl::GetCertificateForDecryptFileAlt2(LPCTSTR szCryptedFileName, CRYPTALT2THUMBPRINTS* pCryptAlt2Thumbprints)
{
	if (!pCryptAlt2Thumbprints)
		return m_LastErrorCode = CCPC_InternalError;
	
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}
	
	//WriteToLog(_T("ICPCryptoImpl::DecryptFileAlt2"));	

	//NMS : ��������� ������ SST � MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}
	//NMS : ��������� SST � MY ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);

	//NMS : ��������� ����� �� ������ � ������
	CFile fIn;
	if (!fIn.Open(szCryptedFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   szCryptedFileName,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}

	//NMS : ��������� ������ �����
	int iVer=0;
	if (fIn.Read(&iVer,sizeof(iVer))!=sizeof(iVer) || iVer!=1)
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : ��������� ��������� ����������� �����������
	CRYPT_DATA_BLOB bThumbS;
	if (fIn.Read(&bThumbS.cbData,sizeof(bThumbS.cbData))!=sizeof(bThumbS.cbData))
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : �������� ������ ��� ���������
	bThumbS.pbData=new BYTE[bThumbS.cbData];
	ASSERT(bThumbS.pbData!=NULL);
	if (bThumbS.pbData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ��������� ����������� ����������� !"),
				   bThumbS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr bThumbSPtr(bThumbS.pbData,false);
	//NMS : ������ ���������
	if (fIn.Read(bThumbS.pbData,bThumbS.cbData)!=bThumbS.cbData)
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : ������ Subject �����������
	CERT_NAME_BLOB cNameS;
	if (fIn.Read(&cNameS.cbData,sizeof(cNameS.cbData))!=sizeof(cNameS.cbData))
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : �������� ������ ��� Subject
	cNameS.pbData=new BYTE[cNameS.cbData];
	ASSERT(cNameS.pbData!=NULL);
	if (cNameS.pbData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ subject ����������� !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr cNameSPtr(cNameS.pbData,false);
	//NMS : ������
	if (fIn.Read(cNameS.pbData,cNameS.cbData)!=cNameS.cbData)
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : ������ ���������
	CRYPT_DATA_BLOB bThumbR;
	if (fIn.Read(&bThumbR.cbData,sizeof(bThumbR.cbData))!=sizeof(bThumbR.cbData))
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : �������� ������ ��� ���������
	bThumbR.pbData=new BYTE[bThumbR.cbData];
	ASSERT(bThumbR.pbData!=NULL);
	if (bThumbR.pbData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ��������� ���������� !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr bThumbRPtr(bThumbR.pbData,false);
	//NMS : ������ ���������
	if (fIn.Read(bThumbR.pbData,bThumbR.cbData)!=bThumbR.cbData)
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : ������ subject ����������
	CERT_NAME_BLOB cNameR;
	if (fIn.Read(&cNameR.cbData,sizeof(cNameR.cbData))!=sizeof(cNameR.cbData))
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : �������� ������ ��� Subject
	cNameR.pbData=new BYTE[cNameR.cbData];
	ASSERT(cNameR.pbData!=NULL);
	if (cNameR.pbData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ subject ���������� !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr cNameRPtr(cNameR.pbData,false);
	//NMS : ������
	if (fIn.Read(cNameR.pbData,cNameR.cbData)!=cNameR.cbData)
	{
		WriteToLog(_T("���� \"%s\" ����� ��������� ������ !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : ����������� � ������
	CString sSubjS=CertNameBlob2Str(&cNameS,true),
			sSubjR=CertNameBlob2Str(&cNameR,true);
	//NMS : �����������
	cNameSPtr.Free();
	cNameRPtr.Free();

	CBinData bdR(bThumbR.pbData,bThumbR.cbData);
	CBinData bdS(bThumbS.pbData,bThumbS.cbData);

	CString strThumbPrintRecipient;
	bdR.Encode2Hex(strThumbPrintRecipient);
	memcpy(pCryptAlt2Thumbprints->RecipientThumbprint,(LPCTSTR)strThumbPrintRecipient,40);

	CString strThumbPrintSender;
	bdS.Encode2Hex(strThumbPrintSender);
	memcpy(pCryptAlt2Thumbprints->SenderThumbprint,(LPCTSTR)strThumbPrintSender,40);
	
	return m_LastErrorCode = CCPC_NoError;
}
#endif //