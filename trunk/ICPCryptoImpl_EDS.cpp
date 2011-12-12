#include "stdafx.h"
#include "ICPCryptoImpl.h"
#ifndef KILL_STREAM_INTERFACE
// #include "../../../lib_for_sprinter/Soft/UnifiedFormat/Common/UniqueFileNameGenerator.h"
#include <fstream>
#endif

#ifdef _DEBUG
	#undef THIS_FILE
	static char THIS_FILE[]=__FILE__;
	#define new DEBUG_NEW
#endif

//**********************************************************
//NMS : �������
//**********************************************************

// sSender == Subject\tOID
/*virtual*/ int ICPCryptoImpl::SignFileA(CString sSender, CString datasignFileName)
{
	int Result = SignFileEx(sSender, datasignFileName, datasignFileName,FALSE);
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
// ���� ��������� ��������� ������� �����, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
		Result = m_pCPCryptoCallBack->OnSignFile(sSender,datasignFileName,datasignFileName,Result);
	}
#endif //
	return m_LastErrorCode =Result;
}

/*virtual*/ int ICPCryptoImpl::SignFileD(CString sSender,
										 CString dataFileName,
										 CString signFileName)
{
	int Result = SignFileEx(sSender,dataFileName,signFileName,TRUE);
// ���� ��������� ��������� ������� �����, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		Result = m_pCPCryptoCallBack->OnSignFile(sSender,signFileName,dataFileName,Result);
	}
#endif //
	return m_LastErrorCode =Result;
}

// ���� dataFileName!="" �� � dataFileName ����� ���� ��� �������
/*virtual*/ int ICPCryptoImpl::CheckFileA(CString signFileName,
										  CString dataFileName,
										  CStringArray& saSignInfos,
										  BOOL bShowDlg)
{
	int Result = CertCheckFileEx(dataFileName, signFileName, saSignInfos, bShowDlg, FALSE);
// ���� ��������� ��������� ��������� �������, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		Result = m_pCPCryptoCallBack->OnCheckFile(signFileName, dataFileName,saSignInfos,bShowDlg,Result);
	}
#endif //
	return m_LastErrorCode =Result;
}
										 
/*virtual*/ int ICPCryptoImpl::CheckFileD(CString dataFileName,
										  CString signFileName,
										  CStringArray& saSignInfos, BOOL bShowDlg)
{
	int Result = CertCheckFileEx(dataFileName, signFileName, saSignInfos, bShowDlg, TRUE);
// ���� ��������� ��������� ��������� �������, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		Result = m_pCPCryptoCallBack->OnCheckFile(signFileName, dataFileName,saSignInfos,bShowDlg,Result);
	}
#endif //
	return m_LastErrorCode =Result;

}

// �������� ������� ������� (Subject\tOID) � �����
// � sSenderInfo ������������ �������� Subject �����������
/*virtual*/ int ICPCryptoImpl::CheckFileA(CString signFileName,
										  CString& sSenderInfo)
{

	int Result = CertCheckFileEx(_T(""), signFileName, sSenderInfo, FALSE);
// ���� ��������� ��������� ��������� �������, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		CStringArray saArr;
		saArr.Add(sSenderInfo);
		Result = m_pCPCryptoCallBack->OnCheckFile(signFileName,"",saArr,FALSE,Result);
		if (saArr.GetSize()==1)
			sSenderInfo = saArr.GetAt(0);
	}
#endif //
	return m_LastErrorCode =Result;
}

/*virtual*/ int ICPCryptoImpl::CheckFileD(CString dataFileName,
										  CString signFileName,
										  CString& sSenderInfo)
{
	int Result = CertCheckFileEx(dataFileName,signFileName,sSenderInfo,TRUE);
// ���� ��������� ��������� ��������� �������, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		CStringArray saArr;
		saArr.Add(sSenderInfo);
		Result = m_pCPCryptoCallBack->OnCheckFile(signFileName,dataFileName,saArr,TRUE,Result);
		if (saArr.GetSize()==1)
			sSenderInfo = saArr.GetAt(0);
	}
#endif //
	return m_LastErrorCode =Result;
}
int ICPCryptoImpl::UnpackSignedFile(CString datasignFileName, CString dataFileName)
{
	int Result = UnpackSignedFileEx(datasignFileName,dataFileName);
// ���� ��������� ��������� ���������� ������������ �����, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnUnpackSignedFile(datasignFileName,dataFileName,Result);
#endif //
	return m_LastErrorCode =Result;
}

/*virtual*/ int ICPCryptoImpl::UnpackSignedFileEx(CString datasignFileName,
												CString dataFileName)
{
	//WriteToLog(_T("����� ICPCryptoImpl::UnpackSignedFile"));

	//NMS : ��������� �����
	CFile fds,fd;
	if (!fds.Open(datasignFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� %s !"),
				   datasignFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	if (!fd.Open(dataFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� %s !"),
				   dataFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	//NMS : ������ ������ �� �����
	DWORD dwDataLen=fds.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ����� \"%s\" !"),
				  dwDataLen,datasignFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ������ ������
	fds.Read(bData,dwDataLen);
	fds.Close();

	//NMS : �������� ����� ������������������ ���������
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  0,0,0,NULL,NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("�� ������� �������� ����� ������������������ ���������, ������� %s !"),GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : ���������� ����������� ������ � ���������
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("�� ������� �������� ����������� ������ �� ����� \"%s\" � ����������������� ���������, ������� : %s !"),
				   datasignFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	//NMS : ����������� ������
	bDataPtr.Free();
	//NMS : ��������, � �������� �� ������ ��������
	DWORD dwCount=0x00;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
		WriteToLog(_T("�� ������� �������� ��� ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ��������� ���			
	if (dwCount!=CMSG_SIGNED)
	{
		WriteToLog(_T("���� \"%s\" �� �������� ������ ������� !"),datasignFileName);
		return m_LastErrorCode =CCPC_FileNotSigned;
	}
	//NMS : ������ ������, ������� ����� ������� � �������������� ����
	//NMS : ������ ������
	DWORD cbDecoded=0;	
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
		WriteToLog(_T("�� ������� �������� ������ ������ ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ������ ������, ������� ��� ���� ������	
	BYTE* pbDecoded=(BYTE*)malloc(cbDecoded);
	if (pbDecoded==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ��������� ������ ������������������ ��������� !"),
				   cbDecoded);
		int Result = CCPC_OutOfMemory;
		return m_LastErrorCode =Result;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr pbDecodedPtr(pbDecoded);
	//NMS : ��������� ���� ������	
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbDecoded,&cbDecoded))
	{
		WriteToLog(_T("�� ������� �������� ������ ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ������� ���������� ������ � �������������� ����
	fd.Write(pbDecoded,cbDecoded);
	fd.Close();
	//NMS : ���������� ����� !
	return m_LastErrorCode =CCPC_NoError;
}

//**********************************************************
//NMS : ����������
//**********************************************************

//NMS : ����������� ������ � �������������
void ICPCryptoImpl::FreeCertsArray(CArray<PCCERT_CONTEXT,PCCERT_CONTEXT>& arrCertRcpt)
{
	const long nRcptItems=arrCertRcpt.GetSize();
	for (long iC=0; iC<nRcptItems;iC++)
	{
		try	{
			::CertFreeCertificateContext(arrCertRcpt[iC]);
		}catch(...)
		{}
		
	}
	arrCertRcpt.RemoveAll();
}

int ICPCryptoImpl::EncryptFile(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs)
{
// ���� ��������� ��������� ���������� �����, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
	int Result = EncryptFileEx(plainFileName, cryptoFileName, saRecepientIDs);
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnEncryptFile(plainFileName,cryptoFileName,saRecepientIDs,Result);
#endif //
	return m_LastErrorCode =Result;
}

BOOL CheckCertOutOfDate (PCERT_INFO pCertInfo)
{
	if (pCertInfo == NULL)
		return FALSE;
	CTime tmNotBefore (pCertInfo->NotBefore);
	CTime tmNotAfter (pCertInfo->NotAfter);
	CTime tmCur (CTime::GetCurrentTime ());
	return tmNotBefore < tmCur && tmCur < tmNotAfter;
}

// saRecepientIDs == Array of (Subject\tOID)
/*virtual*/ int ICPCryptoImpl::EncryptFileEx(CString plainFileName,
										   CString cryptoFileName,
										   CStringArray& saRecepientIDs, CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> * pArrCertRcpt /* = NULL */)
{	
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	m_strLastError.Empty();

	//WriteToLog(_T("����� ICPCryptoImpl::EncryptFile"));		

	if (saRecepientIDs.GetSize()<1 && pArrCertRcpt == NULL)
	{		
		WriteToLog(_T("�� ������ ���������� ����������� !"));
		return m_LastErrorCode =CCPC_NoSender;
	}

	//NMS : ��������� �������� ����
	CFile fIn;
	if (!fIn.Open(plainFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	//NMS : ������ �� ���� ������	
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ����� \"%s\" !"),
				  dwDataLen,plainFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ������ ������ �� �����	
	fIn.Read(bData,dwDataLen);
	fIn.Close();
	//NMS : ��������� ������ SST � MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : ��������� SST � MY ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);	
	//NMS : ���� �� ����������� � ����������
	HCRYPTPROV hProv=NULL;
	CCertCryptProv hProvClose(&hProv);
	PCCERT_CONTEXT pRecipientCert=NULL;
	CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;	
	//NMS : ���� �� ������ ������������ ����������� � ����������� (���������� ��� � YAR)
	for (int iC=0;iC<saRecepientIDs.GetSize();iC++)
	{
		//NMS : �������� CN � OID
		CString sSender=saRecepientIDs[iC]+"\t\t";
		CString sSignerSubj=sSender.Left(sSender.Find("\t")); sSender.Delete(0,1+sSender.Find("\t"));
		CString sSignerOID=sSender.Left(sSender.Find("\t")); sSender.Delete(0,1+sSender.Find("\t"));		
		//NMS : ��������� ��������� ��� ������
		CERTFINDPARAM CertFindParam;
		//NMS : ����� ������������� ��������� � �������� �� ����
		CertFindParam.dwFindInStore=dwStoreTypes;
		CertFindParam.strCN=sSignerSubj;
		CertFindParam.strOID=sSignerOID;
		//NMS : ���� ���� ����������� ������������, ����� �������� ������������� �����
		CertFindParam.bSelAllCert=TRUE;
		CertFindParam.bSelFromAllStores=TRUE;		
		//NMS : ����
		if (CertFind(&CertFindParam,&pRecipientCert)==CCPC_NoError)
		{
			//NMS : ���� ��� ������ ������, ����� ����� �������� �������� ����,
			//		��� ��� ������ � ������ ����� �����������, � ��� ��������� ����������
			if (iC==0 && hProv==NULL)
			{
				//NMS : ��� ���������� ����������� �������� �������� ����
				if (!::CryptAcquireCertificatePrivateKey(pRecipientCert, 
														 CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG, 
														 NULL, 
														 &hProv,
														 NULL,
														 NULL))
				{
					WriteToLog(_T("�� ������� ����� �������� ���� ����������� ����������� : %s (%s) !"),sSignerSubj,sSignerOID);
					return m_LastErrorCode =CCPC_CantFindPrivateKey;
				}				
				//NMS : ������� ��� ��������� �����������
				//arrCertRcpt.Add(pRecipientCert);
				arrCertRcpt.Append(CertFindParam.arrCerts);												
			}
			else
			{
				//NMS : ������� ��� ��������� �����������
				arrCertRcpt.Append(CertFindParam.arrCerts);				
			}
		}
		else
		{
			//NMS : ����� � ���
			WriteToLog(_T("�� ������� ����� ���������� %s : %s(%s) !"),
					   (iC==0 ? _T("�����������"):_T("����������")),
					   sSignerSubj,sSignerOID);
			//NMS : 
			FreeCertsArray(arrCertRcpt);
			return m_LastErrorCode =CCPC_CantFindCertInStore;
		}		
	}

// �������� ����������� �� ��������� ����� ��������
	BOOL bCheckOutOfDate = TRUE;
	if (bCheckOutOfDate)
	{
		if (pArrCertRcpt)
		{
			for (int i = 0; i < pArrCertRcpt->GetSize (); i++)
				if (!CheckCertOutOfDate ((*pArrCertRcpt).GetAt (i)->pCertInfo))
				{
					WriteToLog(_T("���� �������� ����������� ��� ���������� ����� ��� ��� �� �������� (%s)!"),
						(LPCSTR)CertNameBlob2Str(&(*pArrCertRcpt).GetAt (i)->pCertInfo->Subject));
					FreeCertsArray(arrCertRcpt);
					return m_LastErrorCode =CCPC_CertNotValid;
				}
		}	else	{
			for (int i = 0; i < arrCertRcpt.GetSize (); i++)
				if (!CheckCertOutOfDate (arrCertRcpt.GetAt (i)->pCertInfo))
				{
					WriteToLog(_T("���� �������� ����������� ��� ���������� ����� ��� ��� �� �������� (%s)!"),
						(LPCSTR)CertNameBlob2Str(&arrCertRcpt.GetAt (i)->pCertInfo->Subject));
					FreeCertsArray(arrCertRcpt);
					return m_LastErrorCode =CCPC_CertNotValid;
				}
		}
	}

	//NMS : �������� ���������
	CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
	ZeroMemory(&EncryptParams,sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));	
	EncryptParams.cbSize=sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
	EncryptParams.dwMsgEncodingType=PKCS_7_ASN_ENCODING|X509_ASN_ENCODING;
	EncryptParams.hCryptProv=hProv;
	ZeroMemory(&EncryptParams.ContentEncryptionAlgorithm,
			   sizeof(EncryptParams.ContentEncryptionAlgorithm));
	EncryptParams.ContentEncryptionAlgorithm.pszObjId="1.2.643.2.2.21";
	//NMS : ������� ������
	//NMS : ������� ������ ������ ������, ������� ��������� ���
	//NMS : ������������ ������.
	BYTE*    pbEncryptedBlob=NULL;
	DWORD    cbEncryptedBlob=0x00;
	//NMS : ������ ������ ������
	if(!::CryptEncryptMessage(&EncryptParams,
							pArrCertRcpt ? pArrCertRcpt->GetSize () : arrCertRcpt.GetSize(),
							pArrCertRcpt ? pArrCertRcpt->GetData () : arrCertRcpt.GetData(),
							  bData,
							  dwDataLen,
							  NULL,
							  &cbEncryptedBlob))
	{
		WriteToLog(_T("�� ������� �������� ������ ������ ��� ������������� ������, ������� : %s !"),
				   GetSystemErrorDesc());
		FreeCertsArray(arrCertRcpt);
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ������� ������ ��� ������ ������
	pbEncryptedBlob=(BYTE*)malloc(cbEncryptedBlob);
	if (pbEncryptedBlob==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����� ��� ������������� ������ !"),cbEncryptedBlob);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoBytePtr pbEncryptedBlobPtr(pbEncryptedBlob);
	//NMS : �������� ������������� ������
	if(!::CryptEncryptMessage(&EncryptParams,
							pArrCertRcpt ? pArrCertRcpt->GetSize () : arrCertRcpt.GetSize(),
							pArrCertRcpt ? pArrCertRcpt->GetData () : arrCertRcpt.GetData(),
							  bData,
							  dwDataLen,
							  pbEncryptedBlob,
							  &cbEncryptedBlob))
	{
		WriteToLog(_T("�� ������� �������� ������������� ������, ������� : %s !"),
				   GetSystemErrorDesc());
		FreeCertsArray(arrCertRcpt);
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ����������� �������
	FreeCertsArray(arrCertRcpt);
	//NMS : ������ ������� �������������� ���� � ������� � ���� ���������� ����������
	nResult=CCPC_NoError;
	CFile fOut;
	if (fOut.Open(cryptoFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		//NMS : ���������� ������������� ������ � ����
		fOut.Write(pbEncryptedBlob,cbEncryptedBlob);
		fOut.Close();
		m_strLastError.Empty();
	}
	else
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   cryptoFileName,GetSystemErrorDesc());
		nResult=CCPC_CantOpenFileWrite;
	}	
	//NMS : ���������� ���������
	return m_LastErrorCode =nResult;
}
int ICPCryptoImpl::DecryptFile(CString cryptoFileName, CString plainFileName)
{
	int Result = DecryptFileEx(cryptoFileName, plainFileName);
	// ���� ��������� ��������� ����������� �����, ������� ���������� CCPC_NoError ���� ������, ��� ��� ������
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnDecryptFile(cryptoFileName,plainFileName,Result);
#endif //
	return m_LastErrorCode =Result;		
	
}

/*virtual*/ int ICPCryptoImpl::DecryptFileEx(CString cryptoFileName,
										   CString plainFileName)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	//WriteToLog(_T("����� ICPCryptoImpl::DecryptFile"));

	//NMS : �������� ������
	m_strLastError.Empty();
//	ASSERT(FALSE);

	//NMS : ��������� ������ �� ������������ �����
	CFile fIn;
	if (!fIn.Open(cryptoFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   cryptoFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	//NMS : ������ ������ ����� � ������� ������ ��� ������ ������ �� �����
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ����� \"%s\" !"),
				   dwDataLen,cryptoFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ������ ������ �� �����
	fIn.Read(bData,dwDataLen);
	fIn.Close();

	//NMS : ��������� ������ SST � MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : ��������� SST � MY ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : ������� �� MY � SST ������ �������
//	HCERTSTORE arrMyAndSST[2]={CertGetHandleStoreByType(CST_MY),CertGetHandleStoreByType(CST_SST)};
	HCERTSTORE arrMyAndSST[1]={CertGetHandleStoreByType(CST_MY)};//,CertGetHandleStoreByType(CST_SST)};
	//NMS : ��������� ��������� ��� ����������� ���������	
	CRYPT_DECRYPT_MESSAGE_PARA  DecryptParams;
	ZeroMemory(&DecryptParams,sizeof(CRYPT_DECRYPT_MESSAGE_PARA));		
	DecryptParams.cbSize=sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
	DecryptParams.dwMsgAndCertEncodingType=PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	DecryptParams.cCertStore=(sizeof(arrMyAndSST)/sizeof(arrMyAndSST[0]));
	if (CertGetHandleStoreByType(CST_SST)==NULL)
		DecryptParams.cCertStore = 1;
	DecryptParams.rghCertStore=arrMyAndSST;
	//NMS : ������ ������ ������ ��� �������������� ������
	BYTE* pbDecryptedMessage=NULL;
	DWORD cbDecryptedMessage=0x00;
	DWORD dwLenBlock = 64*1024*1024; // 
	dwDataLen;// = dwLenBlock;
	if(!CryptDecryptMessage(&DecryptParams,bData,dwDataLen,NULL,&cbDecryptedMessage,NULL))
	{
		WriteToLog(_T("�� ������� �������� ������ ��� �������������� ������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ������ ������, ������� ������
	pbDecryptedMessage=(BYTE*)malloc(cbDecryptedMessage);
	if (pbDecryptedMessage==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ �������������� ������ !"),
				   cbDecryptedMessage);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoBytePtr pbDecryptedMessagePtr(pbDecryptedMessage);
	//NMS : �������� �������������� ������
	if(!::CryptDecryptMessage(&DecryptParams,bData,dwDataLen,pbDecryptedMessage,&cbDecryptedMessage,NULL))
	{		
		WriteToLog(_T("�� ������� �������� �������������� ������, ������� : %s !"),GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ������� �������������� ���� � ������� ���� ���������
	CFile fOut;
	if (!fOut.Open(plainFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   plainFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	//NMS : ���������� ������ � ����
	fOut.Write(pbDecryptedMessage,cbDecryptedMessage);
	fOut.Close();
	//NMS : ���������� �����
	return m_LastErrorCode =CCPC_NoError;
}

//NMS : �������������� �������, ������� ����������� ����
int ICPCryptoImpl::SignFileEx(CString sSender,
							  CString dataFileName,
							  CString signFileName,
							  BOOL bDetached)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	//NMS : �������� ������
	m_strLastError.Empty();

	sSender+="\t\t";
	CString sSignerSubj=sSender.Left(sSender.Find("\t"));
	sSender.Delete(0,1+sSender.Find("\t"));

	CString sSignerOID=sSender.Left(sSender.Find("\t"));
	sSender.Delete(0,1+sSender.Find("\t"));

	//WriteToLog(_T("������� ICPCryptoImpl::SignFileEx : %s(%s)"),sSignerSubj,sSignerOID);
	
	CFile fIn, fOut;
	//NMS : ��������� ����
	if (!fIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\", ������� : %s !"),
				   dataFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}
	
	//NMS : ������ ����� ����� � �������� ����������� ���-�� ������
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("�� ������� �������� ������ ���������� ������ %d ���� ��� ����� \"%s\" !"),
				   dwDataLen,dataFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ������� ��������,������� ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ������ ������ �� �����
	fIn.Read(bData,dwDataLen);
	fIn.Close();

	//NMS : ��������� ������ SST � MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : ��������� SST � MY ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : ���� ���������� ��� �������
	CERTFINDPARAM CertFindParam;
	CertFindParam.dwFindInStore=dwStoreTypes;
	CertFindParam.strCN=sSignerSubj;
	CertFindParam.strOID=sSignerOID;
	PCCERT_CONTEXT pSenderCert=NULL;
	if (CertFind(&CertFindParam,&pSenderCert)!=CCPC_NoError)
	{
		WriteToLog(_T("�� ������� ����� �������������� ���������� ����������� : %s (%s) !"),
				   sSignerSubj,sSignerOID);
		return m_LastErrorCode =CCPC_CantFindCertInStore;
	}
	// �������� �� ���� ���������
	if (CertCheckCertRemain(pSenderCert)!=CCPC_NoError)
	{
		WriteToLog(_T("�������� �������� ���������, �.�. ���� �������� ������� ����������� %s �������������"),sSignerSubj);
		return m_LastErrorCode =CCPC_CertIsRemainExpiered;
	}

	//NMS : �������� �������� ����
	HCRYPTPROV	hProv=NULL;
	if (!::CryptAcquireCertificatePrivateKey(pSenderCert,
											 CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG,
											 NULL, 
											 &hProv,
											 NULL,
											 NULL))
	{
		WriteToLog(_T("�� ������� ����� �������� ���� ����������� ����������� : %s (%s) !"),
				   sSignerSubj,sSignerOID);
		return m_LastErrorCode =CCPC_CantFindPrivateKey;		
	}
	CCertCryptProv hProvClose(&hProv);

	//NMS : �������� ��������� CMSG_SIGNER_ENCODE_INFO

	CMSG_SIGNER_ENCODE_INFO seiSender;
	ZeroMemory(&seiSender,sizeof(CMSG_SIGNER_ENCODE_INFO));	
	seiSender.cbSize=sizeof(CMSG_SIGNER_ENCODE_INFO);
	seiSender.pCertInfo=pSenderCert->pCertInfo;
	seiSender.hCryptProv=hProv;
	seiSender.dwKeySpec=AT_KEYEXCHANGE;
	ZeroMemory(&seiSender.HashAlgorithm,sizeof(seiSender.HashAlgorithm));	
	seiSender.HashAlgorithm.pszObjId="1.2.643.2.2.9";
	seiSender.pvHashAuxInfo=NULL;

	//NMS : ��������� ��������� ����� � ������� ��� � ������ ����������������� (�����������)
	//		��������� PKCS#7 ��������� � ��������������� szOID_RSA_signingTime.

	PCRYPT_ATTRIBUTE pCA=NULL;
	PCRYPT_ATTR_BLOB pCAblob=NULL;
	BYTE* pbTimeStamp=NULL;
	CCertAutoBytePtr pbTimeStampPtr(NULL);
	CCertAutoBytePtr pCAPtr(NULL);
	CCertAutoBytePtr pCAblobPtr(NULL);

	SYSTEMTIME systemTime;
	FILETIME fileTime;
	GetSystemTime(&systemTime);
	SystemTimeToFileTime(&systemTime, &fileTime);
	DWORD dwTimeStamp=0x00;
	//NMS : �������� ������
	if (::CryptEncodeObject(X509_ASN_ENCODING,
							szOID_RSA_signingTime,
							(LPVOID)&fileTime,
							NULL,
							&dwTimeStamp))
	{
		pbTimeStamp=(BYTE*)malloc(dwTimeStamp);
		ASSERT(pbTimeStamp!=NULL);
		//NMS : ������ ��������� ��������������
		pbTimeStampPtr.Attach(pbTimeStamp);
		if (pbTimeStamp)
		{
			//NMS : ����������� ������� � ������� ���� szOID_RSA_signingTime
			
			if (::CryptEncodeObject(X509_ASN_ENCODING,
									szOID_RSA_signingTime,
									(LPVOID)&fileTime,
									pbTimeStamp,
									&dwTimeStamp))
			{
				//NMS : �������� ������
				pCA=new CRYPT_ATTRIBUTE;
				ASSERT(pCA!=NULL);
				pCAblob=new CRYPT_ATTR_BLOB;
				ASSERT(pCAblob!=NULL);
				//NMS : ������ ��������� ���������������
				pCAPtr.Attach((BYTE*)pCA,false);
				pCAblobPtr.Attach((BYTE*)pCAblob,false);
				//NMS : ��������� ��������
				pCA[0].pszObjId = szOID_RSA_signingTime;
				pCA[0].cValue = 1;
				pCA[0].rgValue = pCAblob;
				pCAblob[0].cbData = dwTimeStamp;
				pCAblob[0].pbData = pbTimeStamp;
				seiSender.cAuthAttr=1;
				seiSender.rgAuthAttr=pCA;
			}
		}
	}

	CMSG_SIGNER_ENCODE_INFO seiSenders[1];
	seiSenders[0]=seiSender;
	
	CERT_BLOB bSender;
	bSender.cbData=pSenderCert->cbCertEncoded;
	bSender.pbData=pSenderCert->pbCertEncoded;
	
	CERT_BLOB bSenders[1];
	bSenders[0]=bSender;
	
	CMSG_SIGNED_ENCODE_INFO seiMsg;
	memset (&seiMsg, 0, sizeof (seiMsg));
	seiMsg.cbSize=sizeof (seiMsg);
	seiMsg.cSigners=1;
	seiMsg.rgSigners=seiSenders;
	seiMsg.cCertEncoded=1;
	seiMsg.rgCertEncoded=bSenders;
	seiMsg.rgCrlEncoded=NULL;
	
	//NMS : ���������� ������
	DWORD dwSigned=::CryptMsgCalculateEncodedLength(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
													dwDetachedFlag,
													CMSG_SIGNED, 
													&seiMsg,
													NULL, 
													dwDataLen);
	if (dwSigned==0)
	{
		WriteToLog(_T("�� ������� ���������� ������ ��� �����������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : �������� ������ ��� ������������ ������		
	BYTE* pbSigned=(BYTE*)malloc(dwSigned);
	ASSERT(pbSigned!=NULL);
	if (pbSigned==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����������� !"),dwSigned);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoBytePtr pbSignedPtr(pbSigned);
	//NMS : �������� ����� ������������������ ���������
	HCRYPTMSG hMsg=::CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, 
										  dwDetachedFlag,
										  CMSG_SIGNED,
										  &seiMsg,
										  NULL,
										  NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("�� ������� ������� ����������������� ��������� ��� ����������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToEncode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);	

	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("�� ������� ��������� ���������� ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	//NMS : ������ ������� �������	
	if (!CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbSigned,&dwSigned))
	{
		WriteToLog(_T("�� ������� �������� �������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : ������-���� do ��� ������ �� ���� �� break.
	if (fIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	do 
	{
		//NMS : ������� _����������_ �������
		BYTE* bAppendData=NULL;
		DWORD dwAppendDataLen=0;
		//NMS : ������ ������ ����� � �������� �������� ������ ��� ���� ������
		dwAppendDataLen=fIn.GetLength();		
		bAppendData=(BYTE*)malloc(dwAppendDataLen);		
		if (bAppendData==NULL)
		{
			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������ ����� \"%s\" !"),
					   bAppendData,
					   signFileName);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		CCertAutoBytePtr bAppendDataPtr(bAppendData);
		//NMS : ������ �� �����
		fIn.Read(bAppendData,dwAppendDataLen);
		fIn.Close();
		
		//NMS : �������� ����� ������������������ ���������
		HCRYPTMSG hMsgAppend=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
													dwDetachedFlag,
													0,
													hProv,
													NULL,
													NULL);
		if (hMsgAppend==NULL)
		{
			break;
		}
		CCertCryptMsgClose hMsgAppendClose(&hMsgAppend);
		
		//NMS : �������� ������ � ���������		
		if (!::CryptMsgUpdate(hMsgAppend,bAppendData,dwAppendDataLen,TRUE))
		{
			break;
		}
		//NMS : �������, �������
		if (!::CryptMsgControl(hMsgAppend,
							   0,
							   CMSG_CTRL_ADD_SIGNER,
							   &seiSender))
		{
			break;
		}
		//NMS : ������� ����������
		if (!::CryptMsgControl(hMsgAppend,
							   0,
							   CMSG_CTRL_ADD_CERT,
							   &bSender))
		{
			break;
		}
		//NMS : �������� ������ �������
		dwSigned=0x00;		
		if (!::CryptMsgGetParam(hMsgAppend,
								CMSG_ENCODED_MESSAGE,
								0,
								NULL,
								&dwSigned))
		{
			break;
		}
		//NMS : ����������� ���������� ���������
		pbSignedPtr.Free();
		//NMS : �������� ������ ��� ����� �������
		pbSigned=(BYTE*)malloc(dwSigned);
		if (pbSigned==NULL)
		{
			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����������� !"),dwSigned);
			return m_LastErrorCode =CCPC_OutOfMemory;			
		}
		//NMS : ������ ��������� ��������������
		pbSignedPtr.Attach(pbSigned);
		//NMS : �������� �������			
		if (!::CryptMsgGetParam(hMsgAppend,
								CMSG_ENCODED_MESSAGE,
								0,
								pbSigned,
								&dwSigned))
		{
			WriteToLog(_T("�� ������� �������� �������, ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}		
	}
	while(false);
	//NMS : ������� ������� � ����
	if (!fOut.Open(signFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   signFileName,
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	fOut.Write(pbSigned, dwSigned);
	fOut.Close();
	//NMS : ��������� �������� ������	
	::CertFreeCertificateContext(pSenderCert);
	//NMS : ���������� �����
	return m_LastErrorCode =CCPC_NoError;
}

//NMS : ��������� �������
int ICPCryptoImpl::CertCheckFileEx(CString dataFileName, CString signFileName, CString& sSignerInfo, BOOL bDetached)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	//NMS : �������� ������
	m_strLastError.Empty();

	//WriteToLog(_T("����� ICPCryptoImpl::CertCheckFileEx(%d)"),__LINE__);

	sSignerInfo+="\t\t";
	CString sSignerSubj=sSignerInfo.Left(sSignerInfo.Find("\t")); sSignerInfo.Delete(0,1+sSignerInfo.Find("\t"));
	CString sSignerOID=sSignerInfo.Left(sSignerInfo.Find("\t")); sSignerInfo.Delete(0,1+sSignerInfo.Find("\t"));
	sSignerInfo="";
	

	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}	

	//NMS : ��������� ���� � ��������
	CFile fDataIn, fSignIn;
	if (!fSignIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
//		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),signFileName,GetSystemErrorDesc());
		WriteToLog(_T("Not read data: %s"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	if (bDetached)
	{
		//NMS : ��������� ���� � �������
		if (!fDataIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
		{
//			WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"), dataFileName,GetSystemErrorDesc());
			WriteToLog(_T("Not read data: %s"), GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantOpenFileRead;
		}
	}
	
	//NMS : ���������� ����� ������� � �������� ���
	//		��� ����� ������
	DWORD dwDataLen=fSignIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	ASSERT(bData!=NULL);
	if (bData==NULL)
	{
//		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����� \"%s\" !"), dwDataLen,signFileName);
		WriteToLog(_T("Memory allocation error: %s"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ��������� ������ �� ����� � ������� ���
	fSignIn.Read(bData,dwDataLen);
	fSignIn.Close();	
	//NMS : ���� ����� ������ ������ �� ����� ������
	DWORD dwDataDataLen=0;
	BYTE* bDataData=NULL;
	CCertAutoBytePtr bDataDataPtr(NULL);
	if (bDetached)
	{
		dwDataDataLen=fDataIn.GetLength();
		bDataData=(BYTE*)malloc(dwDataDataLen);
		if (bDataData==NULL)
		{
//			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����� \"%s\" !"), dwDataDataLen,dataFileName);
			WriteToLog(_T("%s"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : ������� ��������� ��������������
		bDataDataPtr.Attach(bDataData);
		//NMS : ������ ������ �� ����� � ��������� ���
		fDataIn.Read(bDataData,dwDataDataLen);
		fDataIn.Close();
	}
	//NMS : ������� ����� ���������
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  dwDetachedFlag,
										  0,
										  NULL,
										  NULL,										  
										  NULL);
	if (hMsg==NULL)
	{
//		WriteToLog(_T("�� ������� ������� ���������������, ������� : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Not open crypto message: %s"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : �������� � ��������� ������ �� ����� ������
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
//		WriteToLog(_T("�� ������� �������� ������ �� ����� \"%s\" � ���������, ������� : %s !"), signFileName,GetSystemErrorDesc());
		WriteToLog(_T("Not add data : %s !"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	bDataPtr.Free();
	if (bDetached)
	{
		//NMS : �������� � ��������� ������ �� ����� ������
		if (!::CryptMsgUpdate(hMsg,bDataData,dwDataDataLen,TRUE))
		{
//			WriteToLog(_T("�� ������� �������� ������ �� ����� \"%s\" � ���������, ������� : %s !"), dataFileName,GetSystemErrorDesc());
			WriteToLog(_T("Not add data : %s !"), GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantAddDataToMessage;
		}
		bDataDataPtr.Free();
	}

	DWORD dwCount=0;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
//		WriteToLog(_T("�� ������� �������� ��� ������������������ ���������, ������� : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Unknown type of cryptomessage : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ���� �������� �������� ???
	if (dwCount!=CMSG_SIGNED)
	{
//		WriteToLog(_T("���� \"%s\"  �� �������� ������ ������� !"),signFileName);
		WriteToLog(_T("Data is not sign : %s !"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_FileNotSigned;
	}

	//NMS : ������ �������������� ������
	DWORD cbDecoded = 0;
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
//		WriteToLog(_T("�� ������� �������� ������ ��� �������������, ������� : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Unknown length of cryptomessage : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}	
	//NMS : ��������� ��������� ��� ���������
	HCERTSTORE hMsgStore=::CertOpenStore(CERT_STORE_PROV_MSG,
										 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										 NULL,
										 0,
										 hMsg);
	if(hMsgStore==NULL)
	{
//		WriteToLog(_T("�� ������� ������� ��������� �� ������ ������������������ ���������, ������� : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Can't open certstore by handle : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantOpenStore;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoStore hMsgStoreAuto(hMsgStore);
	//NMS : ��������� ������ SST
	const DWORD dwStoreTypes=CST_SST;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : ������� �����
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : ������ ���-�� �����������
	DWORD dwSignersCount = 0;
	dwSize=sizeof(dwSignersCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_COUNT_PARAM,0,&dwSignersCount,&dwSize))
	{
//		WriteToLog(_T("�� ������� �������� ���������� �����������, ������� : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Failure number of signers : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : �������� ������� �� ���������� !
	BOOL bSigValid=FALSE;
    DWORD dwSigner(0);
	for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
	{
		DWORD cbSignerCertInfo = 0;
		//NMS : ������� ������ ���� � ����������
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,NULL,&cbSignerCertInfo))
		{
//			WriteToLog(_T("�� ������� �������� ������ ���������� � ����������, ������� : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure size of information about signer: %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ������ ������ �������� ������
		PCERT_INFO pSignerCertInfo=NULL;
		pSignerCertInfo=(PCERT_INFO)malloc(cbSignerCertInfo);
		if (pSignerCertInfo==NULL)
		{
//			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ���������� !"),cbSignerCertInfo);
			WriteToLog(_T("Failure allocation memory for information about signers : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : ������ ��������� ���������������
		CCertAutoBytePtr pSignerCertInfoPtr((BYTE*)pSignerCertInfo);
		//NMS : �������� ����
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,pSignerCertInfo,&cbSignerCertInfo))
		{		
//			WriteToLog(_T("�� ������� �������� ���������� � ����������, ������� : %s !"),GetSystemErrorDesc());
			WriteToLog(_T("Failure information about signer : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ������� ���������� ����������
		PCCERT_CONTEXT pSignerCertContext=NULL;		
		pSignerCertContext=::CertGetSubjectCertificateFromStore(hMsgStore,
																PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
																pSignerCertInfo);
		//NMS : ���� �� ����� � hMsgStore, ������ hSST
#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
		{

			PCCERT_CONTEXT pCertContext=NULL;
			BOOL bResolved= FALSE;
			if (bResolved = m_pCPCryptoCallBack->OnCertGetSubjectCertificate(pSignerCertInfo,pCertContext))
			{
				if(pCertContext!=NULL)
				{
					pSignerCertContext = ::CertDuplicateCertificateContext(pCertContext);
					m_pCPCryptoCallBack->OnCertFreeContext(pCertContext);
				}
			}
		}
#endif //
		if (pSignerCertContext==NULL && hSST!=NULL)
		{
			pSignerCertContext=::CertGetSubjectCertificateFromStore(hSST,
																	PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
																	pSignerCertInfo);
		}
		//NMS : �� ����� ���������� :(
		if(pSignerCertContext==NULL)
		{
//			WriteToLog(_T("�� ������� ����� ���������� ����������"));
			WriteToLog(_T("Signer certificate not found : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantFindCertInStore;
		}
		//NMS : �������� ���������� �� ���������� !		
		CERTVALIDPARAM ValidParam;
		bool bValid=CertIsValid(pSignerCertContext,&ValidParam);
		PCERT_INFO pSignerCertificateInfo=pSignerCertContext->pCertInfo;
		ASSERT(pSignerCertificateInfo!=NULL);
		//NMS : ������ ���� ���������� �������
		if (bValid!=false)
		{
			if (!::CryptMsgControl(hMsg,0,CMSG_CTRL_VERIFY_SIGNATURE,pSignerCertificateInfo))
			{
				bValid=false;
//				WriteToLog(_T("������� �� ����� :")+GetSystemErrorDesc());
				WriteToLog(_T("Sign is not valid : %s !"), GetSystemErrorDesc());
			}
		}
		CString sInfo=CertNameBlob2Str(&pSignerCertificateInfo->Subject);
		CString strSafeInfo(sInfo);
		//NMS : �������� �� Subject
		if (bValid && (sSignerSubj!=""))
		{
			WriteToLog(_T("Validation of subject : %s"),sSignerSubj);
			bValid=false;			
			WriteToLog(_T("Validation of subject: %s"),sInfo);
			sInfo.MakeLower();
			sSignerSubj.MakeLower();
			if (sInfo.Find(sSignerSubj)>=0)
			{
				bValid=true;
				WriteToLog(_T("Subject is valid!"));
			}
			else
			{
				WriteToLog(_T("Subject is not valid in \"%s\" not found \"%s\" !"),sInfo,sSignerSubj);
			}
		}		
		//NMS : �������� �� OID
/*********************************************************/
		// KAA : �� ������ ����������������� ����������, 
		//����� ���������� ������ �������� OID ������ ��������
/*
		if (bValid && (sSignerOID!=""))
		{			
			bValid=CertCheckOID(pSignerCertContext,sSignerOID);
		}
*/		
		CStringArray saOIDs;
		if (bValid)
		{
			CertGetOIDs(hMsg, pSignerCertContext,saOIDs);
		}
		
//*************************************************************/
		//NMS : ��������� sSignerInfo
		if (bValid)
		{
			//KAA : �� ����� ����������� �� ������ ������� �������, ������ ���� ������
			if (sSignerInfo.IsEmpty()==FALSE) // ���� �� ������ ������ ������� ������ �����������
				sSignerInfo += "\n\r###\n\r";

			sSignerInfo += strSafeInfo+"\t"+GetSignTime(hMsg,dwSigner);

           //NMS : �������� ���������
			CRYPT_DATA_BLOB Thumb;
			if (CertGetThumb( pSignerCertContext, &Thumb ))
			{
				CBinData bdCertThumb(Thumb.pbData, Thumb.cbData);
				CString sThumb;
				bdCertThumb.Encode2Hex( sThumb );
				sSignerInfo+="\t";
				sSignerInfo+=sThumb;
				delete [] Thumb.pbData; 

			}

			// KAA : ������� ���� � �������� OID�
			if (saOIDs.GetSize()>0)
			{
				sSignerInfo+="\tOID:";
				for (int i=0;i<saOIDs.GetSize();i++)
				{
					sSignerInfo+=saOIDs.GetAt(i) + ((i == saOIDs.GetSize()-1) ? "":";");
				}

			}
			bSigValid=TRUE;
			//KAA : �� ����� ����������� �� ������ ������� �������, ������ ���� ������
			//break;
			 
		}
	}
	//NMS : ���� ��� ������ ����������� ����������� � CLR
	if (bSigValid)
	{
		//NMS : ������ ������ ������������
		dwSize=sizeof(dwSignersCount);
		if (!::CryptMsgGetParam(hMsg,CMSG_CERT_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
//			WriteToLog(_T("�� ������� �������� ���������� �����������, ������� : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure number of signers : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ���������� �����������
		for (dwSigner=0; dwSigner<dwSignersCount; dwSigner++)
		{
			DWORD cbCert=0;
			BYTE* pCert=NULL;
			//NMS : �������� ������
			if (!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,NULL,&cbCert))
			{
//				WriteToLog(_T("�� ������� �������� ������ �����������, ������� : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Unknown size of certificate : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
				
			}
			//NMS : �������� ��� ������ ������
			pCert=(BYTE*)malloc(cbCert);
			if (pCert==NULL)
			{
//				WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ���������� !"),cbCert);
				WriteToLog(_T("Failure memory allocation for certificate : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : ������ ��������� ��������������
			CCertAutoBytePtr pCertPtr(pCert);
			//NMS : �������� ������ �����������
			if ((!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,pCert,&cbCert)) ||
				pCert==NULL)
			{
//				WriteToLog(_T("�� ������� �������� ������ �����������, ������� : %s !"),GetSystemErrorDesc());
				WriteToLog(_T("Failure certificates content : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : �� ������ ������� ��������, ����������			
			PCCERT_CONTEXT pCertContext=CertCreateCertificateContext(X509_ASN_ENCODING,pCert,cbCert);
			pCertPtr.Free();
			if(pCertContext==NULL)
			{
//				WriteToLog(_T("�� ������� ������� ���������� �� ������, ������� : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure creation of certificate by data : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantCreateCert;
			}
			//NMS : ���� ���������� �������, ���������
			int nErrorCode=CCPC_NoError;
			CERTVALIDPARAM ValidParam;
/* ���: ������� �������� �� ���������� ��� ������ � SST - ����� ������ �����������
			if (CertIsValid(pCertContext,&ValidParam))
*/
			{
				BOOL bResolved = FALSE;
#ifdef CTHREAD_UPDATE_CRL
				if (NULL!=m_pCPCryptoCallBack)
				{
					CRYPT_DATA_BLOB cdBlob;
					cdBlob.cbData = pCertContext->cbCertEncoded; 
					cdBlob.pbData = pCertContext->pbCertEncoded;
					bResolved = m_pCPCryptoCallBack->OnAddCertOrCRL(&cdBlob,CMSG_CTRL_ADD_CERT,nErrorCode);
				}
#endif //
				if (!bResolved)
					::CertAddCertificateContextToStore(hSST,
												   pCertContext,
												   CERT_STORE_ADD_NEWER,
												   NULL);
			}
			::CertFreeCertificateContext(pCertContext);
		}
		//NMS : ������ CRL-��
		dwSize=sizeof(dwSignersCount);
		if (!CryptMsgGetParam(hMsg,CMSG_CRL_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
//			WriteToLog(_T("�� ������� ��������, ���������� CRL, ������� : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure number of CRL : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
		{
			DWORD cbCRL = 0;
			BYTE* pCRL = NULL;
			//NMS : ������ ������
			if (!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,NULL,&cbCRL))
			{
//				WriteToLog(_T("�� ������� �������� ������ CLR, ������� %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure size of CRL : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : �������� ��� ���� ������ ������
			pCRL=(BYTE*)malloc(cbCRL);
			if (pCRL==NULL)
			{
//				WriteToLog(_T("�� ������� �������� %d ���� ������ ��� CLR, ������� : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure memory allocation for CRL : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : ������ ��������� ��������������
			CCertAutoBytePtr pCRLPtr(pCRL);
			//NMS : ������� �������� ���� ���������
			if ((!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,pCRL,&cbCRL)) ||
				pCRL==NULL)
			{
//				WriteToLog(_T("�� ������� �������� CLR, ������� : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure CRL receiving : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}

			BOOL bResolved = FALSE;
			int nErrorCode;
#ifdef CTHREAD_UPDATE_CRL
			if (NULL!=m_pCPCryptoCallBack)
			{
				CRYPT_DATA_BLOB cdBlob;
				cdBlob.cbData = cbCRL; 
				cdBlob.pbData = pCRL;
				bResolved = m_pCPCryptoCallBack->OnAddCertOrCRL(&cdBlob,CMSG_CTRL_ADD_CRL,nErrorCode);
			}
#endif //
			if (!bResolved)
			{
				
				PCCRL_CONTEXT pCRLContext=::CertCreateCRLContext(X509_ASN_ENCODING,pCRL,cbCRL);
				if (pCRLContext==NULL)
				{
//					WriteToLog(_T("�� ������� ������� CLR �� ������, ������� %s !"), GetSystemErrorDesc());
					WriteToLog(_T("Failure CRL creation by data : %s !"), GetSystemErrorDesc());

					return m_LastErrorCode =CCPC_CantCreateCRL;
				}
				//NMS : ���������			
				CertAddCRLContextToStore(hSST,pCRLContext,CERT_STORE_ADD_NEWER ,NULL);
				//NMS : ����������� ��������
				CertFreeCRLContext(pCRLContext);
			}
		}
	}
	CString strCertStorePath;

// KAA : �������� ���������� Dipost
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : �������� ��������� ����
		m_strRootPath.TrimRight(_T('\\'));	
	}

	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : ��������� ��������� � ����
	if (hSST != NULL) {
		if (::CertSaveStore(hSST,
							PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							CERT_STORE_SAVE_AS_STORE,
							CERT_STORE_SAVE_TO_FILENAME_A,
							(void*)(LPCSTR)strCertStorePath,
							0)==FALSE)
		{
			nResult=CCPC_CantOpenFileWrite;
			WriteToLog(_T("�� ������� ��������� ������ � ��������� certstore.sst, ���� \"%s\", ������� : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
	}
#endif //

	//NMS : ���������
	nResult=CCPC_VerifyFailed;
	if (bSigValid)
	{
		nResult=CCPC_NoError;
		//NMS : ������� ��������� ������
		m_strLastError.Empty();
	}
	//NMS : ������ ���������
	return m_LastErrorCode =nResult;
}

//NMS : ��������� �������
int ICPCryptoImpl::CertCheckFileEx(CString dataFileName,
								   CString signFileName,
								   CStringArray& saSignInfos,
								   BOOL bShowDlg,
								   BOOL bDetached)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	//WriteToLog(_T("����� ICPCryptoImpl::CertCheckFileEx(%s)"),__LINE__);

	//NMS : �������, ����, ��� �� ����� ��� ������������
	//		��������� ����������, ���������� ��� ����������� ��������� � ���������.
	BOOL bNotCheckCertValid=FALSE;

	// AKV: � saSignInfos ����� ������������ ��� Thumbs, ��� ������� ���� ��������� ����. ��������.
	/*
	if (saSignInfos.GetSize()==1 &&
		saSignInfos.GetAt(0).CompareNoCase(_T("#NOT_CHECK_CERT_VALID#"))==0)
	{
		bNotCheckCertValid=TRUE;
	}
	*/
	std::vector<CString> vecKeyIDs;
	LPCTSTR const cszThumbInfo = _T("#KEYID_FOR_CHECK#");
	size_t lenThumbInfo = _tcslen(cszThumbInfo);
	for (INT_PTR iInfoCount = 0; iInfoCount < saSignInfos.GetSize(); ++iInfoCount)
	{
		if (saSignInfos.GetAt(iInfoCount).CompareNoCase(_T("#NOT_CHECK_CERT_VALID#")) == 0)
		{
			bNotCheckCertValid = TRUE;
			continue;
		}
		// ��������� ��� CN
		if (_tcsnicmp(saSignInfos.GetAt(iInfoCount), cszThumbInfo, lenThumbInfo) == 0)
		{
			CString strKeyID = saSignInfos[iInfoCount];
			strKeyID.Delete(0, lenThumbInfo);
			vecKeyIDs.push_back(strKeyID);
		}
	}
	// AKV End
	
	saSignInfos.RemoveAll();

	//NMS : �������� ��������� ������
	m_strLastError.Empty();
	
	
	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}

	//NMS : ��������� ���� � ��������
	CFile fDataIn, fSignIn;
	if (!fSignIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
				   signFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	if (bDetached)
	{
		//NMS : ��������� ���� � �������
		if (!fDataIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
		{
			WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"),
					   dataFileName,GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantOpenFileRead;
		}
	}
	//NMS : ���������� ����� ������� � �������� ���
	//		��� ����� ������
	DWORD dwDataLen=fSignIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	ASSERT(bData!=NULL);
	if (bData==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����� \"%s\" !"),
				   dwDataLen,signFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������� ��������� ��������������
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : ��������� ������ �� ����� � ������� ���
	fSignIn.Read(bData,dwDataLen);
	fSignIn.Close();
	//NMS : ���� ����� ������ ������ �� ����� ������
	DWORD dwDataDataLen=0;
	BYTE* bDataData=NULL;
	CCertAutoBytePtr bDataDataPtr(NULL);
	if (bDetached)
	{
		dwDataDataLen=fDataIn.GetLength();
		bDataData=(BYTE*)malloc(dwDataDataLen);
		if (bDataData==NULL)
		{
			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ����� \"%s\" !"),
					   dwDataDataLen,dataFileName);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : ������� ��������� ��������������
		bDataDataPtr.Attach(bDataData);
		//NMS : ������ ������ �� ����� � ��������� ���
		fDataIn.Read(bDataData,dwDataDataLen);
		fDataIn.Close();
	}
	HCRYPTPROV	hProv=NULL;	
	if (!::CryptAcquireContext(&hProv,NULL,NULL,75,CRYPT_VERIFYCONTEXT))
	{
		throw CString(_T("�� ������� �������� �������� ���������������� !"));
	}
	CCertCryptProv hProvClose(&hProv);

	//NMS : ������� ����� ���������
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  dwDetachedFlag,
										  0,
										  hProv,
										  NULL,										  
										  NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("�� ������� ������� ��������������� ��� �����������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : �������� � ��������� ������ �� ����� ������
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("�� ������� �������� ������ �� ����� \"%s\" � ���������, ������� : %s !"),
				   signFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	bDataPtr.Free();
	if (bDetached)
	{
		//NMS : �������� � ��������� ������ �� ����� ������
		if (!::CryptMsgUpdate(hMsg,bDataData,dwDataDataLen,TRUE))
		{
			WriteToLog(_T("�� ������� �������� ������ �� ����� \"%s\" � ���������, ������� : %s !"),
					   dataFileName,GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantAddDataToMessage;
		}
		bDataDataPtr.Free();
	}

	DWORD dwCount=0;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
		WriteToLog(_T("�� ������� �������� ��� ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : ���� �������� �������� ???
	if (dwCount!=CMSG_SIGNED)
	{
		WriteToLog(_T("���� \"%s\"  �� �������� ������ ������� !"),signFileName);
		return m_LastErrorCode =CCPC_FileNotSigned;
	}

	//NMS : ������ �������������� ������
	DWORD cbDecoded = 0;
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
		WriteToLog(_T("�� ������� �������� ������ ��� �������������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}	
	BYTE* pbDecoded=NULL;
	CCertAutoBytePtr pbDecodedPtr(NULL);	
	//NMS : �������� ������
	pbDecoded=(BYTE *)malloc(cbDecoded);
	if (pbDecoded==NULL)
	{
		WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ������������� !"));
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : ������ �������������
	pbDecodedPtr.Attach(pbDecoded);
	//NMS : ������ ������
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbDecoded,&cbDecoded))
	{
		WriteToLog(_T("�� ������� ��������� �������������� ������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : ��������� ��������� ��� ���������
	HCERTSTORE hMsgStore=::CertOpenStore(CERT_STORE_PROV_MSG,
										 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										 NULL,
										 0,
										 hMsg);
	if(hMsgStore==NULL)
	{
		WriteToLog(_T("�� ������� ������� ��������� �� ������ ������������������ ���������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenStore;
	}
	//NMS : ������ ��������� ��������������
	CCertAutoStore hMsgStoreAuto(hMsgStore);
	//NMS : ��������� ������ SST
	const DWORD dwStoreTypes=CST_SST;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : ������� �����
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);

	//NMS : ������ ���-�� �����������
	DWORD dwSignersCount = 0;
	dwSize=sizeof(dwSignersCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_COUNT_PARAM,0,&dwSignersCount,&dwSize))
	{
		WriteToLog(_T("�� ������� �������� ���������� �����������, ������� : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : �������� ������� �� ���������� !
	bool bSigValid=true;
	CString strSignDateTime;
    DWORD dwSigner(0);
	for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
	{
		DWORD cbSignerCertInfo = 0;
		//NMS : ������� ������ ���� � ����������
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,NULL,&cbSignerCertInfo))
		{
			WriteToLog(_T("�� ������� �������� ������ ���������� � ����������, ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ������ ������ �������� ������
		PCERT_INFO pSignerCertInfo=NULL;
		pSignerCertInfo=(PCERT_INFO)malloc(cbSignerCertInfo);
		if (pSignerCertInfo==NULL)
		{
			WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ���������� !"),cbSignerCertInfo);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : ������ ��������� ���������������
		CCertAutoBytePtr pSignerCertInfoPtr((BYTE*)pSignerCertInfo);
		//NMS : �������� ����
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,pSignerCertInfo,&cbSignerCertInfo))
		{		
			WriteToLog(_T("�� ������� �������� ���������� � ����������, ������� : %s !"),GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ������� ���������� ����������
		PCCERT_CONTEXT pSignerCertContext=NULL;
		BOOL bResolved = FALSE;

#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
		{

			PCCERT_CONTEXT pCertContext=NULL;
			
			if (bResolved = m_pCPCryptoCallBack->OnCertGetSubjectCertificate(pSignerCertInfo,pCertContext))
			{
				if(pCertContext!=NULL)
				{
					pSignerCertContext = ::CertDuplicateCertificateContext(pCertContext);
					m_pCPCryptoCallBack->OnCertFreeContext(pCertContext);
				}
			}
			if (!bResolved || pCertContext==NULL)
			{
				WriteToLog(_T("�� ������� �������� ���������� ���������� �� ��"));
			}
		}
#endif //

		//NMS : ���� �� ����� � hMsgStore, ������ � hSST
		if (pSignerCertContext==NULL && hSST!=NULL)
		{
			pSignerCertContext=::CertGetSubjectCertificateFromStore(hSST,
				PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				pSignerCertInfo);
		}		
		
		if (pSignerCertContext==NULL)
		{
			
			pSignerCertContext=::CertGetSubjectCertificateFromStore(hMsgStore,
																PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
																pSignerCertInfo);
		}
		
		//NMS : �� ����� ���������� :(
		if(pSignerCertContext==NULL)
		{
			WriteToLog(_T("�� ������� ����� ���������� ����������, ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantFindCertInStore;
		}
		
		CCertFreeCertificateContext CertContextFree(&pSignerCertContext);
		//NMS : �������� ���������� �� ���������� !		
		CERTVALIDPARAM ValidParam;
		bool bValid=CertIsValid(pSignerCertContext,&ValidParam);
		//NMS : ���� � ���������� �����������
		const bool bCertValid=bValid;

		// AKV: ���������, ��� �� ��� ����������, ��� ������� ���� ���������.
		if (!vecKeyIDs.empty())
		{
			CRYPT_DATA_BLOB blob = {0};
			CString strSignerCN = GetCNFromCert(pSignerCertContext);
			CString strSignerThumb;
			if (CertGetThumb(pSignerCertContext, &blob))
			{
				GetStrFromThumb(&blob, strSignerThumb);
				delete[] blob.pbData;
			}
			for (std::vector<CString>::const_iterator itKeyID = vecKeyIDs.begin();
								itKeyID != vecKeyIDs.end(); ++itKeyID)
			{
				if ((strSignerThumb.CompareNoCase(*itKeyID) == 0) || (strSignerCN == *itKeyID))
					break;
				strSignerThumb.Empty();
				strSignerCN.Empty();
			}
			if (strSignerThumb.IsEmpty() && strSignerCN.IsEmpty())
			{
				bValid = false;
				m_strLastError = _T("���� ������ ���� �������� ������ ������������.");
			}
		}
		// AKV End

		PCERT_INFO pSignerCertificateInfo=pSignerCertContext->pCertInfo;		
		ASSERT(pSignerCertificateInfo!=NULL);
		CString sValidText;
		//NMS : ������ ���� ���������� �������
		bool bCheckSign=false;//NMS : ������� ����, ��� ������� ���������
		if (bCertValid!=false || bNotCheckCertValid==TRUE)
		{
			bCheckSign=true;
			//NMS : ���� �������, ����������� �����, ����� ���������� ���������� � ������
			if (bNotCheckCertValid!=FALSE)
			{
				bValid=true;
			}
			if (!::CryptMsgControl(hMsg,0,CMSG_CTRL_VERIFY_SIGNATURE,pSignerCertificateInfo))
			{
				bValid=false;
				WriteToLog(_T("������� �� ����� :")+GetSystemErrorDesc());
			}
		}
		//NMS : �������� �������
		if (bValid==false)
		{
			if (bCheckSign!=false)
			{
				sValidText=_T("������� �� ����� :")+GetSystemErrorDesc();
			}
			else
			{
				sValidText=_T("������� �� �����");
			}				
		}
		else
		{
			sValidText=_T("������� �����");
			strSignDateTime=GetSignTime(hMsg,dwSigner);
		}
		//NMS : ��� ����� ���������� ��� ����������	
		if (bCertValid!=false)
		{
			sValidText+=_T(" C��������� ������������");
		}
		else
		{
			sValidText+=_T(" C��������� �� ������������");
		}
		CString strSubject=CertNameBlob2Str(&pSignerCertificateInfo->Subject);
		CString sInfo=strSubject+"\t"+sValidText+"\t"+strSignDateTime;

		//NMS : �������� ���������
       CRYPT_DATA_BLOB Thumb;
       if (CertGetThumb( pSignerCertContext, &Thumb ))
	   {
           CBinData bdCertThumb(Thumb.pbData, Thumb.cbData);
           CString sThumb;
           bdCertThumb.Encode2Hex( sThumb );
           sInfo+="\t";
           sInfo+=sThumb;
		   delete[] Thumb.pbData;
       }
		saSignInfos.Add(sInfo);
		bSigValid&=bValid;
	}
	//NMS : ���� ��� ������ ����������� ����������� � CLR
	if (bSigValid)
	{
		//NMS : ������ ������ ������������
		dwSize=sizeof(dwSignersCount);
		if (!::CryptMsgGetParam(hMsg,CMSG_CERT_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
			WriteToLog(_T("�� ������� �������� ���������� �����������, ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : ���������� �����������
		for (dwSigner=0; dwSigner<dwSignersCount; dwSigner++)
		{
			DWORD cbCert=0;
			BYTE* pCert=NULL;
			//NMS : �������� ������
			if (!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,NULL,&cbCert))
			{
				WriteToLog(_T("�� ������� �������� ������ �����������, ������� : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
				
			}
			//NMS : �������� ��� ������ ������
			pCert=(BYTE*)malloc(cbCert);
			if (pCert==NULL)
			{
				WriteToLog(_T("�� ������� �������� %d ���� ������ ��� ���������� !"),cbCert);
				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : ������ ��������� ��������������
			CCertAutoBytePtr pCertPtr(pCert);
			//NMS : �������� ������ �����������
			if ((!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,pCert,&cbCert)) ||
				pCert==NULL)
			{
				WriteToLog(_T("�� ������� �������� ������ �����������, ������� : %s !"),GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : �� ������ ������� ��������, ����������			
			PCCERT_CONTEXT pCertContext=CertCreateCertificateContext(X509_ASN_ENCODING,pCert,cbCert);
			pCertPtr.Free();
			if(pCertContext==NULL)
			{
				WriteToLog(_T("�� ������� ������� ���������� �� ������, ������� : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantCreateCert;
			}
			//NMS : ���� ���������� �������, ���������
			int nErrorCode=CCPC_NoError;
			CERTVALIDPARAM ValidParam;
/* ���: ������� �������� �� ���������� ��� ������ � SST - ����� ������ �����������
			if (CertIsValid(pCertContext,&ValidParam))
*/
			{
				BOOL bResolved = FALSE;
#ifdef CTHREAD_UPDATE_CRL
				if (NULL!=m_pCPCryptoCallBack)
				{
					CRYPT_DATA_BLOB cdBlob;
					cdBlob.cbData = pCertContext->cbCertEncoded; 
					cdBlob.pbData = pCertContext->pbCertEncoded;
					bResolved = m_pCPCryptoCallBack->OnAddCertOrCRL(&cdBlob,CMSG_CTRL_ADD_CERT,nErrorCode);
				}
#endif //
				if (!bResolved)
					::CertAddCertificateContextToStore(hSST,
												   pCertContext,
												   CERT_STORE_ADD_NEWER,
												   NULL);
			}
			::CertFreeCertificateContext(pCertContext);
		}
		//NMS : ������ CRL-��
		dwSize=sizeof(dwSignersCount);
		if (!CryptMsgGetParam(hMsg,CMSG_CRL_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
			WriteToLog(_T("�� ������� ��������, ���������� CRL, ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
		{
			DWORD cbCRL = 0;
			BYTE* pCRL = NULL;
			//NMS : ������ ������
			if (!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,NULL,&cbCRL))
			{
				WriteToLog(_T("�� ������� �������� ������ CLR, ������� %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : �������� ��� ���� ������ ������
			pCRL=(BYTE*)malloc(cbCRL);
			if (pCRL==NULL)
			{
				WriteToLog(_T("�� ������� �������� %d ���� ������ ��� CLR, ������� : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : ������ ��������� ��������������
			CCertAutoBytePtr pCRLPtr(pCRL);
			//NMS : ������� �������� ���� ���������
			if ((!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,pCRL,&cbCRL)) ||
				pCRL==NULL)
			{
				WriteToLog(_T("�� ������� �������� CLR, ������� : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}

			BOOL bResolved = FALSE;
			int nErrorCode;
#ifdef CTHREAD_UPDATE_CRL
			if (NULL!=m_pCPCryptoCallBack)
			{
				CRYPT_DATA_BLOB cdBlob;
				cdBlob.cbData = cbCRL; 
				cdBlob.pbData = pCRL;
				bResolved = m_pCPCryptoCallBack->OnAddCertOrCRL(&cdBlob,CMSG_CTRL_ADD_CRL,nErrorCode);
			}
#endif //
			if (!bResolved)
			{
				
				PCCRL_CONTEXT pCRLContext=::CertCreateCRLContext(X509_ASN_ENCODING,pCRL,cbCRL);
				if (pCRLContext==NULL)
				{
					WriteToLog(_T("�� ������� ������� CLR �� ������, ������� %s !"),
						GetSystemErrorDesc());
					return m_LastErrorCode =CCPC_CantCreateCRL;
				}
				//NMS : ���������			
				CertAddCRLContextToStore(hSST,pCRLContext,CERT_STORE_ADD_NEWER ,NULL);
				//NMS : ����������� ��������
				CertFreeCRLContext(pCRLContext);
			}
		}
	}
	//NMS : ������� �������������� ������ � ����
	if (!bDetached && dataFileName!="")
	{
		CFile fOut;
		if (!fOut.Open(dataFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
		{
			WriteToLog(_T("�� ������� ������� ���� \"%s\" �� ������, ������� : %s !"));
			return m_LastErrorCode =CCPC_CantOpenFileWrite;
		}
		//NMS : ����������
		fOut.Write(pbDecoded,cbDecoded);
		//NMS : ���������
		fOut.Close();
	}

	CString strCertStorePath;

// KAA : �������� ���������� Dipost
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : �������� ��������� ����
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif //
	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : ��������� ��������� � ����
	if (hSST != NULL) {
		if (::CertSaveStore(hSST,
							PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							CERT_STORE_SAVE_AS_STORE,
							CERT_STORE_SAVE_TO_FILENAME_A,
							(void*)(LPCSTR)strCertStorePath,
							0)==FALSE)
		{
			nResult=CCPC_CantOpenFileWrite;
			WriteToLog(_T("�� ������� ��������� ������ � ��������� certstore.sst, ���� \"%s\", ������� : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
	}
	//NMS : ��������� ���������
	nResult=CCPC_NoError;
	if (bSigValid==FALSE)
	{
		nResult=CCPC_VerifyFailed;
	}
	else
	{
		//NMS : ������� ��������� ������
		m_strLastError.Empty();
	}
	//NMS : ���������� ��������� !
	return m_LastErrorCode =nResult;	
}
#ifndef KILL_STREAM_INTERFACE
/* LLP
���� ������ � ������ �������� �� ������ ������ �������(((
������� ������� ��������� ����� � �������� ����� ���...
*/
int ICPCryptoImpl::encrypt(std::istream& plainStream, std::ostream& cryptoStream,
                    std::vector<std::string>& recepientIDs, ICPCrypto::Cryptography crypt /*= Default*/)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string plainTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream plainTmpFile(plainTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile plainTmpFileNameDeleter(plainTmpFileName);
    std::string cryptoTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    plainTmpFile << plainStream.rdbuf();
    plainTmpFile.close();
    
    CStringArrayEx arr;
    for(std::vector<std::string>::iterator it = recepientIDs.begin();
        it != recepientIDs.end(); ++it)
    {
        arr.Add((*it).c_str());
    }
    switch(crypt)
    {
    /*case Alt:
        ret = EncryptFileAlt(plainTmpFileName.c_str(), cryptoTmpFileName.c_str(), arr);
        break;*/
    case Alt2:
        ret = EncryptFileAlt2(plainTmpFileName.c_str(), cryptoTmpFileName.c_str(), arr);
        break;
    default:
        ret = EncryptFile(plainTmpFileName.c_str(), cryptoTmpFileName.c_str(), arr);
        break;
    }
    // �� ���� ��...
    //////////////////////////////////////////////////////////////////////////
    recepientIDs.clear();
    for(int i = 0; i < arr.GetSize(); ++i)
    {
        recepientIDs.push_back(static_cast<LPCTSTR>(arr[i]));
    }
    //////////////////////////////////////////////////////////////////////////
    std::ifstream cryptoTmpFile(cryptoTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile cryptoTmpFileDeleter(cryptoTmpFileName);
    if(cryptoTmpFile.is_open())
    {
        cryptoStream << cryptoTmpFile.rdbuf();
        cryptoTmpFile.close();
    }
    return ret;
}

int ICPCryptoImpl::decrypt(std::istream& cryptoStream, std::ostream& plainStream,
                           ICPCrypto::Cryptography crypt /*= Default*/)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string cryptoTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream cryptoTmpFile(cryptoTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile cryptoTmpFileDeleter(cryptoTmpFileName);
    std::string plainTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    cryptoTmpFile << cryptoStream.rdbuf();
    cryptoTmpFile.close();

    switch(crypt)
    {
    /*case Alt:
        ret = DecryptFileAlt(cryptoTmpFileName.c_str(), plainTmpFileName.c_str());
        break;*/
    case Alt2:
        ret = DecryptFileAlt2(cryptoTmpFileName.c_str(), plainTmpFileName.c_str());
        break;
    default:
        ret = DecryptFile(cryptoTmpFileName.c_str(), plainTmpFileName.c_str());
        break;
    }
    std::ifstream plainTmpFile(plainTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile plainTmpFileNameDeleter(plainTmpFileName);
    if(plainTmpFile.is_open())
    {
        plainStream << plainTmpFile.rdbuf();
        plainTmpFile.close();
    }
    return ret;
}
int ICPCryptoImpl::signStreamAttach (const std::string &sender, std::istream& dataStream,
                                   std::ostream& datasignStream)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string dataTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream dataTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile dataTmpFileNameDeleter(dataTmpFileName);
    dataTmpFile << dataStream.rdbuf();
    dataTmpFile.close();

    ret = SignFileA(sender.c_str(), dataTmpFileName.c_str());

    std::ifstream datasignTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    if(datasignTmpFile.is_open())
    {
        datasignStream << datasignTmpFile.rdbuf();
        datasignTmpFile.close();
    }
    return ret;
}
int ICPCryptoImpl::signStreamDetach (const std::string &sender, std::istream& dataStream,
                                   std::ostream& signStream)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string dataTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream dataTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile dataTmpFileNameDeleter(dataTmpFileName);
    std::string signTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    dataTmpFile << dataStream.rdbuf();
    dataTmpFile.close();

    ret = SignFileD(sender.c_str(), dataTmpFileName.c_str(), signTmpFileName.c_str());

    std::ifstream signTmpFile(signTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile signTmpFileNameDeleter(signTmpFileName);
    if(signTmpFile.is_open())
    {
        signStream << signTmpFile.rdbuf();
        signTmpFile.close();
    }
    return ret;
}

int ICPCryptoImpl::checkStreamAttach (std::istream& signStreamName, std::ostream& dataStreamName,
                                      std::vector<std::string>& signInfos, bool bShowDlg)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string signTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream signTmpFile(signTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile signTmpFileNameDeleter(signTmpFileName);
    std::string dataTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");

    signTmpFile << signStreamName.rdbuf();
    signTmpFile.close();

    CStringArrayEx arr;
    for(std::vector<std::string>::iterator it = signInfos.begin();
        it != signInfos.end(); ++it)
    {
        arr.Add((*it).c_str());
    }
    ret = CheckFileA(signTmpFileName.c_str(), dataTmpFileName.c_str(), arr, bShowDlg ? TRUE:FALSE);
    // �� ���� ��...
    //////////////////////////////////////////////////////////////////////////
    signInfos.clear();
    for(int i = 0; i < arr.GetSize(); ++i)
    {
        signInfos.push_back(static_cast<LPCTSTR>(arr[i]));
    }
    //////////////////////////////////////////////////////////////////////////
    std::ifstream dataTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile dataTmpFileNameDeleter(dataTmpFileName);
    if(dataTmpFile.is_open())
    {
        dataStreamName << dataTmpFile.rdbuf();
        dataTmpFile.close();
    }
    return ret;
}
int ICPCryptoImpl::checkStreamDetach (std::istream& dataStreamName, std::istream& signStreamName,
                                      std::vector<std::string>& signInfos, bool bShowDlg)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string signTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream signTmpFile(signTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile signTmpFileNameDeleter(signTmpFileName);
    std::string dataTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream dataTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile dataTmpFileNameDeleter(dataTmpFileName);
    signTmpFile << signStreamName.rdbuf();
    signTmpFile.close();
    dataTmpFile << dataStreamName.rdbuf();
    dataTmpFile.close();

    CStringArrayEx arr;
    for(std::vector<std::string>::iterator it = signInfos.begin();
        it != signInfos.end(); ++it)
    {
        arr.Add((*it).c_str());
    }
    ret = CheckFileD(dataTmpFileName.c_str(), signTmpFileName.c_str(), arr, bShowDlg ? TRUE:FALSE);
    // �� ���� ��...
    //////////////////////////////////////////////////////////////////////////
    signInfos.clear();
    for(int i = 0; i < arr.GetSize(); ++i)
    {
        signInfos.push_back(static_cast<LPCTSTR>(arr[i]));
    }
    //////////////////////////////////////////////////////////////////////////
    return ret;
}

int ICPCryptoImpl::checkStreamAttach (std::istream& signStreamName, std::string& sSenderInfo)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string signTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream signTmpFile(signTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile signTmpFileNameDeleter(signTmpFileName);
    signTmpFile << signStreamName.rdbuf();
    signTmpFile.close();
    CString senderInfo(sSenderInfo.c_str());
    ret = CheckFileA(signTmpFileName.c_str(), senderInfo);
    sSenderInfo = senderInfo;
    return ret;
}
int ICPCryptoImpl::checkStreamDetach (std::istream& dataStreamName, std::istream& signStreamName,
                             std::string& sSenderInfo)
{
    int ret(-1);
    UnifiedFormat::UniqueFileNameGenerator fileGen;
    std::string signTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream signTmpFile(signTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile signTmpFileNameDeleter(signTmpFileName);
    std::string dataTmpFileName = fileGen.GetName(fileGen.GetTmpDir(), "tmp");
    std::ofstream dataTmpFile(dataTmpFileName.c_str(), std::ios::binary);
    AutoDeleterFile dataTmpFileNameDeleter(dataTmpFileName);
    signTmpFile << signStreamName.rdbuf();
    signTmpFile.close();
    dataTmpFile << dataStreamName.rdbuf();
    dataTmpFile.close();
    CString senderInfo(sSenderInfo.c_str());
    ret = CheckFileD(dataTmpFileName.c_str(), signTmpFileName.c_str(), senderInfo);
    sSenderInfo = senderInfo;
    return ret;
}
#endif
