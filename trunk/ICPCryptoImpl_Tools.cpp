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
//NMS : Сервис
//**********************************************************

/*virtual*/ int ICPCryptoImpl::ViewStore(CStringArray& saResult)
{	
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

	//WriteToLog("Вызов ICPCryptoImpl::ViewStore");	

	//NMS : Почистим
	saResult.RemoveAll();	

	//NMS : Открываем только SST	
	int nResult=CertOpenStore(CST_SST);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this);
	//NMS : Получим хендл открытого SST
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : Перебираем сертификаты	
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
		//NMS : Чистим
		sStrToAdd.Empty();

		//NMS : Читаем серийный номер сертификата 
		CString sCertSerial;
		for (int iS=0; iS<pCert->pCertInfo->SerialNumber.cbData; iS++)
		{
			CString st2;
			st2.Format("%.2X",pCert->pCertInfo->SerialNumber.pbData[iS]);
			sCertSerial=st2+sCertSerial;
		}
		sStrToAdd+=sCertSerial+_T("\t");
		//NMS : Читаем subject
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
		//NMS : Узнаем кто выдавал сертификат
		CString strIssuer=CertNameBlob2Str(&pCert->pCertInfo->Issuer);
		sStrToAdd+=strIssuer+_T("\t");
		//NMS : Читаем даты
		CTime tm;
		tm=pCert->pCertInfo->NotBefore;
		sStrToAdd+=tm.Format("%d.%m.%Y %H:%M:%S")+_T("\t");
		tm=pCert->pCertInfo->NotAfter;
		sStrToAdd+=tm.Format("%d.%m.%Y %H:%M:%S")+_T("\t");
		//NMS : Проверяем на валидность		
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
			// AKV: Очищаем thumb::pbData, которая выделяется в CertGetThumb
			delete[] thumb.pbData;
		}
// SMU: Add only subject
		{
			CString sForAdd;
			CStringProc::SetTagValue (sForAdd, STR_TAG_CERT_CN, strSubject);
			sStrToAdd += '\t' + sForAdd;
		}
		//NMS : Добавим данные в результирующий массив		
		saResult.Add(sStrToAdd);
	}
	while(pCert!=NULL);	
	//NMS : Возвращаем успех !
	return m_LastErrorCode = CCPC_NoError;
}

/*virtual*/ int ICPCryptoImpl::UpdateCRLs()
{	
	//NMS : Обновляет CRLs для CST_SST
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
	//NMS : Загрузим из файла
	CRYPT_DATA_BLOB cert;
	ZeroMemory(&cert,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCertFile,&cert);
	CCertAutoBytePtr certPtr(cert.pbData);
	if (nResult==CCPC_NoError)
	{
		//NMS : Добавим в хранилище
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
	//NMS : Загрузим из файла
	CRYPT_DATA_BLOB CRL;
	ZeroMemory(&CRL,sizeof(CRYPT_DATA_BLOB));
	long nResult=CryptDataBlobFromFile(sCRLFile,&CRL);
	CCertAutoBytePtr CRLPtr(CRL.pbData);
	if (nResult==CCPC_NoError)
	{
		//NMS : Добавим в хранилище
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
	case CCPC_NoError: return				"Operation finished successfully"; //"Операция завершена успешно";
	case CCPC_NotInitialized: return		"Initialization crypto error."; //Ошибка инициализации крипотсистемы";
	case CCPC_CantLoadCSP: return			"CSP not found"; //Не удалось получить CSP";
	case CCPC_OutOfMemory: return			"Not enought memory";//Ошибка. Недостаточно памяти";
	case CCPC_FileNotSigned: return			"Verifications sign error " + m_strLastError; //Ошибка получения подписи из файла. "+ m_strLastError;
	case CCPC_VerifyFailed: return			"Certificates validation error " + m_strLastError; //Не удалось проверить действительность сертификата." + m_strLastError;
	case CCPC_InternalError: return			"Internal system error."; //Возникла системная ошибка. Обратитесь к разработчикам";
	case CCPC_CantUnLoadCSP: return			"CSP upload error."; //Не удалось выгрузить CSP";
	case CCPC_InvalidAltFileFormat: return	"Invalid data in alt-file " + m_strLastError; //Не удалось получить данные из файла. " +m_strLastError;
	case CCPC_InvalidFileFormat: return		"Invalid data in file " + m_strLastError; //Не удалось получить данные из файла. " +m_strLastError;
	case CCPC_CertNotValid: return			"Certificate is not valid " + m_strLastError; //Сертификат не дейсвителен. "+m_strLastError;
	case CCPC_CantCloseStore: return		"Can't close cert store"; //Файловое хранилище не удалось закрыть";
	case CCPC_CantFindCRLInStore: return	"Can't find CRL in cert store"; //Не удалось получить CRL из хранилища";
	case CCPC_CantAddCRLInStore: return		"Can't add CRL to cert store"; //Не удалось добавить CRL в хранилище";
	case CCPC_CantAddCertInStore: return	"Can't add certificate to cert store"; //Не удалось добавить Сертификат в хранилище";
	case CCPC_NoSender: return				"Uncorrect signers certificate"; // Не указан сертификат отправителя";
	case CCPC_CantDeleteCertFromStore:return "Uncorrect parametres for delete certificate in cert store"; //Неверно заданы параметры сертификата для удаления";
	default: return m_strLastError;	
	}
	
	return m_strLastError;	
}

//NMS : Возвращает путь к временному файлу
CString ICPCryptoImpl::GetTempFilePath(void)
{
	//NMS : Сборщик мусора, если временных файлов больше 100,
	//		тогда, удаляем первые 50 файлов
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

//NMS : Удаляет все временные файлы и очищает массив
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

//NMS : Проверка OID для сертификата
bool ICPCryptoImpl::CertCheckOID(PCCERT_CONTEXT pCertContext,CString strOID)
{
	ASSERT(pCertContext!=NULL);
	//NMS : Если OID пустой, тогда выходим
	if (strOID.IsEmpty())
	{
		return true;
	}
	bool bResult=false;	
	//NMS : Смотрим, а есть ли такой oid в лицензии
	FOR_ALL_STR(pOid,m_arrOIDPrefix)
	{
		WriteToLog(_T("Ищем в OID \"%s\" вхождение из лицензии \"%s\" ..."),strOID,*pOid);
		if (strOID.Find(*pOid)>=0)
		{
			WriteToLog(_T("Нашли."));
			bResult=true;
			break;
		}
	}
	if (bResult==false)
	{
		WriteToLog(_T("Не нашли."));
		return false;
	}
	//NMS : Сбрасываем результат
	bResult=false;
	//NMS : Узнаем размер
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : Выделяем память
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : Превращаем в автоуказатель
		CCertAutoBytePtr pUsagePtr((BYTE*)pUsage);
		if (::CertGetEnhancedKeyUsage(pCertContext,0,pUsage,&dwSize))
		{
			CString strOIDNow;
			for (int nItem=0;nItem<pUsage->cUsageIdentifier;nItem++)
			{
				strOIDNow=pUsage->rgpszUsageIdentifier[nItem];
				WriteToLog(_T("Найден OID : %s."),(LPCTSTR)strOIDNow);
				if (strOIDNow==strOID)
				{
					WriteToLog(_T("OID \"%s\" является действительным !"),strOID);
					bResult=true;
					break;
				}
			}
		}
	}
	else
	{
		WriteToLog(_T("Не удалось получить размер списка OID, причина : %s !"),CStringProc::GetSystemError());		
	}
	if (bResult==false)
	{
		WriteToLog(_T("OID \"%s\" не является действительным !"),strOID);
	}
	return bResult;
}
bool ICPCryptoImpl::CertGetOIDs(HCRYPTMSG hMsg, PCCERT_CONTEXT pCertContext,CStringArray& saOIDs)
{
	// Достанем по старому пути
	//NMS : Узнаем размер
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : Выделяем память
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : Превращаем в автоуказатель
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
	
	// добавим по новому пути

	for (int iE=0;iE<pCertContext->pCertInfo->cExtension; iE++)
	{
		CString strObjId=pCertContext->pCertInfo->rgExtension[iE].pszObjId;
		if (strObjId!=szOID_CERT_POLICIES) // Политики безопасности
		{
			
			continue;
		}
		CERT_POLICIES_INFO* pCPI=NULL;
		DWORD dwCPISize=0;
		//KAA : Читаем размер данных под расширение
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
		
		//KAA : Прочитаем сами данные
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
		//NMS : Выделим память под CRL_DIST_POINTS_INFO
	}
	return TRUE;
	
}
//NMS : Позволяет получить, список используемых ключей для сертификата OID's
CString ICPCryptoImpl::CertGetEKUs(PCCERT_CONTEXT pCertContext)
{
	ASSERT(pCertContext!=NULL);
	WriteToLog(_T("Получаем EKUs для сертификата"));
	CString strResult;
	//NMS : Узнаем размер
	DWORD dwSize=0x00;
	if (::CertGetEnhancedKeyUsage(pCertContext,0,NULL,&dwSize))
	{
		//NMS : Выделяем память
		PCERT_ENHKEY_USAGE pUsage=(PCERT_ENHKEY_USAGE)malloc(dwSize);
		ASSERT(pUsage!=NULL);
		//NMS : Превращаем в автоуказатель
		CCertAutoBytePtr pUsagePtr((BYTE*)pUsage);
		if (::CertGetEnhancedKeyUsage(pCertContext,0,pUsage,&dwSize))
		{
			CString strOIDNow;
			for (int nItem=0;nItem<pUsage->cUsageIdentifier;nItem++)
			{
				strOIDNow=pUsage->rgpszUsageIdentifier[nItem];
				WriteToLog(_T("Найден EKU : %s"),(LPCTSTR)strOIDNow);
				strResult+=_T(", EKU=")+strOIDNow;
			}
		}
	}
	return strResult;
}

//NMS : Позволяет получить время подписи
CString ICPCryptoImpl::GetSignTime(HCRYPTMSG hMsg,DWORD dwSigner)
{
	ASSERT(hMsg!=NULL);
	//NMS : Узнаем размер
	DWORD dwSize=0x00;
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_AUTH_ATTR_PARAM,dwSigner,NULL,&dwSize))
	{
		WriteToLog(_T("ICPCryptoImpl::GetSignTime => CryptMsgGetParam вернула FALSE !"));
		return CString();
	}
	//NMS : Выделяем память
	PCRYPT_ATTRIBUTES pattrs=(PCRYPT_ATTRIBUTES)malloc(dwSize);
	ASSERT(pattrs!=NULL);
	//NMS : Делаем автоуказатель
	CCertAutoBytePtr PattrsPtr((BYTE*)pattrs);
	//NMS : Получаем данные
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_AUTH_ATTR_PARAM,dwSigner,pattrs,&dwSize))
	{
		WriteToLog(_T("ICPCryptoImpl::GetSignTime => CryptMsgGetParam вернула FALSE !"));
		return CString();
	}
	//NMS : Вытаскиваем время
	CString strResult;
	for (int iA=0;iA<pattrs->cAttr;iA++)
	{
		if (strcmp(pattrs->rgAttr[iA].pszObjId,"1.2.840.113549.1.9.5")==0 &&
			pattrs->rgAttr[iA].cValue==1)
		{
			//NMS : Проверим размер, размер должен соответствовать размеру структуры FILETIME
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
				//NMS : Считаем время
				FILETIME ft;
				if (::CryptDecodeObject(X509_ASN_ENCODING,
										szOID_RSA_signingTime,
										pattrs->rgAttr[iA].rgValue[0].pbData,
										pattrs->rgAttr[iA].rgValue[0].cbData,
										0,
										&ft,
										&dwSize))
				{
					//NMS : Сконвертируем время
					SYSTEMTIME stZ,st;
					FileTimeToSystemTime(&ft,&stZ);
					TIME_ZONE_INFORMATION tz;
					GetTimeZoneInformation(&tz);
					SystemTimeToTzSpecificLocalTime(&tz,&stZ,&st);
					//NMS : Отформатируем результат
					strResult.Format(_T("%.2d.%.2d.%.4d %.2d:%.2d:%.2d"),
									 st.wDay,st.wMonth,st.wYear,st.wHour,
									 st.wMinute,st.wSecond);
					break;
				}
			}
		}
	}
	//NMS : Возвращаем результат
	return strResult;
}

//NMS : И удаляет его
int ICPCryptoImpl::CertDeleteFromStore(const LPCERTFINDPARAM lpCertFindParam)
{
	ASSERT(lpCertFindParam!=NULL);
	if (lpCertFindParam==NULL &&
		lpCertFindParam->dwFindInStore==0x00 &&
		(lpCertFindParam->strCN.IsEmpty() || (!lpCertFindParam->IsSetThumb())))
	{
		return m_LastErrorCode = CCPC_CantDeleteCertFromStore;
	}
	//WriteToLog("Вызов ICPCryptoImpl::CertDeleteFromStrote");	
	
	//NMS : Открываем только SST	
	int nResult=CertOpenStore(lpCertFindParam->dwFindInStore);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}	
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this);
	//NMS : Ищем сертификат и если нашли удаляем его из хранилища
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
		WriteToLog(_T("Не удалось найти сертификат \"%s\" для удаления !"),
				   lpCertFindParam->strCN);

	}
	//NMS : Сохраняем изменения в файл
	if (nResult==CCPC_NoError)
	{
		m_strLastError.Empty();
		nResult=SaveSSTInFile();
	}
	//NMS : Возвращаем результат
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

//NMS : Позволяет получить сертификат из хранилища по subject,email,thumb
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
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this);
	//NMS : Ищем сертификат и если нашли удаляем его из хранилища
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
			//NMS : Успешно
			nResult=CCPC_NoError;
		}
		else
		{
			nResult=CCPC_OutOfMemory;
		}
		//NMS : Очистим сертификаты
		FindParam.ClearArrCerts();
	}
	return m_LastErrorCode = nResult;
}

//NMS : Сохраняет данные SST в файл
int ICPCryptoImpl::SaveSSTInFile(HCERTSTORE hStore/*=NULL*/)
{
	int nResult=CCPC_CantSaveStore;
	if (hStore==NULL)
	{
		hStore=CertGetHandleStoreByType(CST_SST);
	}	
//	ASSERT(hStore!=NULL);	
	//NMS : Будем сохранять измененные данные
		//NMS : Сформируем путь к файлу, файл и директории в пути ужзе существуют,
		//		это гарантирует CertOpenStore(CST_SST)
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : Проверим последний слэш
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif//
	ASSERT(!m_strRootPath.IsEmpty());
	CString strCertStorePath;
	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : Сохраняем изменения в файл
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
			WriteToLog(_T("Не удалось сохранить данные в хранилище certstore.sst, путь \"%s\", причина : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
		else
		{
			nResult=CCPC_NoError;
		}
	}
	//NMS : Возвращаем результат
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
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this);
	//NMS : Ищем сертификат
	PCCERT_CONTEXT pCertResult=NULL;	
	int nResult=CertFind(&FindParam,&pCertResult);

	if (nResult==CCPC_NoError)
	{
			pCertContext = pCertResult;
			//NMS : Успешно
			nResult=CCPC_NoError;
	}
	else
	{
		pCertContext=NULL;
	}
		
	return m_LastErrorCode = nResult;

}

//KAA : Проверяет сертификат на валидность как это делается при шифровании, возвращает CCPC_NoError или код ошибки
/*virtual*/ int ICPCryptoImpl::CheckCertificate(const PCCERT_CONTEXT pCertContext)
{
	//NMS : Проверим сертификат на валидность, а так же 
	//		проверим цепочку сертификата		
	CERTVALIDPARAM ValidParam;
	if (!CertIsValid(pCertContext,&ValidParam))
	{
		return m_LastErrorCode = ValidParam.nResultCode;
	}
	return m_LastErrorCode = CCPC_NoError;
}

#ifdef CTHREAD_UPDATE_CRL
//KAA : Получает отпечатки сертификатов (в формате HEX), использованные при шифровании по 141, возвращает CCPC_NoError или код ошибки
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

	//NMS : Открываем только SST и MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}
	//NMS : Закрывать SST и MY будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);

	//NMS : Открываем файлы на чтение и запись
	CFile fIn;
	if (!fIn.Open(szCryptedFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),
				   szCryptedFileName,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}

	//NMS : Считываем версию файла
	int iVer=0;
	if (fIn.Read(&iVer,sizeof(iVer))!=sizeof(iVer) || iVer!=1)
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Считываем отпечаток сертификата отправителя
	CRYPT_DATA_BLOB bThumbS;
	if (fIn.Read(&bThumbS.cbData,sizeof(bThumbS.cbData))!=sizeof(bThumbS.cbData))
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Выделяем память под отпечаток
	bThumbS.pbData=new BYTE[bThumbS.cbData];
	ASSERT(bThumbS.pbData!=NULL);
	if (bThumbS.pbData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения отпечатка сертификата отправителя !"),
				   bThumbS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr bThumbSPtr(bThumbS.pbData,false);
	//NMS : Читаем отпечаток
	if (fIn.Read(bThumbS.pbData,bThumbS.cbData)!=bThumbS.cbData)
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Читаем Subject отправителя
	CERT_NAME_BLOB cNameS;
	if (fIn.Read(&cNameS.cbData,sizeof(cNameS.cbData))!=sizeof(cNameS.cbData))
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Выделяем память под Subject
	cNameS.pbData=new BYTE[cNameS.cbData];
	ASSERT(cNameS.pbData!=NULL);
	if (cNameS.pbData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения subject отправителя !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr cNameSPtr(cNameS.pbData,false);
	//NMS : Читаем
	if (fIn.Read(cNameS.pbData,cNameS.cbData)!=cNameS.cbData)
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Читаем отпечаток
	CRYPT_DATA_BLOB bThumbR;
	if (fIn.Read(&bThumbR.cbData,sizeof(bThumbR.cbData))!=sizeof(bThumbR.cbData))
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Выделяем память под отпечаток
	bThumbR.pbData=new BYTE[bThumbR.cbData];
	ASSERT(bThumbR.pbData!=NULL);
	if (bThumbR.pbData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения отпечатка получателя !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr bThumbRPtr(bThumbR.pbData,false);
	//NMS : Читаем отпечаток
	if (fIn.Read(bThumbR.pbData,bThumbR.cbData)!=bThumbR.cbData)
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Читаем subject получателя
	CERT_NAME_BLOB cNameR;
	if (fIn.Read(&cNameR.cbData,sizeof(cNameR.cbData))!=sizeof(cNameR.cbData))
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Выделяем память под Subject
	cNameR.pbData=new BYTE[cNameR.cbData];
	ASSERT(cNameR.pbData!=NULL);
	if (cNameR.pbData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения subject получателя !"),
				   cNameS.cbData);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr cNameRPtr(cNameR.pbData,false);
	//NMS : Читаем
	if (fIn.Read(cNameR.pbData,cNameR.cbData)!=cNameR.cbData)
	{
		WriteToLog(_T("Файл \"%s\" имеет ошибочный формат !"),szCryptedFileName);
		return m_LastErrorCode = CCPC_InvalidAltFileFormat;
	}
	//NMS : Преобразуем в строки
	CString sSubjS=CertNameBlob2Str(&cNameS,true),
			sSubjR=CertNameBlob2Str(&cNameR,true);
	//NMS : Освобождаем
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