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
//NMS : Подпись
//**********************************************************

// sSender == Subject\tOID
/*virtual*/ int ICPCryptoImpl::SignFileA(CString sSender, CString datasignFileName)
{
	int Result = SignFileEx(sSender, datasignFileName, datasignFileName,FALSE);
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
// пост обработка процедуры подписи файла, результ выполнения CCPC_NoError если удачно, или код ошибки
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
// пост обработка процедуры подписи файла, результ выполнения CCPC_NoError если удачно, или код ошибки
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		Result = m_pCPCryptoCallBack->OnSignFile(sSender,signFileName,dataFileName,Result);
	}
#endif //
	return m_LastErrorCode =Result;
}

// если dataFileName!="" то в dataFileName будет файл без подписи
/*virtual*/ int ICPCryptoImpl::CheckFileA(CString signFileName,
										  CString dataFileName,
										  CStringArray& saSignInfos,
										  BOOL bShowDlg)
{
	int Result = CertCheckFileEx(dataFileName, signFileName, saSignInfos, bShowDlg, FALSE);
// пост обработка процедуры получения подписи, результ выполнения CCPC_NoError если удачно, или код ошибки
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
// пост обработка процедуры получения подписи, результ выполнения CCPC_NoError если удачно, или код ошибки
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		Result = m_pCPCryptoCallBack->OnCheckFile(signFileName, dataFileName,saSignInfos,bShowDlg,Result);
	}
#endif //
	return m_LastErrorCode =Result;

}

// проверка наличия подписи (Subject\tOID) в файле
// в sSenderInfo возвращается значение Subject сертификата
/*virtual*/ int ICPCryptoImpl::CheckFileA(CString signFileName,
										  CString& sSenderInfo)
{

	int Result = CertCheckFileEx(_T(""), signFileName, sSenderInfo, FALSE);
// пост обработка процедуры получения подписи, результ выполнения CCPC_NoError если удачно, или код ошибки
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
// пост обработка процедуры получения подписи, результ выполнения CCPC_NoError если удачно, или код ошибки
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
// пост обработка процедуры распаковки подписанного файла, результ выполнения CCPC_NoError если удачно, или код ошибки
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnUnpackSignedFile(datasignFileName,dataFileName,Result);
#endif //
	return m_LastErrorCode =Result;
}

/*virtual*/ int ICPCryptoImpl::UnpackSignedFileEx(CString datasignFileName,
												CString dataFileName)
{
	//WriteToLog(_T("Вызов ICPCryptoImpl::UnpackSignedFile"));

	//NMS : Открываем файлы
	CFile fds,fd;
	if (!fds.Open(datasignFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина %s !"),
				   datasignFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	if (!fd.Open(dataFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на запись, причина %s !"),
				   dataFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	//NMS : Читаем данные из файла
	DWORD dwDataLen=fds.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения файла \"%s\" !"),
				  dwDataLen,datasignFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Читаем данные
	fds.Read(bData,dwDataLen);
	fds.Close();

	//NMS : Получаем хэндл криптографического сообщения
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  0,0,0,NULL,NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("Не удалось получить хэндл криптографического сообщения, причина %s !"),GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : Запихиваем прочитанные данные в сообщение
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("Не удалось записать прочитанные данные из файла \"%s\" в криптографическое сообщение, причина : %s !"),
				   datasignFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	//NMS : Освобождаем память
	bDataPtr.Free();
	//NMS : Проверим, а является ли данные подписью
	DWORD dwCount=0x00;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
		WriteToLog(_T("Не удалось получить тип криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Проверяем тип			
	if (dwCount!=CMSG_SIGNED)
	{
		WriteToLog(_T("Файл \"%s\" не является файлом подписи !"),datasignFileName);
		return m_LastErrorCode =CCPC_FileNotSigned;
	}
	//NMS : Читаем данные, которые потом запишем в результирующий файл
	//NMS : Узнаем размер
	DWORD cbDecoded=0;	
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
		WriteToLog(_T("Не удалось получить размер данных криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Узнали размер, выделим под него память	
	BYTE* pbDecoded=(BYTE*)malloc(cbDecoded);
	if (pbDecoded==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для прочтения данных криптографического сообщения !"),
				   cbDecoded);
		int Result = CCPC_OutOfMemory;
		return m_LastErrorCode =Result;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr pbDecodedPtr(pbDecoded);
	//NMS : Прочитаем сами данные	
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbDecoded,&cbDecoded))
	{
		WriteToLog(_T("Не удалось получить данные криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Запишем полученные данные в результирующий файл
	fd.Write(pbDecoded,cbDecoded);
	fd.Close();
	//NMS : Возвращаем успех !
	return m_LastErrorCode =CCPC_NoError;
}

//**********************************************************
//NMS : Шифрование
//**********************************************************

//NMS : Освобождает массив с сертификатами
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
// пост обработка процедуры шифрования файла, результ выполнения CCPC_NoError если удачно, или код ошибки
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

	//WriteToLog(_T("Вызов ICPCryptoImpl::EncryptFile"));		

	if (saRecepientIDs.GetSize()<1 && pArrCertRcpt == NULL)
	{		
		WriteToLog(_T("Не указан сертификат отправителя !"));
		return m_LastErrorCode =CCPC_NoSender;
	}

	//NMS : Открываем исходный файл
	CFile fIn;
	if (!fIn.Open(plainFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	//NMS : Читаем из него данные	
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения файла \"%s\" !"),
				  dwDataLen,plainFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Читаем данные из файла	
	fIn.Read(bData,dwDataLen);
	fIn.Close();
	//NMS : Открываем только SST и MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : Закрывать SST и MY будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);	
	//NMS : Цикл по отправителю и получателю
	HCRYPTPROV hProv=NULL;
	CCertCryptProv hProvClose(&hProv);
	PCCERT_CONTEXT pRecipientCert=NULL;
	CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> arrCertRcpt;	
	//NMS : Цикл по поиску сертификатов отправителя и получателей (реализация как у YAR)
	for (int iC=0;iC<saRecepientIDs.GetSize();iC++)
	{
		//NMS : Выделяем CN И OID
		CString sSender=saRecepientIDs[iC]+"\t\t";
		CString sSignerSubj=sSender.Left(sSender.Find("\t")); sSender.Delete(0,1+sSender.Find("\t"));
		CString sSignerOID=sSender.Left(sSender.Find("\t")); sSender.Delete(0,1+sSender.Find("\t"));		
		//NMS : Заполняем структуру для поиска
		CERTFINDPARAM CertFindParam;
		//NMS : Будем устанавливать хранилища и собирать из всех
		CertFindParam.dwFindInStore=dwStoreTypes;
		CertFindParam.strCN=sSignerSubj;
		CertFindParam.strOID=sSignerOID;
		//NMS : Если ищем сертификаты отправителей, тогда включаем множественный режим
		CertFindParam.bSelAllCert=TRUE;
		CertFindParam.bSelFromAllStores=TRUE;		
		//NMS : Ищем
		if (CertFind(&CertFindParam,&pRecipientCert)==CCPC_NoError)
		{
			//NMS : Если это первый проход, тогда нужно получить закрытый ключ,
			//		так как первым в списке стоит отправитель, а все остальные получатели
			if (iC==0 && hProv==NULL)
			{
				//NMS : Для найденного отправителя запросим закрытый ключ
				if (!::CryptAcquireCertificatePrivateKey(pRecipientCert, 
														 CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG, 
														 NULL, 
														 &hProv,
														 NULL,
														 NULL))
				{
					WriteToLog(_T("Не удалось найти закрытый ключ сертификата отправителя : %s (%s) !"),sSignerSubj,sSignerOID);
					return m_LastErrorCode =CCPC_CantFindPrivateKey;
				}				
				//NMS : Добавим все найденные сертификаты
				//arrCertRcpt.Add(pRecipientCert);
				arrCertRcpt.Append(CertFindParam.arrCerts);												
			}
			else
			{
				//NMS : Добавим все найденные сертификаты
				arrCertRcpt.Append(CertFindParam.arrCerts);				
			}
		}
		else
		{
			//NMS : Пишем в лог
			WriteToLog(_T("Не удалось найти сертификат %s : %s(%s) !"),
					   (iC==0 ? _T("отправителя"):_T("получателя")),
					   sSignerSubj,sSignerOID);
			//NMS : 
			FreeCertsArray(arrCertRcpt);
			return m_LastErrorCode =CCPC_CantFindCertInStore;
		}		
	}

// Проверим сертификаты на истечение срока действия
	BOOL bCheckOutOfDate = TRUE;
	if (bCheckOutOfDate)
	{
		if (pArrCertRcpt)
		{
			for (int i = 0; i < pArrCertRcpt->GetSize (); i++)
				if (!CheckCertOutOfDate ((*pArrCertRcpt).GetAt (i)->pCertInfo))
				{
					WriteToLog(_T("Срок действия сертификата для шифрования истек или еще не наступил (%s)!"),
						(LPCSTR)CertNameBlob2Str(&(*pArrCertRcpt).GetAt (i)->pCertInfo->Subject));
					FreeCertsArray(arrCertRcpt);
					return m_LastErrorCode =CCPC_CertNotValid;
				}
		}	else	{
			for (int i = 0; i < arrCertRcpt.GetSize (); i++)
				if (!CheckCertOutOfDate (arrCertRcpt.GetAt (i)->pCertInfo))
				{
					WriteToLog(_T("Срок действия сертификата для шифрования истек или еще не наступил (%s)!"),
						(LPCSTR)CertNameBlob2Str(&arrCertRcpt.GetAt (i)->pCertInfo->Subject));
					FreeCertsArray(arrCertRcpt);
					return m_LastErrorCode =CCPC_CertNotValid;
				}
		}
	}

	//NMS : Начинаем шифровать
	CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
	ZeroMemory(&EncryptParams,sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));	
	EncryptParams.cbSize=sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
	EncryptParams.dwMsgEncodingType=PKCS_7_ASN_ENCODING|X509_ASN_ENCODING;
	EncryptParams.hCryptProv=hProv;
	ZeroMemory(&EncryptParams.ContentEncryptionAlgorithm,
			   sizeof(EncryptParams.ContentEncryptionAlgorithm));
	EncryptParams.ContentEncryptionAlgorithm.pszObjId="1.2.643.2.2.21";
	//NMS : Шифруем данные
	//NMS : Вначале узнаем размер буфера, который необходим для
	//NMS : зашифрованых данных.
	BYTE*    pbEncryptedBlob=NULL;
	DWORD    cbEncryptedBlob=0x00;
	//NMS : Узнаем размер буфера
	if(!::CryptEncryptMessage(&EncryptParams,
							pArrCertRcpt ? pArrCertRcpt->GetSize () : arrCertRcpt.GetSize(),
							pArrCertRcpt ? pArrCertRcpt->GetData () : arrCertRcpt.GetData(),
							  bData,
							  dwDataLen,
							  NULL,
							  &cbEncryptedBlob))
	{
		WriteToLog(_T("Не удалось получить размер буфера для зашифрованных данных, причина : %s !"),
				   GetSystemErrorDesc());
		FreeCertsArray(arrCertRcpt);
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Выделим память под размер буфера
	pbEncryptedBlob=(BYTE*)malloc(cbEncryptedBlob);
	if (pbEncryptedBlob==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти под буфер для зашифрованных данных !"),cbEncryptedBlob);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем указатель автоматическим
	CCertAutoBytePtr pbEncryptedBlobPtr(pbEncryptedBlob);
	//NMS : Получаем зашифрованные данные
	if(!::CryptEncryptMessage(&EncryptParams,
							pArrCertRcpt ? pArrCertRcpt->GetSize () : arrCertRcpt.GetSize(),
							pArrCertRcpt ? pArrCertRcpt->GetData () : arrCertRcpt.GetData(),
							  bData,
							  dwDataLen,
							  pbEncryptedBlob,
							  &cbEncryptedBlob))
	{
		WriteToLog(_T("Не удалось получить зашифрованные данные, причина : %s !"),
				   GetSystemErrorDesc());
		FreeCertsArray(arrCertRcpt);
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Освобождаем ресурсы
	FreeCertsArray(arrCertRcpt);
	//NMS : Теперь откроем результирующий файл и запишем в него результаты шифрования
	nResult=CCPC_NoError;
	CFile fOut;
	if (fOut.Open(cryptoFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		//NMS : Записываем зашифрованные данные в файл
		fOut.Write(pbEncryptedBlob,cbEncryptedBlob);
		fOut.Close();
		m_strLastError.Empty();
	}
	else
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на запись, причина : %s !"),
				   cryptoFileName,GetSystemErrorDesc());
		nResult=CCPC_CantOpenFileWrite;
	}	
	//NMS : Возвращаем результат
	return m_LastErrorCode =nResult;
}
int ICPCryptoImpl::DecryptFile(CString cryptoFileName, CString plainFileName)
{
	int Result = DecryptFileEx(cryptoFileName, plainFileName);
	// пост обработка процедуры разшифровки файла, результ выполнения CCPC_NoError если удачно, или код ошибки
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

	//WriteToLog(_T("Вызов ICPCryptoImpl::DecryptFile"));

	//NMS : Почистим ошибку
	m_strLastError.Empty();
//	ASSERT(FALSE);

	//NMS : Считываем данные из шифрованного файла
	CFile fIn;
	if (!fIn.Open(cryptoFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),
				   cryptoFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}
	//NMS : Узнаем размер файла и выделим память под чтение данных из файла
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения файла \"%s\" !"),
				   dwDataLen,cryptoFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Читаем данные из файла
	fIn.Read(bData,dwDataLen);
	fIn.Close();

	//NMS : Открываем только SST и MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : Закрывать SST и MY будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : Сделаем из MY и SST массив хэндлов
//	HCERTSTORE arrMyAndSST[2]={CertGetHandleStoreByType(CST_MY),CertGetHandleStoreByType(CST_SST)};
	HCERTSTORE arrMyAndSST[1]={CertGetHandleStoreByType(CST_MY)};//,CertGetHandleStoreByType(CST_SST)};
	//NMS : Заполняем структуру для расшифровки сообщения	
	CRYPT_DECRYPT_MESSAGE_PARA  DecryptParams;
	ZeroMemory(&DecryptParams,sizeof(CRYPT_DECRYPT_MESSAGE_PARA));		
	DecryptParams.cbSize=sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
	DecryptParams.dwMsgAndCertEncodingType=PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	DecryptParams.cCertStore=(sizeof(arrMyAndSST)/sizeof(arrMyAndSST[0]));
	if (CertGetHandleStoreByType(CST_SST)==NULL)
		DecryptParams.cCertStore = 1;
	DecryptParams.rghCertStore=arrMyAndSST;
	//NMS : Узнаем размер буфера для расшифрованных данных
	BYTE* pbDecryptedMessage=NULL;
	DWORD cbDecryptedMessage=0x00;
	DWORD dwLenBlock = 64*1024*1024; // 
	dwDataLen;// = dwLenBlock;
	if(!CryptDecryptMessage(&DecryptParams,bData,dwDataLen,NULL,&cbDecryptedMessage,NULL))
	{
		WriteToLog(_T("Не удалось получить размер для расшифрованных данных, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Узнали размер, выделим память
	pbDecryptedMessage=(BYTE*)malloc(cbDecryptedMessage);
	if (pbDecryptedMessage==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для чтения расшифрованных данных !"),
				   cbDecryptedMessage);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем указатель автоматическим
	CCertAutoBytePtr pbDecryptedMessagePtr(pbDecryptedMessage);
	//NMS : Получаем расшифрованные данные
	if(!::CryptDecryptMessage(&DecryptParams,bData,dwDataLen,pbDecryptedMessage,&cbDecryptedMessage,NULL))
	{		
		WriteToLog(_T("Не удалось получить расшифрованные данные, причина : %s !"),GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Откроем результирующий файл и запишем туда результат
	CFile fOut;
	if (!fOut.Open(plainFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на запись, причина : %s !"),
				   plainFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	//NMS : Записываем данные в файл
	fOut.Write(pbDecryptedMessage,cbDecryptedMessage);
	fOut.Close();
	//NMS : Возвращаем успех
	return m_LastErrorCode =CCPC_NoError;
}

//NMS : Низкоуровневая функция, которая подписывает файл
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

	//NMS : Почистим ошибку
	m_strLastError.Empty();

	sSender+="\t\t";
	CString sSignerSubj=sSender.Left(sSender.Find("\t"));
	sSender.Delete(0,1+sSender.Find("\t"));

	CString sSignerOID=sSender.Left(sSender.Find("\t"));
	sSender.Delete(0,1+sSender.Find("\t"));

	//WriteToLog(_T("Вызвана ICPCryptoImpl::SignFileEx : %s(%s)"),sSignerSubj,sSignerOID);
	
	CFile fIn, fOut;
	//NMS : Открываем файл
	if (!fIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\", причина : %s !"),
				   dataFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}
	
	//NMS : Узнаем длину файла и выделяем необходимое кол-во памяти
	DWORD dwDataLen=fIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	if (bData==NULL)
	{
		WriteToLog(_T("Не удалось выделить нужное количество памяти %d байт для файла \"%s\" !"),
				   dwDataLen,dataFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Память успешно выделили,сделаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Читаем данные из файла
	fIn.Read(bData,dwDataLen);
	fIn.Close();

	//NMS : Открываем только SST и MY
	const DWORD dwStoreTypes=CST_SST|CST_MY;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : Закрывать SST и MY будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : Ищем сертификат для подписи
	CERTFINDPARAM CertFindParam;
	CertFindParam.dwFindInStore=dwStoreTypes;
	CertFindParam.strCN=sSignerSubj;
	CertFindParam.strOID=sSignerOID;
	PCCERT_CONTEXT pSenderCert=NULL;
	if (CertFind(&CertFindParam,&pSenderCert)!=CCPC_NoError)
	{
		WriteToLog(_T("Не удалось найти действительный сертификат отправителя : %s (%s) !"),
				   sSignerSubj,sSignerOID);
		return m_LastErrorCode =CCPC_CantFindCertInStore;
	}
	// проверим на срок окончания
	if (CertCheckCertRemain(pSenderCert)!=CCPC_NoError)
	{
		WriteToLog(_T("Действие отменено абонентом, т.к. срок действия личного сертификата %s заканчивается"),sSignerSubj);
		return m_LastErrorCode =CCPC_CertIsRemainExpiered;
	}

	//NMS : Получаем закрытый ключ
	HCRYPTPROV	hProv=NULL;
	if (!::CryptAcquireCertificatePrivateKey(pSenderCert,
											 CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG,
											 NULL, 
											 &hProv,
											 NULL,
											 NULL))
	{
		WriteToLog(_T("Не удалось найти закрытый ключ сертификата отправителя : %s (%s) !"),
				   sSignerSubj,sSignerOID);
		return m_LastErrorCode =CCPC_CantFindPrivateKey;		
	}
	CCertCryptProv hProvClose(&hProv);

	//NMS : Заполним структуру CMSG_SIGNER_ENCODE_INFO

	CMSG_SIGNER_ENCODE_INFO seiSender;
	ZeroMemory(&seiSender,sizeof(CMSG_SIGNER_ENCODE_INFO));	
	seiSender.cbSize=sizeof(CMSG_SIGNER_ENCODE_INFO);
	seiSender.pCertInfo=pSenderCert->pCertInfo;
	seiSender.hCryptProv=hProv;
	seiSender.dwKeySpec=AT_KEYEXCHANGE;
	ZeroMemory(&seiSender.HashAlgorithm,sizeof(seiSender.HashAlgorithm));	
	seiSender.HashAlgorithm.pszObjId="1.2.643.2.2.9";
	seiSender.pvHashAuxInfo=NULL;

	//NMS : Определим системное время и добавим его в список аутентифицируемых (подписанных)
	//		атрибутов PKCS#7 сообщения с идентификатором szOID_RSA_signingTime.

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
	//NMS : Получаем размер
	if (::CryptEncodeObject(X509_ASN_ENCODING,
							szOID_RSA_signingTime,
							(LPVOID)&fileTime,
							NULL,
							&dwTimeStamp))
	{
		pbTimeStamp=(BYTE*)malloc(dwTimeStamp);
		ASSERT(pbTimeStamp!=NULL);
		//NMS : Делаем указатель автоматическим
		pbTimeStampPtr.Attach(pbTimeStamp);
		if (pbTimeStamp)
		{
			//NMS : Кодирование времени в атрибут типа szOID_RSA_signingTime
			
			if (::CryptEncodeObject(X509_ASN_ENCODING,
									szOID_RSA_signingTime,
									(LPVOID)&fileTime,
									pbTimeStamp,
									&dwTimeStamp))
			{
				//NMS : Выделяем память
				pCA=new CRYPT_ATTRIBUTE;
				ASSERT(pCA!=NULL);
				pCAblob=new CRYPT_ATTR_BLOB;
				ASSERT(pCAblob!=NULL);
				//NMS : Делаем указатели автоматическими
				pCAPtr.Attach((BYTE*)pCA,false);
				pCAblobPtr.Attach((BYTE*)pCAblob,false);
				//NMS : Установим значения
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
	
	//NMS : Определяем размер
	DWORD dwSigned=::CryptMsgCalculateEncodedLength(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
													dwDetachedFlag,
													CMSG_SIGNED, 
													&seiMsg,
													NULL, 
													dwDataLen);
	if (dwSigned==0)
	{
		WriteToLog(_T("Не удалось определить размер для кодирования, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : Выделяем память под определенный размер		
	BYTE* pbSigned=(BYTE*)malloc(dwSigned);
	ASSERT(pbSigned!=NULL);
	if (pbSigned==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для кодирования !"),dwSigned);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем указатель автоматическим
	CCertAutoBytePtr pbSignedPtr(pbSigned);
	//NMS : Получаем хендл криптографического сообщения
	HCRYPTMSG hMsg=::CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, 
										  dwDetachedFlag,
										  CMSG_SIGNED,
										  &seiMsg,
										  NULL,
										  NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("Не удалось открыть криптографическое сообщение для шифрования, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToEncode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);	

	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("Не удалось выполнить обновление криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	//NMS : Теперь получим подпись	
	if (!CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbSigned,&dwSigned))
	{
		WriteToLog(_T("Не удалось получить подпись, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : псевдо-цикл do для выхода из него по break.
	if (fIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	do 
	{
		//NMS : Попытка _добавления_ подписи
		BYTE* bAppendData=NULL;
		DWORD dwAppendDataLen=0;
		//NMS : Узнаем длинну файла и пытаемся выделить память под этот размер
		dwAppendDataLen=fIn.GetLength();		
		bAppendData=(BYTE*)malloc(dwAppendDataLen);		
		if (bAppendData==NULL)
		{
			WriteToLog(_T("Не удалось выделить %d байт памяти для чтения файла \"%s\" !"),
					   bAppendData,
					   signFileName);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		CCertAutoBytePtr bAppendDataPtr(bAppendData);
		//NMS : Читаем из файла
		fIn.Read(bAppendData,dwAppendDataLen);
		fIn.Close();
		
		//NMS : Получаем хэндл криптографического сообщения
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
		
		//NMS : Заливаем данные в сообщение		
		if (!::CryptMsgUpdate(hMsgAppend,bAppendData,dwAppendDataLen,TRUE))
		{
			break;
		}
		//NMS : Добавим, подпись
		if (!::CryptMsgControl(hMsgAppend,
							   0,
							   CMSG_CTRL_ADD_SIGNER,
							   &seiSender))
		{
			break;
		}
		//NMS : Добавим сертификат
		if (!::CryptMsgControl(hMsgAppend,
							   0,
							   CMSG_CTRL_ADD_CERT,
							   &bSender))
		{
			break;
		}
		//NMS : Получаем размер подписи
		dwSigned=0x00;		
		if (!::CryptMsgGetParam(hMsgAppend,
								CMSG_ENCODED_MESSAGE,
								0,
								NULL,
								&dwSigned))
		{
			break;
		}
		//NMS : Освобождаем предыдущий указатель
		pbSignedPtr.Free();
		//NMS : Выделяем память под новую подпись
		pbSigned=(BYTE*)malloc(dwSigned);
		if (pbSigned==NULL)
		{
			WriteToLog(_T("Не удалось выделить %d байт памяти для кодирования !"),dwSigned);
			return m_LastErrorCode =CCPC_OutOfMemory;			
		}
		//NMS : Делаем указатель автоматическим
		pbSignedPtr.Attach(pbSigned);
		//NMS : Получаем подпись			
		if (!::CryptMsgGetParam(hMsgAppend,
								CMSG_ENCODED_MESSAGE,
								0,
								pbSigned,
								&dwSigned))
		{
			WriteToLog(_T("Не удалось получить подпись, причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}		
	}
	while(false);
	//NMS : Запишем подпись в файл
	if (!fOut.Open(signFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на запись, причина : %s !"),
				   signFileName,
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileWrite;
	}
	fOut.Write(pbSigned, dwSigned);
	fOut.Close();
	//NMS : Освободим открытые хэндлы	
	::CertFreeCertificateContext(pSenderCert);
	//NMS : Возвращаем успех
	return m_LastErrorCode =CCPC_NoError;
}

//NMS : Проверяет подпись
int ICPCryptoImpl::CertCheckFileEx(CString dataFileName, CString signFileName, CString& sSignerInfo, BOOL bDetached)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode =CertLockMethods.m_nStatus;
	}

	//NMS : Почистим ошибку
	m_strLastError.Empty();

	//WriteToLog(_T("Вызов ICPCryptoImpl::CertCheckFileEx(%d)"),__LINE__);

	sSignerInfo+="\t\t";
	CString sSignerSubj=sSignerInfo.Left(sSignerInfo.Find("\t")); sSignerInfo.Delete(0,1+sSignerInfo.Find("\t"));
	CString sSignerOID=sSignerInfo.Left(sSignerInfo.Find("\t")); sSignerInfo.Delete(0,1+sSignerInfo.Find("\t"));
	sSignerInfo="";
	

	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}	

	//NMS : Открываем файл с подписью
	CFile fDataIn, fSignIn;
	if (!fSignIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
//		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),signFileName,GetSystemErrorDesc());
		WriteToLog(_T("Not read data: %s"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	if (bDetached)
	{
		//NMS : Открываем файл с данными
		if (!fDataIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
		{
//			WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"), dataFileName,GetSystemErrorDesc());
			WriteToLog(_T("Not read data: %s"), GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantOpenFileRead;
		}
	}
	
	//NMS : Определяем длину подписи и выделяем под
	//		эту длину память
	DWORD dwDataLen=fSignIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	ASSERT(bData!=NULL);
	if (bData==NULL)
	{
//		WriteToLog(_T("Не удалось выделить %d байт памяти для файла \"%s\" !"), dwDataLen,signFileName);
		WriteToLog(_T("Memory allocation error: %s"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Прочитаем данные из файла и закроем его
	fSignIn.Read(bData,dwDataLen);
	fSignIn.Close();	
	//NMS : Если нужно читаем данные из файла данных
	DWORD dwDataDataLen=0;
	BYTE* bDataData=NULL;
	CCertAutoBytePtr bDataDataPtr(NULL);
	if (bDetached)
	{
		dwDataDataLen=fDataIn.GetLength();
		bDataData=(BYTE*)malloc(dwDataDataLen);
		if (bDataData==NULL)
		{
//			WriteToLog(_T("Не удалось выделить %d байт памяти для файла \"%s\" !"), dwDataDataLen,dataFileName);
			WriteToLog(_T("%s"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : Сделаем указатель автоматическим
		bDataDataPtr.Attach(bDataData);
		//NMS : Читаем данные из файла и закрываем его
		fDataIn.Read(bDataData,dwDataDataLen);
		fDataIn.Close();
	}
	//NMS : Создаем хендл сообщения
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  dwDetachedFlag,
										  0,
										  NULL,
										  NULL,										  
										  NULL);
	if (hMsg==NULL)
	{
//		WriteToLog(_T("Не удалось открыть криптосообщение, причина : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Not open crypto message: %s"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : Заливаем в сообщение данные из файла данных
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
//		WriteToLog(_T("Не удалось добавить данные из файла \"%s\" в сообщение, причина : %s !"), signFileName,GetSystemErrorDesc());
		WriteToLog(_T("Not add data : %s !"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	bDataPtr.Free();
	if (bDetached)
	{
		//NMS : Заливаем в сообщение данные из файла данных
		if (!::CryptMsgUpdate(hMsg,bDataData,dwDataDataLen,TRUE))
		{
//			WriteToLog(_T("Не удалось добавить данные из файла \"%s\" в сообщение, причина : %s !"), dataFileName,GetSystemErrorDesc());
			WriteToLog(_T("Not add data : %s !"), GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantAddDataToMessage;
		}
		bDataDataPtr.Free();
	}

	DWORD dwCount=0;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
//		WriteToLog(_T("Не удалось получить тип криптографического сообщения, причина : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Unknown type of cryptomessage : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Файл является подписью ???
	if (dwCount!=CMSG_SIGNED)
	{
//		WriteToLog(_T("Файл \"%s\"  не является файлом подписи !"),signFileName);
		WriteToLog(_T("Data is not sign : %s !"), GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_FileNotSigned;
	}

	//NMS : Узнаем декодированный размер
	DWORD cbDecoded = 0;
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
//		WriteToLog(_T("Не удалось получить размер для декодирования, причина : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Unknown length of cryptomessage : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}	
	//NMS : Открываем хранилище для сообщения
	HCERTSTORE hMsgStore=::CertOpenStore(CERT_STORE_PROV_MSG,
										 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										 NULL,
										 0,
										 hMsg);
	if(hMsgStore==NULL)
	{
//		WriteToLog(_T("Не удалось открыть хранилище по хэндлу криптографического сообщения, причина : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Can't open certstore by handle : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantOpenStore;
	}
	//NMS : Делаем хранилище автоматическим
	CCertAutoStore hMsgStoreAuto(hMsgStore);
	//NMS : Открываем только SST
	const DWORD dwStoreTypes=CST_SST;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : Получим хэндл
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : Узнаем кол-во подписчиков
	DWORD dwSignersCount = 0;
	dwSize=sizeof(dwSignersCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_COUNT_PARAM,0,&dwSignersCount,&dwSize))
	{
//		WriteToLog(_T("Не удалось получить количество подписчиков, причина : %s !"), GetSystemErrorDesc());
		WriteToLog(_T("Failure number of signers : %s !"), GetSystemErrorDesc());

		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Проверим подпись на валидность !
	BOOL bSigValid=FALSE;
    DWORD dwSigner(0);
	for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
	{
		DWORD cbSignerCertInfo = 0;
		//NMS : Получим размер инфы о подписчике
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,NULL,&cbSignerCertInfo))
		{
//			WriteToLog(_T("Не удалось получить размер информации о подписчике, причина : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure size of information about signer: %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Узнали размер выделяем память
		PCERT_INFO pSignerCertInfo=NULL;
		pSignerCertInfo=(PCERT_INFO)malloc(cbSignerCertInfo);
		if (pSignerCertInfo==NULL)
		{
//			WriteToLog(_T("Не удалось выделить %d байт памяти для подписчика !"),cbSignerCertInfo);
			WriteToLog(_T("Failure allocation memory for information about signers : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : Делаем указатель автоматичиеским
		CCertAutoBytePtr pSignerCertInfoPtr((BYTE*)pSignerCertInfo);
		//NMS : Получаем инфу
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,pSignerCertInfo,&cbSignerCertInfo))
		{		
//			WriteToLog(_T("Не удалось получить информацию о подписчике, причина : %s !"),GetSystemErrorDesc());
			WriteToLog(_T("Failure information about signer : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Получим сертификат подписчика
		PCCERT_CONTEXT pSignerCertContext=NULL;		
		pSignerCertContext=::CertGetSubjectCertificateFromStore(hMsgStore,
																PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
																pSignerCertInfo);
		//NMS : Если не нашли в hMsgStore, поищем hSST
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
		//NMS : Не нашли сертификат :(
		if(pSignerCertContext==NULL)
		{
//			WriteToLog(_T("Не удалось найти сертификат подписчика"));
			WriteToLog(_T("Signer certificate not found : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantFindCertInStore;
		}
		//NMS : Проверим сертификат на валидность !		
		CERTVALIDPARAM ValidParam;
		bool bValid=CertIsValid(pSignerCertContext,&ValidParam);
		PCERT_INFO pSignerCertificateInfo=pSignerCertContext->pCertInfo;
		ASSERT(pSignerCertificateInfo!=NULL);
		//NMS : Только если сертификат валидин
		if (bValid!=false)
		{
			if (!::CryptMsgControl(hMsg,0,CMSG_CTRL_VERIFY_SIGNATURE,pSignerCertificateInfo))
			{
				bValid=false;
//				WriteToLog(_T("Подпись не верна :")+GetSystemErrorDesc());
				WriteToLog(_T("Sign is not valid : %s !"), GetSystemErrorDesc());
			}
		}
		CString sInfo=CertNameBlob2Str(&pSignerCertificateInfo->Subject);
		CString strSafeInfo(sInfo);
		//NMS : Проверка на Subject
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
		//NMS : Проверка на OID
/*********************************************************/
		// KAA : по новому административному регламенту, 
		//будем возвращать список найденых OID вместо проверки
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
		//NMS : Формируем sSignerInfo
		if (bValid)
		{
			//KAA : не будем прерываться на первой удачной подписи, вернем весь список
			if (sSignerInfo.IsEmpty()==FALSE) // если не первая строка добавим хитрый разделитель
				sSignerInfo += "\n\r###\n\r";

			sSignerInfo += strSafeInfo+"\t"+GetSignTime(hMsg,dwSigner);

           //NMS : Получаем отпечаток
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

			// KAA : Положим сюда и найденые OIDы
			if (saOIDs.GetSize()>0)
			{
				sSignerInfo+="\tOID:";
				for (int i=0;i<saOIDs.GetSize();i++)
				{
					sSignerInfo+=saOIDs.GetAt(i) + ((i == saOIDs.GetSize()-1) ? "":";");
				}

			}
			bSigValid=TRUE;
			//KAA : не будем прерываться на первой удачной подписи, вернем весь список
			//break;
			 
		}
	}
	//NMS : Если все хорошо импортируем сертификаты и CLR
	if (bSigValid)
	{
		//NMS : Импорт прочих сертификатов
		dwSize=sizeof(dwSignersCount);
		if (!::CryptMsgGetParam(hMsg,CMSG_CERT_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
//			WriteToLog(_T("Не удалось получить количество подписчиков, причина : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure number of signers : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Перебираем подписчиков
		for (dwSigner=0; dwSigner<dwSignersCount; dwSigner++)
		{
			DWORD cbCert=0;
			BYTE* pCert=NULL;
			//NMS : Получаем размер
			if (!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,NULL,&cbCert))
			{
//				WriteToLog(_T("Не удалось получить размер сертификата, причина : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Unknown size of certificate : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
				
			}
			//NMS : Выделяем под размер память
			pCert=(BYTE*)malloc(cbCert);
			if (pCert==NULL)
			{
//				WriteToLog(_T("Не удалось выделить %d байт памяти под сертификат !"),cbCert);
				WriteToLog(_T("Failure memory allocation for certificate : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : Делаем указатель автоматическим
			CCertAutoBytePtr pCertPtr(pCert);
			//NMS : Получаем данные сертификата
			if ((!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,pCert,&cbCert)) ||
				pCert==NULL)
			{
//				WriteToLog(_T("Не удалось получить данные сертификата, причина : %s !"),GetSystemErrorDesc());
				WriteToLog(_T("Failure certificates content : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : По данным создаем контекст, сертификат			
			PCCERT_CONTEXT pCertContext=CertCreateCertificateContext(X509_ASN_ENCODING,pCert,cbCert);
			pCertPtr.Free();
			if(pCertContext==NULL)
			{
//				WriteToLog(_T("Не удалось создать сертификат по данным, причина : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure creation of certificate by data : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantCreateCert;
			}
			//NMS : Если сертификат хороший, добавляем
			int nErrorCode=CCPC_NoError;
			CERTVALIDPARAM ValidParam;
/* КАА: Убираем проверку на валидность при записи в SST - пусть всегда сохраняется
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
		//NMS : Импорт CRL-ов
		dwSize=sizeof(dwSignersCount);
		if (!CryptMsgGetParam(hMsg,CMSG_CRL_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
//			WriteToLog(_T("Не удалось получить, количество CRL, причина : %s !"), GetSystemErrorDesc());
			WriteToLog(_T("Failure number of CRL : %s !"), GetSystemErrorDesc());

			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
		{
			DWORD cbCRL = 0;
			BYTE* pCRL = NULL;
			//NMS : Узнаем размер
			if (!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,NULL,&cbCRL))
			{
//				WriteToLog(_T("Не удалось получить размер CLR, причина %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure size of CRL : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : Выделяем под этот размер память
			pCRL=(BYTE*)malloc(cbCRL);
			if (pCRL==NULL)
			{
//				WriteToLog(_T("Не удалось выделить %d байт памяти для CLR, причина : %s !"), GetSystemErrorDesc());
				WriteToLog(_T("Failure memory allocation for CRL : %s !"), GetSystemErrorDesc());

				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : Делаем указатель автоматическим
			CCertAutoBytePtr pCRLPtr(pCRL);
			//NMS : Пробуем получить само сообщение
			if ((!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,pCRL,&cbCRL)) ||
				pCRL==NULL)
			{
//				WriteToLog(_T("Не удалось получить CLR, причина : %s !"), GetSystemErrorDesc());
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
//					WriteToLog(_T("Не удалось создать CLR по данным, причина %s !"), GetSystemErrorDesc());
					WriteToLog(_T("Failure CRL creation by data : %s !"), GetSystemErrorDesc());

					return m_LastErrorCode =CCPC_CantCreateCRL;
				}
				//NMS : Добавляем			
				CertAddCRLContextToStore(hSST,pCRLContext,CERT_STORE_ADD_NEWER ,NULL);
				//NMS : Освобождаем контекст
				CertFreeCRLContext(pCRLContext);
			}
		}
	}
	CString strCertStorePath;

// KAA : запросим директорию Dipost
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : Проверим последний слэш
		m_strRootPath.TrimRight(_T('\\'));	
	}

	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : Сохраняем изменения в файл
	if (hSST != NULL) {
		if (::CertSaveStore(hSST,
							PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							CERT_STORE_SAVE_AS_STORE,
							CERT_STORE_SAVE_TO_FILENAME_A,
							(void*)(LPCSTR)strCertStorePath,
							0)==FALSE)
		{
			nResult=CCPC_CantOpenFileWrite;
			WriteToLog(_T("Не удалось сохранить данные в хранилище certstore.sst, путь \"%s\", причина : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
	}
#endif //

	//NMS : Результат
	nResult=CCPC_VerifyFailed;
	if (bSigValid)
	{
		nResult=CCPC_NoError;
		//NMS : Обнулим последнюю ошибку
		m_strLastError.Empty();
	}
	//NMS : Вернем результат
	return m_LastErrorCode =nResult;
}

//NMS : Проверяет подпись
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

	//WriteToLog(_T("Вызов ICPCryptoImpl::CertCheckFileEx(%s)"),__LINE__);

	//NMS : Признак, того, что не нужно для сертификатов
	//		проверять валидность, необходимо для отображения состояния в референте.
	BOOL bNotCheckCertValid=FALSE;

	// AKV: В saSignInfos могут передаваться еще Thumbs, для которых надо проверить файл. Изменено.
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
		// Отпечаток или CN
		if (_tcsnicmp(saSignInfos.GetAt(iInfoCount), cszThumbInfo, lenThumbInfo) == 0)
		{
			CString strKeyID = saSignInfos[iInfoCount];
			strKeyID.Delete(0, lenThumbInfo);
			vecKeyIDs.push_back(strKeyID);
		}
	}
	// AKV End
	
	saSignInfos.RemoveAll();

	//NMS : Почистим последнюю ошибку
	m_strLastError.Empty();
	
	
	DWORD dwDetachedFlag=0x00;
	if (bDetached)
	{
		dwDetachedFlag=CMSG_DETACHED_FLAG;
	}

	//NMS : Открываем файл с подписью
	CFile fDataIn, fSignIn;
	if (!fSignIn.Open(signFileName,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),
				   signFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenFileRead;
	}

	if (bDetached)
	{
		//NMS : Открываем файл с данными
		if (!fDataIn.Open(dataFileName,CFile::modeRead|CFile::shareDenyWrite))
		{
			WriteToLog(_T("Не удалось открыть файл \"%s\" на чтение, причина : %s !"),
					   dataFileName,GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantOpenFileRead;
		}
	}
	//NMS : Определяем длину подписи и выделяем под
	//		эту длину память
	DWORD dwDataLen=fSignIn.GetLength();
	BYTE* bData=(BYTE*)malloc(dwDataLen);
	ASSERT(bData!=NULL);
	if (bData==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для файла \"%s\" !"),
				   dwDataLen,signFileName);
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Сделаем указатель автоматическим
	CCertAutoBytePtr bDataPtr(bData);
	//NMS : Прочитаем данные из файла и закроем его
	fSignIn.Read(bData,dwDataLen);
	fSignIn.Close();
	//NMS : Если нужно читаем данные из файла данных
	DWORD dwDataDataLen=0;
	BYTE* bDataData=NULL;
	CCertAutoBytePtr bDataDataPtr(NULL);
	if (bDetached)
	{
		dwDataDataLen=fDataIn.GetLength();
		bDataData=(BYTE*)malloc(dwDataDataLen);
		if (bDataData==NULL)
		{
			WriteToLog(_T("Не удалось выделить %d байт памяти для файла \"%s\" !"),
					   dwDataDataLen,dataFileName);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : Сделаем указатель автоматическим
		bDataDataPtr.Attach(bDataData);
		//NMS : Читаем данные из файла и закрываем его
		fDataIn.Read(bDataData,dwDataDataLen);
		fDataIn.Close();
	}
	HCRYPTPROV	hProv=NULL;	
	if (!::CryptAcquireContext(&hProv,NULL,NULL,75,CRYPT_VERIFYCONTEXT))
	{
		throw CString(_T("Не удалось получить контекст криптопровайдера !"));
	}
	CCertCryptProv hProvClose(&hProv);

	//NMS : Создаем хендл сообщения
	HCRYPTMSG hMsg=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										  dwDetachedFlag,
										  0,
										  hProv,
										  NULL,										  
										  NULL);
	if (hMsg==NULL)
	{
		WriteToLog(_T("Не удалось открыть криптосообщения для расшифровки, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgClose(&hMsg);
	//NMS : Заливаем в сообщение данные из файла данных
	if (!::CryptMsgUpdate(hMsg,bData,dwDataLen,TRUE))
	{
		WriteToLog(_T("Не удалось добавить данные из файла \"%s\" в сообщение, причина : %s !"),
				   signFileName,GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantAddDataToMessage;
	}
	bDataPtr.Free();
	if (bDetached)
	{
		//NMS : Заливаем в сообщение данные из файла данных
		if (!::CryptMsgUpdate(hMsg,bDataData,dwDataDataLen,TRUE))
		{
			WriteToLog(_T("Не удалось добавить данные из файла \"%s\" в сообщение, причина : %s !"),
					   dataFileName,GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantAddDataToMessage;
		}
		bDataDataPtr.Free();
	}

	DWORD dwCount=0;
	DWORD dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_TYPE_PARAM,0,&dwCount,&dwSize))
	{
		WriteToLog(_T("Не удалось получить тип криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Файл является подписью ???
	if (dwCount!=CMSG_SIGNED)
	{
		WriteToLog(_T("Файл \"%s\"  не является файлом подписи !"),signFileName);
		return m_LastErrorCode =CCPC_FileNotSigned;
	}

	//NMS : Узнаем декодированный размер
	DWORD cbDecoded = 0;
	dwSize=sizeof(dwCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,NULL,&cbDecoded))
	{
		WriteToLog(_T("Не удалось получить размер для декодирования, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}	
	BYTE* pbDecoded=NULL;
	CCertAutoBytePtr pbDecodedPtr(NULL);	
	//NMS : Выделяем память
	pbDecoded=(BYTE *)malloc(cbDecoded);
	if (pbDecoded==NULL)
	{
		WriteToLog(_T("Не удалось выделить %d байт памяти для декодирования !"));
		return m_LastErrorCode =CCPC_OutOfMemory;
	}
	//NMS : Делаем автоуказатель
	pbDecodedPtr.Attach(pbDecoded);
	//NMS : Читаем данные
	if (!::CryptMsgGetParam(hMsg,CMSG_CONTENT_PARAM,0,pbDecoded,&cbDecoded))
	{
		WriteToLog(_T("Не удалось прочитать декодированные данные, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}

	//NMS : Открываем хранилище для сообщения
	HCERTSTORE hMsgStore=::CertOpenStore(CERT_STORE_PROV_MSG,
										 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
										 NULL,
										 0,
										 hMsg);
	if(hMsgStore==NULL)
	{
		WriteToLog(_T("Не удалось открыть хранилище по хэндлу криптографического сообщения, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantOpenStore;
	}
	//NMS : Делаем хранилище автоматическим
	CCertAutoStore hMsgStoreAuto(hMsgStore);
	//NMS : Открываем только SST
	const DWORD dwStoreTypes=CST_SST;
	int nResult=CertOpenStore(dwStoreTypes);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode =nResult;
	}
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this,dwStoreTypes);
	//NMS : Получим хэндл
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);

	//NMS : Узнаем кол-во подписчиков
	DWORD dwSignersCount = 0;
	dwSize=sizeof(dwSignersCount);
	if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_COUNT_PARAM,0,&dwSignersCount,&dwSize))
	{
		WriteToLog(_T("Не удалось получить количество подписчиков, причина : %s !"),
				   GetSystemErrorDesc());
		return m_LastErrorCode =CCPC_CantGetParamMessage;
	}
	//NMS : Проверим подпись на валидность !
	bool bSigValid=true;
	CString strSignDateTime;
    DWORD dwSigner(0);
	for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
	{
		DWORD cbSignerCertInfo = 0;
		//NMS : Получим размер инфы о подписчике
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,NULL,&cbSignerCertInfo))
		{
			WriteToLog(_T("Не удалось получить размер информации о подписчике, причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Узнали размер выделяем память
		PCERT_INFO pSignerCertInfo=NULL;
		pSignerCertInfo=(PCERT_INFO)malloc(cbSignerCertInfo);
		if (pSignerCertInfo==NULL)
		{
			WriteToLog(_T("Не удалось выделить %d байт памяти для подписчика !"),cbSignerCertInfo);
			return m_LastErrorCode =CCPC_OutOfMemory;
		}
		//NMS : Делаем указатель автоматичиеским
		CCertAutoBytePtr pSignerCertInfoPtr((BYTE*)pSignerCertInfo);
		//NMS : Получаем инфу
		if (!::CryptMsgGetParam(hMsg,CMSG_SIGNER_CERT_INFO_PARAM,dwSigner,pSignerCertInfo,&cbSignerCertInfo))
		{		
			WriteToLog(_T("Не удалось получить информацию о подписчике, причина : %s !"),GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Получим сертификат подписчика
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
				WriteToLog(_T("Не удалось получить сертификат подписчика из БД"));
			}
		}
#endif //

		//NMS : Если не нашли в hMsgStore, поищем в hSST
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
		
		//NMS : Не нашли сертификат :(
		if(pSignerCertContext==NULL)
		{
			WriteToLog(_T("Не удалось найти сертификат подписчика, причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantFindCertInStore;
		}
		
		CCertFreeCertificateContext CertContextFree(&pSignerCertContext);
		//NMS : Проверим сертификат на валидность !		
		CERTVALIDPARAM ValidParam;
		bool bValid=CertIsValid(pSignerCertContext,&ValidParam);
		//NMS : Флаг о валидности сертификата
		const bool bCertValid=bValid;

		// AKV: Проверяем, тот ли это сертификат, чью подпись надо проверить.
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
				m_strLastError = _T("Файл должен быть подписан другим сертификатом.");
			}
		}
		// AKV End

		PCERT_INFO pSignerCertificateInfo=pSignerCertContext->pCertInfo;		
		ASSERT(pSignerCertificateInfo!=NULL);
		CString sValidText;
		//NMS : Только если сертификат валиден
		bool bCheckSign=false;//NMS : Признак того, что подпись проверяли
		if (bCertValid!=false || bNotCheckCertValid==TRUE)
		{
			bCheckSign=true;
			//NMS : Если включен, специальный режим, тогда выставляем валидность в истину
			if (bNotCheckCertValid!=FALSE)
			{
				bValid=true;
			}
			if (!::CryptMsgControl(hMsg,0,CMSG_CTRL_VERIFY_SIGNATURE,pSignerCertificateInfo))
			{
				bValid=false;
				WriteToLog(_T("Подпись не верна :")+GetSystemErrorDesc());
			}
		}
		//NMS : Проверим подпись
		if (bValid==false)
		{
			if (bCheckSign!=false)
			{
				sValidText=_T("Подпись не верна :")+GetSystemErrorDesc();
			}
			else
			{
				sValidText=_T("Подпись не верна");
			}				
		}
		else
		{
			sValidText=_T("Подпись верна");
			strSignDateTime=GetSignTime(hMsg,dwSigner);
		}
		//NMS : Тут будем дописывать про сертификат	
		if (bCertValid!=false)
		{
			sValidText+=_T(" Cертификат действителен");
		}
		else
		{
			sValidText+=_T(" Cертификат не действителен");
		}
		CString strSubject=CertNameBlob2Str(&pSignerCertificateInfo->Subject);
		CString sInfo=strSubject+"\t"+sValidText+"\t"+strSignDateTime;

		//NMS : Получаем отпечаток
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
	//NMS : Если все хорошо импортируем сертификаты и CLR
	if (bSigValid)
	{
		//NMS : Импорт прочих сертификатов
		dwSize=sizeof(dwSignersCount);
		if (!::CryptMsgGetParam(hMsg,CMSG_CERT_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
			WriteToLog(_T("Не удалось получить количество подписчиков, причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		//NMS : Перебираем подписчиков
		for (dwSigner=0; dwSigner<dwSignersCount; dwSigner++)
		{
			DWORD cbCert=0;
			BYTE* pCert=NULL;
			//NMS : Получаем размер
			if (!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,NULL,&cbCert))
			{
				WriteToLog(_T("Не удалось получить размер сертификата, причина : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
				
			}
			//NMS : Выделяем под размер память
			pCert=(BYTE*)malloc(cbCert);
			if (pCert==NULL)
			{
				WriteToLog(_T("Не удалось выделить %d байт памяти под сертификат !"),cbCert);
				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : Делаем указатель автоматическим
			CCertAutoBytePtr pCertPtr(pCert);
			//NMS : Получаем данные сертификата
			if ((!::CryptMsgGetParam(hMsg,CMSG_CERT_PARAM,dwSigner,pCert,&cbCert)) ||
				pCert==NULL)
			{
				WriteToLog(_T("Не удалось получить данные сертификата, причина : %s !"),GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : По данным создаем контекст, сертификат			
			PCCERT_CONTEXT pCertContext=CertCreateCertificateContext(X509_ASN_ENCODING,pCert,cbCert);
			pCertPtr.Free();
			if(pCertContext==NULL)
			{
				WriteToLog(_T("Не удалось создать сертификат по данным, причина : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantCreateCert;
			}
			//NMS : Если сертификат хороший, добавляем
			int nErrorCode=CCPC_NoError;
			CERTVALIDPARAM ValidParam;
/* КАА: Убираем проверку на валидность при записи в SST - пусть всегда сохраняется
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
		//NMS : Импорт CRL-ов
		dwSize=sizeof(dwSignersCount);
		if (!CryptMsgGetParam(hMsg,CMSG_CRL_COUNT_PARAM,0,&dwSignersCount,&dwSize))
		{
			WriteToLog(_T("Не удалось получить, количество CRL, причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode =CCPC_CantGetParamMessage;
		}
		for (dwSigner=0;dwSigner<dwSignersCount;dwSigner++)
		{
			DWORD cbCRL = 0;
			BYTE* pCRL = NULL;
			//NMS : Узнаем размер
			if (!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,NULL,&cbCRL))
			{
				WriteToLog(_T("Не удалось получить размер CLR, причина %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_CantGetParamMessage;
			}
			//NMS : Выделяем под этот размер память
			pCRL=(BYTE*)malloc(cbCRL);
			if (pCRL==NULL)
			{
				WriteToLog(_T("Не удалось выделить %d байт памяти для CLR, причина : %s !"),
						   GetSystemErrorDesc());
				return m_LastErrorCode =CCPC_OutOfMemory;
			}
			//NMS : Делаем указатель автоматическим
			CCertAutoBytePtr pCRLPtr(pCRL);
			//NMS : Пробуем получить само сообщение
			if ((!::CryptMsgGetParam(hMsg,CMSG_CRL_PARAM,dwSigner,pCRL,&cbCRL)) ||
				pCRL==NULL)
			{
				WriteToLog(_T("Не удалось получить CLR, причина : %s !"),
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
					WriteToLog(_T("Не удалось создать CLR по данным, причина %s !"),
						GetSystemErrorDesc());
					return m_LastErrorCode =CCPC_CantCreateCRL;
				}
				//NMS : Добавляем			
				CertAddCRLContextToStore(hSST,pCRLContext,CERT_STORE_ADD_NEWER ,NULL);
				//NMS : Освобождаем контекст
				CertFreeCRLContext(pCRLContext);
			}
		}
	}
	//NMS : Запишем декодированные данные в файл
	if (!bDetached && dataFileName!="")
	{
		CFile fOut;
		if (!fOut.Open(dataFileName,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
		{
			WriteToLog(_T("Не удалось открыть файл \"%s\" на запись, причина : %s !"));
			return m_LastErrorCode =CCPC_CantOpenFileWrite;
		}
		//NMS : Записываем
		fOut.Write(pbDecoded,cbDecoded);
		//NMS : Закрываем
		fOut.Close();
	}

	CString strCertStorePath;

// KAA : запросим директорию Dipost
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : Проверим последний слэш
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif //
	strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
	//NMS : Сохраняем изменения в файл
	if (hSST != NULL) {
		if (::CertSaveStore(hSST,
							PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							CERT_STORE_SAVE_AS_STORE,
							CERT_STORE_SAVE_TO_FILENAME_A,
							(void*)(LPCSTR)strCertStorePath,
							0)==FALSE)
		{
			nResult=CCPC_CantOpenFileWrite;
			WriteToLog(_T("Не удалось сохранить данные в хранилище certstore.sst, путь \"%s\", причина : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
		}
	}
	//NMS : Формируем результат
	nResult=CCPC_NoError;
	if (bSigValid==FALSE)
	{
		nResult=CCPC_VerifyFailed;
	}
	else
	{
		//NMS : Обнулим последнюю ошибку
		m_strLastError.Empty();
	}
	//NMS : Возвращаем результат !
	return m_LastErrorCode =nResult;	
}
#ifndef KILL_STREAM_INTERFACE
/* LLP
Было решено в первой итерации не менять старые функции(((
Поэтому создаем временные файлы и работаем через них...
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
    // хз надо ли...
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
    // хз надо ли...
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
    // хз надо ли...
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
