#include "stdafx.h"
# include <afx.h>
#include <shlwapi.h>
// #include "Yar\ini.h"

#include <vector>
#include <afxtempl.h>
// #include "ICPCrypto.h"
#include "LogFile.h"
#include "BinData.h"
#include "StringArrayEx.h"
#include "FileMng.h"
#include "CBase64Utils.h"
#include "IniMng.h"

#include <WinCrypt.h>
#pragma comment(lib,"Crypt32.lib")
#include "ICPCryptoImpl.h"

#ifdef _DEBUG
	#undef THIS_FILE
	static char THIS_FILE[]=__FILE__;
	#define new DEBUG_NEW
#endif

//NMS : Критическая секция для лога
static CCriticalSection g_csLog;

//*****************************************************************************
//* CCertFreeCertificateContext
//*****************************************************************************

//NMS : Автоматически освобождает контекст сертификата

CCertFreeCertificateContext::CCertFreeCertificateContext(PCCERT_CONTEXT* ppCert)
: m_ppCert(ppCert) {}

CCertFreeCertificateContext::~CCertFreeCertificateContext()
{
	if (m_ppCert!=NULL &&
		(*m_ppCert)!=NULL)
	{
		::CertFreeCertificateContext((*m_ppCert));
		(*m_ppCert)=NULL;
	}
}

//*****************************************************************************
//* CCertCryptDestroyKey
//*****************************************************************************

//NMS : Автоматически освобождает ключ

CCertCryptDestroyKey::CCertCryptDestroyKey(HCRYPTKEY* phKey)
: m_phKey(phKey){}

CCertCryptDestroyKey::~CCertCryptDestroyKey()
{
	if (m_phKey!=NULL &&
		(*m_phKey)!=NULL)
	{
		::CryptDestroyKey((*m_phKey));
		(*m_phKey)=NULL;
	}
}

//*****************************************************************************
//* CCertCryptDestroyHash
//*****************************************************************************

//NMS : Автоматически освобождает хэш

CCertCryptDestroyHash::CCertCryptDestroyHash(HCRYPTHASH* phHash)
: m_phHash(phHash) {}

CCertCryptDestroyHash::~CCertCryptDestroyHash()
{
	ASSERT(m_phHash!=NULL);
	if (m_phHash!=NULL &&
		(*m_phHash)!=NULL)
	{
		::CryptDestroyHash((*m_phHash));
		(*m_phHash)=NULL;
	}
}

//*****************************************************************************
//* CCertCryptProv
//*****************************************************************************

//NMS : Автоматически освобождает криптопровайдера

CCertCryptProv::CCertCryptProv(HCRYPTPROV* phProv)
: m_phProv(phProv) {}

CCertCryptProv::~CCertCryptProv()
{
	ASSERT(m_phProv!=NULL);
	if (m_phProv!=NULL &&
		(*m_phProv)!=NULL)
	{
		::CryptReleaseContext((*m_phProv),0);
		(*m_phProv)=NULL;
	}
}

//*****************************************************************************
//* CCertCryptMsgClose
//*****************************************************************************

//NMS : Автоматически освобождает дискриптор криптографического сообщения

CCertCryptMsgClose::CCertCryptMsgClose(HCRYPTMSG* phMsg)
: m_phMsg(phMsg) {}

CCertCryptMsgClose::~CCertCryptMsgClose()
{
	ASSERT(m_phMsg!=NULL);
	if (m_phMsg!=NULL &&
		(*m_phMsg)!=NULL)
	{
		::CryptMsgClose((*m_phMsg));
		(*m_phMsg)=NULL;
		m_phMsg=NULL;
	}
}

//*****************************************************************************
//* CCertCloseCache
//*****************************************************************************

//NMS : Закрывает автоматически кэш открытых хранилищ сертификатов
CCertCloseCache::CCertCloseCache(ICPCryptoImpl* pCls,const DWORD dwType/*=CST_ALL*/)
: m_pCls(pCls),m_dwType(dwType){}

CCertCloseCache::~CCertCloseCache()
{
	if (m_pCls!=NULL)
	{
		m_pCls->CertCloseStore(m_dwType);
		m_pCls=NULL;
	}
}

//*****************************************************************************
//* CCertAutoBytePtr
//*****************************************************************************

CCertAutoBytePtr::CCertAutoBytePtr(const BYTE* pPtr,const bool bFree/*=true*/)
{
	Attach(pPtr,bFree);
}	

CCertAutoBytePtr::~CCertAutoBytePtr()
{
	Free();
}

//NMS : Устанавливаем указатель на данные и метод удаления
void CCertAutoBytePtr::Attach(const BYTE* pPtr,const bool bFree/*=true*/)
{
	m_pPtr=const_cast<BYTE*>(pPtr);
	m_bFree=bFree;
}

//NMS : Удаляем и обнуляем указатель на данные
void CCertAutoBytePtr::Free(void)
{
	if (m_pPtr!=NULL)
	{
		//NMS : Удаляем
		if (m_bFree)
		{
			free(m_pPtr);
		}
		else
		{
			delete[] m_pPtr;
		}
		//NMS : Обнуляем
		m_pPtr=NULL;
	}
}

//*****************************************************************************
//* CCertAutoStore
//*****************************************************************************

//NMS : Автоматически закрывает хранилище

CCertAutoStore::CCertAutoStore(HCERTSTORE hStore)
: m_hStore(NULL)
{
	Attach(hStore);
}

CCertAutoStore::~CCertAutoStore()
{
	Close();
}

void CCertAutoStore::Attach(HCERTSTORE hStore)
{
	m_hStore=hStore;
}

void CCertAutoStore::Close()
{
	if (m_hStore!=NULL)
	{
		::CertCloseStore(m_hStore,CERT_CLOSE_STORE_FORCE_FLAG);
	}
}

//*****************************************************************************
//* CCertLockMethods
//*****************************************************************************

//NMS : Автоматически блокирует доступ для других к вызываемому методу,

CCertLockMethods::CCertLockMethods(const ICPCryptoImpl* pICPCryptoImpl)
: m_pICPCryptoImpl((ICPCryptoImpl*)pICPCryptoImpl)
, m_nStatus(CCPC_NoError)
{
	ASSERT(m_pICPCryptoImpl!=NULL);
	m_nStatus=m_pICPCryptoImpl->LockMethods();
}

CCertLockMethods::~CCertLockMethods()
{
	ASSERT(m_pICPCryptoImpl!=NULL);	
	if (m_pICPCryptoImpl!=NULL &&
		m_nStatus==CCPC_NoError)
	{
		m_pICPCryptoImpl->UnLockMethods();
	}
	m_pICPCryptoImpl=NULL;
}

bool CCertLockMethods::Check(void) const
{
	bool bResult=true;
	if (m_nStatus!=CCPC_NoError)
	{
		bResult=false;
	}
	return bResult;
}

//*****************************************************************************
//* ICPCryptoImpl
//*****************************************************************************

//NMS : ТОчка входа для потока, который обновляет CRL в фоне
static UINT _ThreadEntryUpdateCRL(LPVOID pParam)
{	
	try
	{
		TRACE("\nЗапустился поток обновления CRL в фоне !\n");
		ICPCryptoImpl* pCPCryptoImpl=(ICPCryptoImpl*)pParam;
		VERIFY(pCPCryptoImpl!=NULL);
		pCPCryptoImpl->UpdateCRLs();
		TRACE("\nЗакончил работу поток обновления CRL в фоне !\n");
	}
	catch(...)
	{
		TRACE("\nПри обновлении CRL в фоне произошла неизвестная ошибка !\n");
	}	
	return 0;
}

//NMS : Объект потока, который занимается обновление CRL
#ifdef CTHREAD_UPDATE_CRL
static CThreadsPool g_ThreadUpdateCRL;
#endif // CTHREAD_UPDATE_CRL

ICPCryptoImpl::ICPCryptoImpl()
: m_strRootPath(_T(""))
, m_tmLastCRLCheck(0)
, m_tValidCache(CTime::GetCurrentTime())

{
#ifdef CTHREAD_UPDATE_CRL
	m_pCPCryptoCallBack = NULL;
#endif // CTHREAD_UPDATE_CRL

	//NMS : Обнулим критическую секцию и проведем её инициализацию
	ZeroMemory(&m_CS,sizeof(CRITICAL_SECTION));
	::InitializeCriticalSection(&m_CS);	
	//NMS : Добавим префикс по умолчанию
	m_arrOIDPrefix.Add(GetDefaultOID());
}
void ICPCryptoImpl::release()
{
    delete this;
}
ICPCryptoImpl::~ICPCryptoImpl()
{
	//NMS : Почистим кэш, если он не очистился
	CertCloseStore(CST_ALL);
	//NMS : Удалим все временные файлы
	DeleteAllTempFiles();
	//NMS : Завершаем поток обновления CRL
#ifdef CTHREAD_UPDATE_CRL
	if (g_ThreadUpdateCRL.IsCreate())
	{
		g_ThreadUpdateCRL.Destroy();
	}
#endif // CTHREAD_UPDATE_CRL

	//NMS : Все, что было логе сбрасываем в файл,
	//		только если лог не отключен
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : Защита для Log
		CSingleLock LogLock(&g_csLog,TRUE);
		m_Log.WriteLog();
	}
	//NMS : Освободим критическую секцию
	::DeleteCriticalSection(&m_CS);
}

//NMS : Блокирует доступ к методам
int	ICPCryptoImpl::LockMethods(void)
{
	//NMS : Вход в критическую секцию
	EnterCriticalSection(&m_CS);
	
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : Разблокирует доступ к методам
int	ICPCryptoImpl::UnLockMethods(void)
{
	//NMS : Все, что было логе сбрасываем в файл, если это требуется
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : Защита для Log
		CSingleLock LogLock(&g_csLog,TRUE);
		m_Log.WriteLog();
	}	
	//NMS : Удалим все временные файлы
	DeleteAllTempFiles();
	//NMS : Выход из критической секции
	::LeaveCriticalSection(&m_CS);
	return m_LastErrorCode = CCPC_NoError;
}

//**********************************************************
//NMS : Инициализация
//**********************************************************

#define STR_VALUE_LIC_OID		_T("LicOID")
#define STR_KEY_LIC_OID_PREFIX	_T("OIDPrefix")

/*virtual*/ int ICPCryptoImpl::Initialize(CString sRootPath, ICPCryptoCallBack* iCPCryptoCallBack/*=NULL*/)
{
// KAA : сохраним интерфейс обратного вызова
#ifdef CTHREAD_UPDATE_CRL
	m_pCPCryptoCallBack = iCPCryptoCallBack;
#endif // CTHREAD_UPDATE_CRL

#ifdef _DEBUG
	//__asm int 3;
#endif//_DEBUG


	//NMS : Сохраним путь
	m_strRootPath=sRootPath;

#ifdef CTHREAD_UPDATE_CRL
	// KAA : запросим директорию Dipost-а 
	if (NULL!=m_pCPCryptoCallBack)
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
#endif // CTHREAD_UPDATE_CRL

	//NMS : Проверим последний слэш
	m_strRootPath.TrimRight(_T('\\'));
	
	//NMS : Загрузим настройки
	LoadSettings();
	//NMS : Установим путь к лог файлу, только если лог включен
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : Защита для Log
		CSingleLock LogLock(&g_csLog,TRUE);
		//NMS : Запишем, то что было в логе
		m_Log.WriteLog();
		//NMS : Формируем новый путь к логу
		m_Log.m_sPFNLog.Format(_T("%s\\CPCrypto.log"),m_strRootPath);
		//NMS : Лог будет не 100кб по умолчанию, а 512 кб
		m_Log.SetLogSize(_T("512"));
	}	
	//NMS : Лицензия
	m_arrOIDPrefix.RemoveAll();
	m_arrOIDPrefix.Add(GetDefaultOID());	
#if 0 // not check license
	CLicValidator lic(sRootPath,STR_VALUE_LIC_OID,1);
    if (lic.IsValid())
	{
		m_arrOIDPrefix.RemoveAll();
		//NMS : Делаем совместимость со старым режимом чтения
		CString strPrefix=lic.GetValue(STR_KEY_LIC_OID_PREFIX);
		if (!strPrefix.IsEmpty())
		{
			m_arrOIDPrefix.Add(strPrefix);
		}
		LONG nPrefixNo=1;		
		for(;;)
		{
			//NMS : Защита от рекурсии
			if (nPrefixNo>100)
			{
				break;
			}
			//NMS : Читаем
			strPrefix=lic.GetValue(CStringProc::Format(_T("%s_%d"),STR_KEY_LIC_OID_PREFIX,nPrefixNo));
			nPrefixNo++;
			//NMS : Если пусто сразу выходим
			if (strPrefix.IsEmpty())
			{
				break;
			}
			//NMS : Если есть данные, запишем их в массив
			m_arrOIDPrefix.Add(strPrefix);
		}
		//NMS : Если массив пустой добавим OID по умолчанию
		if (m_arrOIDPrefix.GetSize()<=0)
		{
			m_arrOIDPrefix.Add(GetDefaultOID());
		}
	}
	else
	{
		WriteToLog(_T("Не найдено ни одной действующей лицензии, при проверке OID будет использоваться префикс по умолчанию !"));
	}
	WriteToLog(_T("При проверке OID будут использованы префиксы \"%s\"."),((CStringArrayEx*)&m_arrOIDPrefix)->GetAsString(_T(";"),FALSE));
	m_strLastError.Empty();

	//NMS : Проверим путь на существование, а
	//		так же что он является путем (директорией)
	if (!CFileMng::IsDirExist(sRootPath))		
	{
		WriteToLog(_T("Путь не существует или не доступен \"%s\" !"),sRootPath);
		//NMS : Был передан плохой путь !
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}
	//NMS : Обновляем certstore
	UpdateCertStore();
#endif // 0

// KAA : Убираем принудительное обновление CRL при инитиализации
/* 
#if 0
	//NMS : Обновляем CRL в паралельном потоке
	//NMS : Нельзя обновлять просто так, так как
	//		портится хранилище сертификатов SST
	if (!g_ThreadUpdateCRL.IsStart())
	{
		if (g_ThreadUpdateCRL.IsCreate())
		{
			g_ThreadUpdateCRL.Destroy();
		}
		CPtrArray arrParams;
		arrParams.Add(this);
		if (g_ThreadUpdateCRL.Create(_ThreadEntryUpdateCRL,1,&arrParams))
		{
			g_ThreadUpdateCRL.Start();
		}
	}
#else
	UpdateCRLs();
#endif//0
*///UpdateCRLs();
	int Result = CCPC_NoError;

#ifdef CTHREAD_UPDATE_CRL
// KAA : пост инициализация
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnInitialize(Result);
#endif // CTHREAD_UPDATE_CRL

	//NMS : Вернем успех
	return m_LastErrorCode = Result;
}

/*virtual*/ BOOL ICPCryptoImpl::IsInitialized()
{
	BOOL bResult=FALSE;
	if (!m_strRootPath.IsEmpty())
	{
		bResult=TRUE;
	}
	return bResult;
}

//**********************************************************
//NMS : Protected методы
//**********************************************************

//NMS : Возвращает описание системной ошибки
CString ICPCryptoImpl::GetSystemErrorDesc(const DWORD dwError/*=::GetLastError()*/)
{	
	CString m_strErrorDescr;
	LPVOID lpMsgBuf=NULL;
	::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					dwError,
					0,
					(LPTSTR)&lpMsgBuf,
					0,
					NULL);
	CString strError((LPCSTR)lpMsgBuf);
	::LocalFree(lpMsgBuf);
	strError.TrimRight();	
	m_strErrorDescr.Format("%s (SystemErrorCode: 0x%.8X)",strError,dwError);
	return m_strErrorDescr;
}

//NMS : Открываем хранилища в которых будем искать сертификат
//	bReOpen - переоткрыть все хранилища заново, а не
//	брать хэндлы из кэша.
int ICPCryptoImpl::CertOpenStore(const DWORD dwType/*=CST_ALL*/,
								 const bool bReOpen/*=false*/)
{
//	WriteToLog(_T("Вызов ICPCryptoImpl::CertOpenStore"));
	//NMS : Если нужно все переоткрыть, тогда закроем
	//		все открытые хранилища
	if (bReOpen)
	{
		WriteToLog(_T("Очистка кэша хэндлов хранилищ сертификатов !"));
		CertCloseStore(dwType);
	}
	//NMS : Нужно открывать хранилища и складывать хэндлы в кэш
	HCERTSTORE hStore=NULL;
	//NMS : В случае ошибки автоматом закроем все открытые хранилища
	CCertCloseCache CertCloseCache(this);
	//NMS : Самым первым открываем certstore.sst
	if (dwType&CST_SST && CertGetHandleStoreByType(CST_SST)==NULL)
	{
		CString strCertStorePath;

#ifdef CTHREAD_UPDATE_CRL
// KAA : запросим путь Dipost
		if (NULL!=m_pCPCryptoCallBack)
		{
			if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
					m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
			//NMS : Проверим последний слэш
			m_strRootPath.TrimRight(_T('\\'));	
		}
#endif // CTHREAD_UPDATE_CRL
		strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
		//NMS : Проверим пути к certstore.sst
		CertStoreVerifyExistPath(strCertStorePath);
		//NMS : Открываем ...	
		hStore=::CertOpenStore(CERT_STORE_PROV_FILENAME_A,
							   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							   NULL,
							   CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_CREATE_NEW_FLAG,
							   (LPCSTR)strCertStorePath);
#ifdef CTHREAD_UPDATE_CRL
		if (hStore==NULL && m_pCPCryptoCallBack==NULL)
		{
			WriteToLog(_T("Не удалось открыть хранилище certstore.sst, путь \"%s\", причина : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
#endif // CTHREAD_UPDATE_CRL
		//NMS : Успешно открыли, добавляем в кэш
		m_mapCertStore.SetAt(CST_SST,hStore);
		hStore=NULL;
	}
	//NMS : Открываем личные сертификаты
	if (dwType&CST_MY && CertGetHandleStoreByType(CST_MY)==NULL)
	{
		hStore=::CertOpenStore(CERT_STORE_PROV_SYSTEM,
							   0,
							   NULL,CERT_SYSTEM_STORE_CURRENT_USER,
							   L"My");
		if (hStore==NULL)
		{
			WriteToLog(_T("Не удалось открыть хранилище Личные(My), причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : Успешно открыли, добавляем в кэш
		m_mapCertStore.SetAt(CST_MY,hStore);
		hStore=NULL;
	}
	//NMS : Открываем root сертификаты 
	if (dwType&CST_ROOT && CertGetHandleStoreByType(CST_ROOT)==NULL)
	{
		hStore=::CertOpenStore(CERT_STORE_PROV_SYSTEM,
							   0,
							   NULL,
							   CERT_SYSTEM_STORE_CURRENT_USER,
							   L"Root");
		if (hStore==NULL)
		{
			WriteToLog(_T("Не удалось открыть хранилище Доверенные корневые центры сертификации(Root), причина : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : Успешно открыли, добавляем в кэш
		m_mapCertStore.SetAt(CST_ROOT,hStore);
		hStore=NULL;
	}

	//  KAA: Открываем сертификаты во внешнем хранилище CST_OWNER
	if (dwType&CST_OWNER && CertGetHandleStoreByType(CST_OWNER)==NULL)
	{
#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
			hStore=m_pCPCryptoCallBack->OnCertOpenStore();
#endif // CTHREAD_UPDATE_CRL

		if (hStore==NULL)
		{
			WriteToLog(_T("Не удалось открыть хранилище"));
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : Успешно открыли, добавляем в кэш
		m_mapCertStore.SetAt(CST_OWNER,hStore);
		hStore=NULL;
	}


	//NMS : Все хорошо открылось, поэтому закрывать ни чего не нужно !
	CertCloseCache.m_pCls=NULL;
	//NMS : Возвращаем успех !
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : Закрываем открытые хранилища сертификатов

void ICPCryptoImpl::CertCloseStore(const DWORD dwType/*=CST_ALL*/)
{
	//WriteToLog(_T("Вызов ICPCryptoImpl::CertCloseStore"));

	//NMS : Бежим по карте
	POSITION pos=m_mapCertStore.GetStartPosition();
	DWORD dwTypeKey;
	HCERTSTORE hStore=NULL;
	//NMS : Если установлен флажок CST_ALL значит чистим все
	const bool bClearAll=(dwType==CST_ALL) ? true:false;
	while(pos!=NULL)
	{
		hStore=NULL;
		dwTypeKey=0x00;
		m_mapCertStore.GetNextAssoc(pos,dwTypeKey,hStore);
// KAA : закрытие внешнего хранилища
		if (dwTypeKey==CST_OWNER)
		{
#ifdef CTHREAD_UPDATE_CRL
			if (NULL!=m_pCPCryptoCallBack)
				m_pCPCryptoCallBack->OnCertCloseStore(hStore);
#endif // CTHREAD_UPDATE_CRL
			hStore = NULL;
		}

		if (hStore!=NULL)
		{
			if (bClearAll)
			{
				//NMS : Закрываем  хранилище
				::CertCloseStore(hStore,CERT_CLOSE_STORE_FORCE_FLAG);
			}
			else if (dwType&dwTypeKey)
			{
				//NMS : Закрываем  хранилище
				::CertCloseStore(hStore,CERT_CLOSE_STORE_FORCE_FLAG);
				//NMS : Удаляем из карты, только то что просят,
				//		так как в карте могут лежать и другие хэндлы
				m_mapCertStore.RemoveKey(dwTypeKey);
			}
		}
	}
	//NMS : Чистим всю карту
	if (bClearAll)
	{
		m_mapCertStore.RemoveAll();
	}
}

//NMS : Позволяет получить хэндл хранилища из кэша по типу
HCERTSTORE ICPCryptoImpl::CertGetHandleStoreByType(const DWORD dwType)
{
	HCERTSTORE hResult=NULL;
	m_mapCertStore.Lookup(dwType,hResult);
	return hResult;
}

//NMS : Проверяем существование SST файла, если не существует
//		создаем, причем даже с учетом директорий.
void ICPCryptoImpl::CertStoreVerifyExistPath(CString strStoreFilePath)
{
	//NMS : Проверяем существование SST файла
	CFileFind ff;
	if (!ff.FindFile(strStoreFilePath))
	{
		//NMS : Создаем директории, если они не существуют в пути strStoreFilePath
		CString sStorePath="";
		while (strStoreFilePath.Find("\\")>=0)
		{
			sStorePath+=strStoreFilePath.Left(strStoreFilePath.Find("\\"));
			strStoreFilePath.Delete(0,1+strStoreFilePath.Find("\\"));
			CreateDirectory(sStorePath,NULL);
			sStorePath+="\\";
		}
		//NMS : Создаем сам файл
		CFile file;
		if (file.Open(sStorePath+strStoreFilePath,
					  CFile::modeWrite|CFile::modeCreate|CFile::modeNoTruncate|
					  CFile::shareDenyWrite))
		{
			file.Close();
		}
	}
}

//NMS : Выводим сообщение в лог
void ICPCryptoImpl::WriteToLog(LPCTSTR lpszFormat,...)
{
	ASSERT(lpszFormat!=NULL);
	if (lpszFormat==NULL)
	{
		return;
	}

	CString strResult;
	va_list pList=NULL;
	va_start(pList,lpszFormat);		
	strResult.FormatV(lpszFormat,pList);
	va_end(pList);
	//NMS : Установим последнюю ошибку
	m_strLastError=strResult;
	//NMS : Лог отключен
	if (m_Settings.bOffLogFile!=FALSE)
	{
		return;
	}
	try
	{	
		//NMS : В отладке будем выводить инфу
#ifdef _DEBUG
		CString strResult2(strResult);
		strResult2+=_T("\r\n");
		//NMS : TRACE для удобства
		::OutputDebugString(strResult2);
#endif //_DEBUG
		
// KAA : пишем в лог интерфейса, если вернулся с FALSE, то писать в обычный лог не нужно  
		
		BOOL bResolved = TRUE;
#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
		{
			bResolved = m_pCPCryptoCallBack->WriteLog(strResult);
		}
#endif // CTHREAD_UPDATE_CRL
		if (bResolved)
		{
				//NMS : Пишем в "обычный" лог
			CSingleLock LogLock(&g_csLog,TRUE);
			m_Log.AddLine(strResult);
		}
	}
	catch(...)
	{
		m_strLastError=_T("Exception in ICPCryptoImpl::WriteToLog !");
	}
}

/*static*/ CString ICPCryptoImpl::CertNameBlob2Str(const CERT_NAME_BLOB* pBlob,
												   const bool b345/*=false*/)
{
	ASSERT(pBlob!=NULL);
	CString strResult;
	if (pBlob!=NULL)
	{
		//NMS : Узнаем кол-во символов
		DWORD dwBuffLen=0x00;
		dwBuffLen=CertNameToStr(X509_ASN_ENCODING,
								const_cast<CERT_NAME_BLOB*>(pBlob),
								CERT_X500_NAME_STR,
								NULL,
								0);
		//NMS : Если конвертация осущевствляется для 345 приказа,
		//		тогда строку нужно просто сконвертить из
		//		DOS в Win кодировку
		if (b345 && ::GetLastError()==CRYPT_E_ASN1_BADTAG)
		{
			strResult=CString((char*)pBlob->pbData,pBlob->cbData);
// SMU: CN wrote in sign file in Win1251
//			strResult.OemToAnsi();
		}
		else if (dwBuffLen>0)
		{
			TCHAR* lpszString=new TCHAR[(dwBuffLen+1)*sizeof(TCHAR)];
			if (lpszString!=NULL)
			{
				ZeroMemory(lpszString,dwBuffLen+1);
				::CertNameToStr(X509_ASN_ENCODING,
								const_cast<CERT_NAME_BLOB*>(pBlob),
								CERT_X500_NAME_STR,
								lpszString,
								dwBuffLen);
				strResult=lpszString;
				delete[] lpszString;
				lpszString=NULL;
			}
		}
	}
	return strResult;
}

//NMS : Добавляет сертификат или CRL в хранилище (на данный момент это только SST)
int ICPCryptoImpl::AddCertOrCRLToStore(const CRYPT_DATA_BLOB* pCertOrCRL,const int iType)
{
	ASSERT(pCertOrCRL!=NULL);
	//WriteToLog(_T("Вызов ICPCryptoImpl::AddCertOrCRLToStore"));
	//NMS : Открываем только SST
	BOOL bResolved = false;
	int nResult = CCPC_NoError;
	
// KAA : добавляем крипто данные(CRL или Cert) во внешнее хранилище, если результат - FALSE идет обычное сохранение 
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
		bResolved = m_pCPCryptoCallBack->OnAddCertOrCRL(pCertOrCRL,iType,nResult);
#endif // CTHREAD_UPDATE_CRL
	
	if (bResolved)
		return m_LastErrorCode = nResult;

	nResult=CertOpenStore(CST_SST);
	if (nResult!=CCPC_NoError)
	{
		return m_LastErrorCode = nResult;
	}
	//NMS : Закрывать SST будем автоматом
	CCertCloseCache CertCloseCache(this);
	//NMS : Получим хендл открытого SST
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : Используем более низкоуровневую функцию, чтобы добавить
	//		сертификат в хранилище SST
	nResult=AddCertOrCRLToStoreEx(hSST,pCertOrCRL,iType);
	//NMS : Будем сохранять измененные данные
	if (nResult==CCPC_NoError)
	{
		nResult=SaveSSTInFile(hSST);
	}
	if (nResult==CCPC_NoError)
	{
		m_strLastError.Empty();
	}
	//NMS : Возвращаем результат
	return m_LastErrorCode = nResult;
}

//NMS : Добавляет сертификат или CRL в указанное хранилище
int ICPCryptoImpl::AddCertOrCRLToStoreEx(HCERTSTORE hStore,
										 const CRYPT_DATA_BLOB* pCertOrCRL,
										 const int nType)
{
	ASSERT(pCertOrCRL!=NULL);

	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}	

	//WriteToLog("Вызов ICPCryptoImpl::AddCertOrCRLToStoreEx");
	if (hStore==NULL) 
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	BOOL bResult=FALSE;
	LPCTSTR lpszName=NULL;
	long nResult=CCPC_NoError;
	//NMS : Разводим добавление по типу
	switch (nType)
	{
	case CMSG_CTRL_ADD_CERT:
		{
			lpszName=_T("сертификат");
			bResult=::CertAddEncodedCertificateToStore(hStore,
													   X509_ASN_ENCODING,
													   pCertOrCRL->pbData,
													   pCertOrCRL->cbData,
													   CERT_STORE_ADD_NEWER,
													   NULL);
			if (!bResult && (::GetLastError()!=CRYPT_E_EXISTS))
				nResult = CCPC_CantAddCertInStore;
			break;
		}		
	case CMSG_CTRL_ADD_CRL:
		{
			lpszName=_T("CRL");
			bResult=::CertAddEncodedCRLToStore(hStore,
											   X509_ASN_ENCODING,
											   pCertOrCRL->pbData,
											   pCertOrCRL->cbData,
											   CERT_STORE_ADD_NEWER,
											   NULL);
			if (!bResult && (::GetLastError()!=CRYPT_E_EXISTS))
				nResult = CCPC_CantAddCRLInStore;
			break;
		}		
	default:
		{
			lpszName=_T("unknown");
			WriteToLog("Вызов ICPCryptoImpl::AddCertOrCRLToStoreEx с параметром nType=%d, такой тип неизвестен !",nType);
			return m_LastErrorCode = CCPC_InternalError;			
		}
	}
	//NMS : Если не удалось добавить данные в хранилище
	if ((bResult==FALSE) && (::GetLastError()!=CRYPT_E_EXISTS))
	{
		WriteToLog(_T("Не удалось добавить %s в хранилище, причина : %s !"),
				   lpszName,GetSystemErrorDesc());
	}
	//NMS : Возвращаем результат
	return m_LastErrorCode = nResult;
}

//NMS : Создает CRYPT_DATA_BLOB из файла
int ICPCryptoImpl::CryptDataBlobFromFile(CString strFile,CRYPT_DATA_BLOB* pCertOrCRL, CBinData* pbnData /* = NULL */)
{	
#define CERT_IN_BASE64_BEGIN	_T("-----BEGIN CERTIFICATE-----")
#define CERT_IN_BASE64_END		_T("-----END CERTIFICATE-----")
#define CRL_IN_BASE64_BEGIN		_T("-----BEGIN X509 CRL-----")
#define CRL_IN_BASE64_END		_T("-----END X509 CRL-----")

// SMU: Add for work with pbnData
	if (pCertOrCRL != NULL)
		ZeroMemory(pCertOrCRL,sizeof(CRYPT_DATA_BLOB));

	CBinData bdData;
// SMU: Add for work with pbnData
	if (pbnData)
		bdData = *pbnData;
	else 
		if (!bdData.fRead(strFile))
		{
			WriteToLog(_T("Не удалось открыть файл \"%s\", причина : %s !"),strFile,GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenFileRead;
		}

	CString strCertInBase64;	
	
	if (bdData.Find(CERT_IN_BASE64_BEGIN)>=0)
		strCertInBase64=bdData.GetStrBetween(CERT_IN_BASE64_BEGIN,CERT_IN_BASE64_END);
	else
		if (bdData.Find(CRL_IN_BASE64_BEGIN)>=0)
			strCertInBase64=bdData.GetStrBetween(CRL_IN_BASE64_BEGIN,CRL_IN_BASE64_END);

	//NMS : В случае, если весь файл сертификата это base64, тогда он будет начинаться с символов "MII"
	if (strCertInBase64.IsEmpty() && bdData.Find(_T("MII"))==0) 
	{
		strCertInBase64=CString((CHAR*)bdData.Buf(),bdData.Size());
	}

	if (!strCertInBase64.IsEmpty())
	{
		CBinData bdCertInBase64;
		if (!CBase64Utils::DecodeFromB64(strCertInBase64,bdCertInBase64))
		{
			WriteToLog(_T("Файл \"%s\" имеет плохой формат !"),strFile);
			return m_LastErrorCode = CCPC_InvalidFileFormat;
		}
		bdData=bdCertInBase64;
	}

// SMU: Add for work with pbnData
	if (pbnData != NULL)
		*pbnData = bdData;

// SMU: Add for work with pbnData
	if (pCertOrCRL == NULL)
	return m_LastErrorCode = CCPC_NoError;
		
	pCertOrCRL->pbData=(BYTE*)malloc(bdData.Size());
	if (pCertOrCRL->pbData==NULL)
	{
		WriteToLog(_T("Не удалось выделить нужное количество памяти %d байт для файла \"%s\" !"),
				   bdData.Size(),strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	pCertOrCRL->cbData=bdData.Size();
	CopyMemory(pCertOrCRL->pbData,bdData.Buf(),bdData.Size());
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : Добавляет сертификат или CRL в файл
int ICPCryptoImpl::AddCertOrCRLToFile(CString strFile,
									  const CRYPT_DATA_BLOB* pCertOrCRL,
									  const int iType)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

	//WriteToLog(_T("Вызов ICPCryptoImpl::AddCertOrCRLToFile"));	
	
	//NMS : Проверим переданный тип
	if (iType!=CMSG_CTRL_ADD_CERT && iType!=CMSG_CTRL_ADD_CRL)
	{
		//NMS : Не поддерживаем !!!
		WriteToLog("Вызван ICPCryptoImpl::AddCertOrCRLToFile с параметром iType=%d, параметр не поддерживается !",iType);
		return m_LastErrorCode = CCPC_InternalError;
	}
	CFile file;
	if (!file.Open(strFile,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл \"%s\", причина : %s !"),strFile,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}
	//NMS : Узнаем длину файла и пытаемся выделить под эту длину память
	BYTE* bAppendData=NULL;
	DWORD dwAppendDataLen=file.GetLength();
	bAppendData = (BYTE*)malloc(dwAppendDataLen);
	if (!bAppendData)
	{
		WriteToLog(_T("Не удалось выделить нужное количество памяти %d байт для файла \"%s\" !"),
				   dwAppendDataLen,
				   strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Удалять будем автоматом чтобы не терять память
	CCertAutoBytePtr bAppendDataPtr(bAppendData);
	//NMS : Читаем данные из файла
	file.Read(bAppendData,dwAppendDataLen);
	file.Close();
	//NMS : Создаем хендл
	HCRYPTMSG hMsgAppend=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
												0,
												0,
												NULL,
												NULL,
												NULL);
	if (hMsgAppend==NULL)
	{
		WriteToLog(_T("Не удалось открыть криптосообщения для расшифровки, причина: %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgAppendClose(&hMsgAppend);
	//NMS : Пробудем добавить данные в сообщение			
	if (::CryptMsgUpdate(hMsgAppend,bAppendData,dwAppendDataLen,TRUE)==FALSE)
	{
		WriteToLog(_T("Не удалось добавить данные в криптосообщение, причина: %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantAddDataToMessage;
	}
	//NMS : Освободим данные
	bAppendDataPtr.Free();
	//NMS : После того как добавили данные в сообщение,
	//		добавлем pCertOrCRL			
	if (::CryptMsgControl(hMsgAppend,0,iType,pCertOrCRL)==FALSE)
	{
		WriteToLog(_T("Не удалось добавить кртиптоданные в сообщение, причина : %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantAddDataToMessage;
	}
	//NMS : Получаем длину сообщения			
	if (::CryptMsgGetParam(hMsgAppend,CMSG_ENCODED_MESSAGE,0,NULL,&dwAppendDataLen))
	{
		WriteToLog(_T("Не удалось определить размер сообщения, причина : %s !"),__LINE__,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantGetParamMessage;
	}
	//NMS : Пробудем выделить память по размеру сообщению			
	bAppendData=(BYTE*)malloc(dwAppendDataLen);
	if (bAppendData==NULL)
	{
		WriteToLog(_T("Не удалось выделить нужное количество памяти %d байт для файла \"%s\" !"),
				   dwAppendDataLen,
				   strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : Успешного выделения сделаем указатель автоматическим, автоматом удаляется
	bAppendDataPtr.Attach(bAppendData);
	//NMS : Получаем само сообщение			
	if (::CryptMsgGetParam(hMsgAppend,CMSG_ENCODED_MESSAGE,0,bAppendData,&dwAppendDataLen)==FALSE)
	{
		WriteToLog(_T("Не удалось прочитать данные из сообщения, причина : %s !"),__LINE__,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantGetParamMessage;
	}
	if (!file.Open(strFile,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("Не удалось открыть файл хранилища для добавления данных\"%s\", причина : %s !"),strFile,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileWrite;
	}	
	file.Write(bAppendData,dwAppendDataLen);
	file.Close();
	//NMS : Возвращаем успех !
	return m_LastErrorCode = CCPC_NoError;
}

/*static*/ CString ICPCryptoImpl::GetCertStoreNameByType(const DWORD dwType)
{
	CString strResult;
	switch(dwType)
	{
	case CST_SST:
//		{
//			strResult=_T("certstore.sst");
//			break;
//		}
	case CST_MY:
		{
			strResult=_T("Личные");
			break;
		}
	case CST_ROOT:
		{
			strResult=_T("Доверенные корневые центры сертификации");
			break;
		}
	default:
		{
			strResult.Format(_T("Неизвестный тип хранилища (%d)"),dwType);
			break;
		}
	}
	return strResult;
}

//NMS : Ищет сертификат в хранилище
int ICPCryptoImpl::CertFind(LPCERTFINDPARAM lpFindParam,
							PCCERT_CONTEXT* ppCertContext)
{
	ASSERT(lpFindParam!=NULL);
	ASSERT(lpFindParam->dwFindInStore>0);	
	ASSERT(ppCertContext!=NULL);

	//WriteToLog(_T("Вызов ICPCryptoImpl::CertFind"));

	//NMS : Проверки
	if (lpFindParam==NULL ||
		lpFindParam->dwFindInStore==0 ||		
		ppCertContext==NULL)
	{
		WriteToLog(_T("При вызове функции поиска сертификата один из параметров задан не верно !"));
		return m_LastErrorCode = CCPC_InternalError;
	}
	long nResult=CCPC_NoError;	
	//NMS : Перебор открытых хранилищ
	//		Причем перебор делаем хитро, а именно
	//		первым делом ищем в SST, если там не
	//		нашли тогда смотрим в MY, а если не нашли
	//		в MY смотрим в последнем хранилище ROOT
	CArray<DWORD,DWORD> arrType;
	arrType.SetSize(3);
	arrType[0]=CST_MY;
	arrType[1]=CST_SST;
	arrType[2]=CST_ROOT;
	//NMS : Очистим
	lpFindParam->ClearArrCerts();
	//NMS : Предыдущий результат поиска
	LONG nPrevResult=CCPC_NotInit;
	//NMS : Результат поиска сертификата
	PCCERT_CONTEXT pCertContext=NULL;
	//NMS : Цикл по типам
	const long nTypes=arrType.GetSize();
	for(long nType=0;nType<nTypes;nType++)
	{
		const DWORD dwType=arrType[nType];
		//NMS : Проверим, а нужно ли смотреть в
		//		этом хранилище сертификат
		if (!(lpFindParam->dwFindInStore&dwType))
		{
			continue;
		}
		//NMS : Пытаемся получить хэндл хранилища
		HCERTSTORE hStore=CertGetHandleStoreByType(dwType);
#ifdef CTHREAD_UPDATE_CRL
		if (hStore==NULL && m_pCPCryptoCallBack==NULL)
		{
			WriteToLog(_T("При поиске сертификата в хранилищах не удалось получить хэндл для хранилища \"%s\" !"),
					   GetCertStoreNameByType(dwType));
			//NMS : Продолжим поиск
			continue;
		}
#endif // CTHREAD_UPDATE_CRL
		//NMS : Ищем сертификат в хранилище
		nResult=CertFindEx(hStore,lpFindParam,&pCertContext);
		//NMS : Сертификат который был выпущен последним, причем если в первом хранилище его нашли
		//		в my, тогда больше его не переопределяем
		if ((*ppCertContext)==NULL && pCertContext!=NULL)
		{
			(*ppCertContext)=pCertContext;
		}
		//NMS : Если все хорошо, будем писать где был найден сертификат(ы)
		if (nResult==CCPC_NoError)
		{
			WriteToLog(_T("Сертификат(ы) был(и) найден(ы) в хранилище \"%s\"."),GetCertStoreNameByType(dwType));
			m_strLastError.Empty();
		}
		//NMS : Если стоит режим выбора из всех хранилищ, тогда цикл не прерываем
		if (lpFindParam->bSelFromAllStores!=FALSE &&
			(nResult==CCPC_NoError || nResult==CCPC_CertNotFind))//NMS : Только если все хорошо или сертификат не найден
		{
			//NMS : Если все хорошо, сохраним предыдущий результат
			if (nResult==CCPC_NoError)
			{
				//NMS : Сохраним предыдущий результат
				nPrevResult=nResult;
			}			
			//NMS : Перейдем к следующему хранилищу
			continue;
		}
		//NMS : Анализируем результат поиска в хранилище
		if (nResult==CCPC_CertNotFind)
		{
			//NMS : Не нашли сертификат в данном хранилище, ищем дальше
			continue;
		}
		else
		{
			//NMS : Нашли нужный нужный сертификат или произошла ошибка, выходим из цикла поиска
			break;
		}
	}
	//NMS : Если в последнем хранилище, не нашли, тогда будем
	//		использовать предыдущий результат, если он есть
	if (nResult==CCPC_CertNotFind && nPrevResult!=CCPC_NotInit)
	{
		nResult=nPrevResult;
	}
	//NMS : Возвращаем результат поиска сертификата
	return m_LastErrorCode = nResult;
}

//NMS : Позволяет по коду статуса получить строку описания.
CString GetTrustStatusAsStr(const DWORD dwStatus)
{
	CString strResult;
	switch(dwStatus)
	{
	case CERT_TRUST_NO_ERROR :
		 strResult=_T("No error found for this certificate or chain.");
		 break;
	case CERT_TRUST_IS_NOT_TIME_VALID: 
		 strResult=_T("This certificate or one of the certificates in the certificate chain is not time-valid.");
		 break;
	case CERT_TRUST_IS_NOT_TIME_NESTED: 
		 strResult=_T("Certificates in the chain are not properly time-nested.");
		 break;
	case CERT_TRUST_IS_REVOKED:
		 strResult=_T("Trust for this certificate or one of the certificates in the certificate chain has been revoked.");
		 break;
	case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
		 strResult=_T("The certificate or one of the certificates in the certificate chain does not have a valid signature.");
		 break;
	case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
		 strResult=_T("The certificate or certificate chain is not valid in its proposed usage.");
		 break;
	case CERT_TRUST_IS_UNTRUSTED_ROOT:
		 strResult=_T("The certificate or certificate chain is based on an untrusted root.");
		 break;
	case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
		 strResult=_T("The revocation status of the certificate or one of the certificates in the certificate chain is unknown.");
		 break;
	case CERT_TRUST_IS_CYCLIC :
		 strResult=_T("One of the certificates in the chain was issued by a certification authority that the original certificate had certified.");
		 break;
	case CERT_TRUST_IS_PARTIAL_CHAIN: 
		 strResult=_T("The certificate chain is not complete.");
		 break;
	case CERT_TRUST_CTL_IS_NOT_TIME_VALID: 
		 strResult=_T("A CTL used to create this chain was not time-valid.");
		 break;
	case CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID: 
		 strResult=_T("A CTL used to create this chain did not have a valid signature.");
		 break;
	case CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE: 
		 strResult=_T("A CTL used to create this chain is not valid for this usage.");
	default:
		strResult=_T("The unknown status code !");

	} // End switch
	return strResult;
}

//NMS : Позволяет получить имя сертификата
CString ICPCryptoImpl::CertGetName(PCCERT_CONTEXT pCertContext,const BOOL bIssuer/*=FALSE*/)
{
	CString strResult;
	TCHAR szBuff[1024]={0};
	::CertGetNameString(pCertContext,CERT_NAME_DNS_TYPE,bIssuer==FALSE ? 0:CERT_NAME_ISSUER_FLAG,NULL,
						&szBuff[0],(sizeof(szBuff)/sizeof(szBuff[0]))-1);
	strResult=&szBuff[0];
	return strResult;
}

int ReverseFind(LPCTSTR Str, LPCTSTR SubStr)
{
	LPTSTR lpsz = StrRStrI(Str,NULL, SubStr);
	return (lpsz == NULL) ? -1 : (int)(lpsz - Str);
}

CString ICPCryptoImpl::CertGetName(PCCRL_CONTEXT  pCrlContext)
{

	CString strResult = CertNameBlob2Str(&pCrlContext->pCrlInfo->Issuer);
	// ещем CN
	int p1 = ReverseFind(strResult,"CN=");
	if (p1<0) return "";
	p1+=3;
	TCHAR chEnd = ',';
	if (strResult[p1] == '\"')
	{
		p1++;
		chEnd = '\"';
	}
	int p2 = strResult.Find(chEnd,p1);
	if (p2<0) return strResult.Mid(p1);
	return strResult.Mid(p1,p2-p1); 
}

//NMS : Проверяет цепочку сертификата
int ICPCryptoImpl::CertCheckChain(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pCertValidParam)
{
	CString strErrMsg;	
	LONG nResult=CCPC_NoError;
	HCERTCHAINENGINE hChainEngine=NULL;
	CERT_CHAIN_ENGINE_CONFIG ChainConfig;
	PCCERT_CHAIN_CONTEXT pChainContext=NULL;
	try
	{
		//NMS : Инициализируем движок цепочек сертификатов
		ChainConfig.cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG);
		ChainConfig.hRestrictedRoot= NULL ;
		ChainConfig.hRestrictedTrust= NULL ;
		ChainConfig.hRestrictedOther= NULL ;
		ChainConfig.cAdditionalStore=0 ;
		ChainConfig.rghAdditionalStore = NULL ;
		ChainConfig.dwFlags = CERT_CHAIN_CACHE_END_CERT;
		ChainConfig.dwUrlRetrievalTimeout= 0 ;
		ChainConfig.MaximumCachedCertificates=0 ;
		ChainConfig.CycleDetectionModulus = 0;
		if(!::CertCreateCertificateChainEngine(&ChainConfig,&hChainEngine))
		{
			nResult=CCPC_CantGetTrustChain;
			throw CStringProc::Format(_T("Не удалось проинициализировать движок цепочек сертификатов, причина : %s !"),
									  CStringProc::GetSystemError());
		}
		//NMS : Готовим данные для получения цепочки
		CERT_ENHKEY_USAGE EnhkeyUsage;
		CERT_USAGE_MATCH CertUsage;
		CERT_CHAIN_PARA ChainPara;		
		EnhkeyUsage.cUsageIdentifier=0;
		EnhkeyUsage.rgpszUsageIdentifier=NULL;
		CertUsage.dwType=USAGE_MATCH_TYPE_AND;
		CertUsage.Usage=EnhkeyUsage;
		ChainPara.cbSize=sizeof(CERT_CHAIN_PARA);
		ChainPara.RequestedUsage=CertUsage;
		//NMS : Флаги опций
		DWORD dwFlags=0x00;
		HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
		if (NULL==hSST)
		{
			const DWORD dwSSTOpen=CST_SST;
			nResult=CertOpenStore(dwSSTOpen);
			if (nResult!=CCPC_NoError)
			{
				return m_LastErrorCode = nResult;
			}
			hSST=CertGetHandleStoreByType(CST_SST);
		}
		//NMS : Строим цепочку		
		if(!::CertGetCertificateChain(NULL,pCertContext,NULL,hSST,&ChainPara,dwFlags,NULL,&pChainContext))
		{
			nResult=CCPC_CantGetTrustChain;
			pCertValidParam->nResultCode = nResult;
			throw CStringProc::Format(_T("Не удалось построить цепочку для сертификата \"%s\", причина : %s !"),
									  CertGetName(pCertContext),CStringProc::GetSystemError());
		}
		switch(pChainContext->TrustStatus.dwErrorStatus)
		{
		case CERT_TRUST_NO_ERROR:
			{
				break;
			}
		default:
			{
				//NMS : В цепочке есть ошибки, скажем о них
				nResult=CCPC_CantGetTrustChain;
				pCertValidParam->nResultCode = nResult;
				throw CStringProc::Format(_T("При проверке цепочки сертификата \"%s\" были выявлены следующие ошибки \"%s\" ! "),
										  CertGetName(pCertContext),GetTrustStatusAsStr(pChainContext->TrustStatus.dwErrorStatus));
			}
		}
		//NMS : Пока работаем с одной цепочкой, так как больше нужно тестировать,
		//		а данных для тестирования нет !
		ASSERT(pChainContext->cChain==1);
		WriteToLog(_T("Всего нашли %d цепочку для сертификата \"%s\" !"),
				   pChainContext->cChain,CertGetName(pCertContext));
		const LONG nChains=min(1,pChainContext->cChain);
		PCCERT_CONTEXT pIssuerCertContext=NULL;
		//NMS : Бежим по цепочкам и строим для каждой цепочки карту в
		//		которой ключем является сертификат, а значением его поставщик
		for(LONG nChain=0;nChain<nChains;nChain++)
		{
			typedef class std::map<PCCERT_CONTEXT,PCCERT_CONTEXT> MAPCERTANDCERTISSUER;
			MAPCERTANDCERTISSUER mapCertAndCertIssuer;
			BOOL bSetCertIssuer=FALSE;
			PCCERT_CONTEXT pCertContextKey=NULL;
			for(int nElement=0;nElement<pChainContext->rgpChain[nChain]->cElement;nElement++)
			{
				PCCERT_CONTEXT pCertInChain=pChainContext->rgpChain[nChain]->rgpElement[nElement]->pCertContext;
				WriteToLog(_T("Сертификат \"%s\"(%d) поставщик \"%s\", в цепочке %d !"),
						   CertGetName(pCertInChain),nElement,CertGetName(pCertInChain,TRUE),nChain+1);
				//NMS : Формируем карту				
				if (bSetCertIssuer!=FALSE)
				{
					mapCertAndCertIssuer.insert(MAPCERTANDCERTISSUER::value_type(pCertContextKey,pCertInChain));
					bSetCertIssuer=FALSE;
				}
				else
				{
					pCertContextKey=pCertInChain;
					bSetCertIssuer=TRUE;
				}
			}			
			//NMS : Проверяем CRL
			for(MAPCERTANDCERTISSUER::iterator iter=mapCertAndCertIssuer.begin();
				iter!=mapCertAndCertIssuer.end();
				iter++)
			{
				PCCERT_CONTEXT pCert=iter->first;
				PCCERT_CONTEXT pCertIssuer=iter->second;
				ASSERT(pCert!=NULL && pCertIssuer!=NULL);
				HCERTSTORE hCertStore=pCert->hCertStore;				
				//NMS : Проверим CRL для текущего хранилища, но только в режиме ReadOnly
				if (CertCheckCRL(hCertStore,pCertIssuer,pCert,pCertValidParam,TRUE))
				{					
					//NMS : Далее, если успешно, проверяем CRL в SST
					if (!CertCheckCRL(hSST,pCertIssuer,pCert,pCertValidParam,FALSE))
					{
						nResult=pCertValidParam->nResultCode;
						break;//NMS : Описание ошибки уже есть в pCertValidParam
					}				
				}
				else
				{	// Сертификат отозван
					if (pCertValidParam->nResultCode==CCPC_CertNotValid)
					{
						nResult=pCertValidParam->nResultCode;
						break;//NMS : Описание ошибки уже есть в pCertValidParam
					}
				}
			}
		}
	}
	catch(CString strErr)
	{
		strErrMsg=strErr;
	}
	catch(...)
	{
		strErrMsg=_T("CertCheckChain => Неизвестная ошибка !");
		nResult=CCPC_InternalError;
		pCertValidParam->nResultCode = nResult;
	}
	//NMS : Если текст ошибки не пустой, тогда запишем
	try
	{
		if (!strErrMsg.IsEmpty())
		{
			WriteToLog(strErrMsg);		
		}
		//NMS : Освободим цепочку
		if (pChainContext!=NULL)
		{
			::CertFreeCertificateChain(pChainContext); 
			pChainContext=NULL;
		}
		//NMS : Освободим движок цепочек сертификатов
		if (hChainEngine!=NULL)
		{
			::CertFreeCertificateChainEngine(hChainEngine);
			hChainEngine=NULL;
		}
	}
	catch (...)
	{
		strErrMsg=_T("CertCheckChain => Неизвестная ошибка !");
		nResult=CCPC_InternalError;
		pCertValidParam->nResultCode = nResult;
	}
	return m_LastErrorCode = nResult;
}

//NMS : Ищет сертификат с заданными параметрами и в заданом хранилище (только в нем)
int ICPCryptoImpl::CertFindEx(HCERTSTORE hStore,
							  LPCERTFINDPARAM lpFindParam,
							  PCCERT_CONTEXT* ppCertContext)
{
	ASSERT(lpFindParam!=NULL);	
	ASSERT(ppCertContext!=NULL);

	//WriteToLog(_T("Вызов ICPCryptoImpl::CertFindEx"));

	//NMS : Проверки
	if (lpFindParam==NULL ||		
		ppCertContext==NULL)
	{
		WriteToLog(_T("При вызове функции поиска сертификата один из параметров задан не верно !"));
		return m_LastErrorCode = CCPC_InternalError;
	}	
	//NMS : Перебираем сертификаты в хранилище и строим список подходящих
	PCCERT_CONTEXT pCertContext=lpFindParam->pCertPrev;
	//NMS : Список с подходящими сертификатами
	CList<PCCERT_CONTEXT,PCCERT_CONTEXT> lstCertContext;
	
	BOOL bResolved = FALSE;

// KAA : ищем во внешнем хранилище, если FALSE - стандарная схема
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
// KAA : Сюда заходим если hStore == CertGetHandleStoreByType(CST_SST)
		if ((hStore == CertGetHandleStoreByType(CST_SST)) || (hStore == NULL))
		for (;;)
		{
			bResolved = m_pCPCryptoCallBack->OnCertFindEx(lpFindParam, pCertContext);

			if ((pCertContext == NULL) || (!bResolved))
			{
				break;
			}

			//NMS : Проверим, алгоритм, если не нашли пропустим
			CString sKeyAlgID=pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
			if (sKeyAlgID.Find("1.2.643.2.2.")!=0)
			{
				WriteToLog(_T("Сертификат не прошел проверку по KeyAlgID, текущий KeyAlgID равен \"%s\" !"),sKeyAlgID);
				continue;
			}
			//NMS : Проверим OID, если он не пустой
			if (!lpFindParam->strOID.IsEmpty())
			{
				if (!CertCheckOID(pCertContext,lpFindParam->strOID))
				{
					//NMS : Не прошли проверку на OID, сообщение в логе уже есть
					continue;
				}
			}
			//NMS : Проверим сертификат на валидность, а так же 
			//		проверим цепочку сертификата		
			CERTVALIDPARAM ValidParam;
			if (lpFindParam->bSkipCertIsValid==FALSE &&
				(!CertIsValid(pCertContext,&ValidParam)))
			{
				//NMS : Не валидный сертификат - выходим
				continue;
			}
			
			PCCERT_CONTEXT pCertContextDup=::CertDuplicateCertificateContext(pCertContext);
			ASSERT(pCertContextDup!=NULL);
			lstCertContext.AddTail(pCertContextDup);
		}
	
	}
#endif // CTHREAD_UPDATE_CRL

	if (lstCertContext.GetCount() == 0 && hStore!=NULL)
	{
		//NMS : Данные атрибуты необходимы если искать нужно по полю email
		CERT_RDN rdn;
		CERT_RDN_ATTR aRdnAttrs[1];
		ZeroMemory(&rdn,sizeof(CERT_RDN));
		ZeroMemory(&aRdnAttrs,sizeof(aRdnAttrs));
		//NMS : Создадим локальный отпечаток сертификата
		CRYPT_DATA_BLOB cdbThumb;
		cdbThumb.cbData=lpFindParam->cdbThumb.cbData;
		cdbThumb.pbData=lpFindParam->cdbThumb.pbData;	
		//NMS : Если нужно искать по email, тогда заполняем атрибуты
		DWORD dwFindType=0x00;
		void* pFindParam=NULL;
		//NMS : Если в CN попадается @ значит искать нужно
		//		по полю E в свойстве сертификата Subject
		const bool bFindByEmail=(lpFindParam->strCN.Find(_T("@"))>0) ? true:false;
		bool bFindByThumb=false;
		CCertAutoBytePtr AutoClearThumb(NULL);
		if (bFindByEmail)
		{
			//NMS : Будем производить поиск по полю E
			aRdnAttrs[0].pszObjId=szOID_RSA_emailAddr;
			aRdnAttrs[0].dwValueType=CERT_RDN_IA5_STRING;
			aRdnAttrs[0].Value.pbData=(BYTE*)(LPCTSTR)lpFindParam->strCN;
			aRdnAttrs[0].Value.cbData=lpFindParam->strCN.GetLength();
			rdn.cRDNAttr=sizeof(aRdnAttrs)/sizeof(aRdnAttrs[0]);
			rdn.rgRDNAttr=&aRdnAttrs[0];
			//NMS : Установим данные поиска
			dwFindType=CERT_FIND_SUBJECT_ATTR;
			pFindParam=&rdn;
		}
		else
		{
			//NMS : Если указан отпечатк сертификата,
			//		тогда ищем по нему
			if (cdbThumb.pbData!=NULL && cdbThumb.cbData>0)
			{
				bFindByThumb=true;
			}
			else
			{
				//NMS : Пытаемся получить из строки отпечаток сертификата
				if (ICPCryptoImpl::GetThumbFromStr(lpFindParam->strCN,&cdbThumb))
				{
					//NMS : Сделаем указатель автоматическим, так как память
					//		для него выделяется динамически через new.
					AutoClearThumb.Attach(cdbThumb.pbData,false);
					bFindByThumb=true;
				}
			}
			if (bFindByThumb)
			{
				//NMS : Будем производить поиск по отпечатку сертификата
				dwFindType=CERT_FIND_SHA1_HASH;
				pFindParam=(void*)&cdbThumb;
				//#ifdef _DEBUG
				//NMS : В Debug версии будем выводить отпечаток в виде строки
				CBinData bdThumb(cdbThumb.pbData,cdbThumb.cbData);
				CString strThumbInHex;
				bdThumb.Encode2Hex(strThumbInHex);
				strThumbInHex.MakeUpper();
				//NMS : Если отпечаток равен 40 символам,
				//		поставим пробелы через каждые 4 символа
				const long nThumbLen=strThumbInHex.GetLength();
				if (nThumbLen==40)
				{
					for(long nSpace=1;nSpace<=9;nSpace++)
					{
						strThumbInHex.Insert(nThumbLen-(nSpace*4),_T(' '));
					}
				}
				//NMS : Пишем в лог
				WriteToLog(_T("Поиск сертификата будет производиться по отпечатку : \"%s\"."),strThumbInHex);
				//#endif
			}
			else
			{
				//NMS : Будем производить поиск по полю CN
				dwFindType=CERT_FIND_SUBJECT_STR_A;
				pFindParam=(void*)(LPCSTR)lpFindParam->strCN;
			}
		}
		//NMS : Цикл поиска сертификатов		
		for(;;)
		{		
			pCertContext=::CertFindCertificateInStore(hStore,
				PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
				0x00,
				dwFindType,
				pFindParam, 
				pCertContext);
			//NMS : Если NULL это значит, что в хранилище нет сертификатов
			if (pCertContext==NULL)
			{
				break;
			}
			//NMS : В дебаге будем писать, какой сертификат нашли
#ifdef _DEBUG
			WriteToLog(_T("Найден сертификат : \"%s\"."),
				CertGetName(pCertContext));
#endif //_DEBUG	
			if (dwFindType==CERT_FIND_SUBJECT_STR_A)
			{//NMS : Жесткая проверка на CN, для этого типа поиска
				//NMS : Получаем CN
				CString strCN;
				const LONG nCNLen=1024;
				TCHAR szCN[nCNLen]={0};
				CertGetNameString(pCertContext,CERT_NAME_ATTR_TYPE,0x00,
					szOID_COMMON_NAME,&szCN[0],nCNLen-1);
				strCN=&szCN[0];
				if (strCN.CompareNoCase(lpFindParam->strCN)!=0)
				{
#ifdef _DEBUG
					WriteToLog(_T("Cертификат не прошел проверку на CN, должен быть \"%s\", а в сертификате указан \"%s\" !"),
						lpFindParam->strCN,strCN);
					
#endif //_DEBUG
					continue;
				}
			}
			//NMS : Проверим, алгоритм, если нашли пропустим
			CString sKeyAlgID=pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
			if (sKeyAlgID.Find("1.2.643.2.2.")!=0)
			{
				WriteToLog(_T("Сертификат не прошел проверку по KeyAlgID, текущий KeyAlgID равен \"%s\" !"),sKeyAlgID);
				continue;
			}
			//NMS : Проверка корневого CN, если он задан
			if (!m_strRootCN.IsEmpty())
			{
				CString strIssuer=CertNameBlob2Str(&pCertContext->pCertInfo->Issuer);
				CString strRootCN(m_strRootCN);
				strIssuer.MakeLower();
				strRootCN.MakeLower();
				if (strIssuer.Find(strRootCN)<0)
				{
					WriteToLog(_T("Сертификат не прошел проверку по Root CN !"));
					continue;
				}
			}
			//NMS : Проверим отпечаток сертификата, если его нужно проверять
			if (bFindByThumb==false && //NMS : Только если перебераем сертефикаты не по отпечатку !
				lpFindParam->cdbThumb.cbData>0 &&
				lpFindParam->cdbThumb.pbData!=NULL)
			{
				CRYPT_DATA_BLOB bThumbCert;
				ZeroMemory(&bThumbCert,sizeof(CRYPT_DATA_BLOB));			
				//NMS : Пробуем получить отпечаток			
				if (CertGetThumb(pCertContext,&bThumbCert)==false)
				{
					//NMS : Увы, не удалось получить отпечаток сертификата, пропустим его
					continue;
				}
				//NMS : Выделяется динамически поэтому необходимо удалять
				CCertAutoBytePtr pbDataPtr(bThumbCert.pbData,false);
				//NMS : Сравниваем отпечатки
				if (memcmp(lpFindParam->cdbThumb.pbData,
					bThumbCert.pbData,
					min(lpFindParam->cdbThumb.cbData,bThumbCert.cbData))!=0)
				{
					//NMS : Отпечатки не совпали, пропустим
#ifdef _DEBUG
					WriteToLog(_T("Сертификат будет пропущен, так как отпечатки не совпали !"));
#endif //_DEBUG
					continue;
				}			
			}
			//NMS : Проверим OID, если он не пустой
			if (!lpFindParam->strOID.IsEmpty())
			{
				if (!CertCheckOID(pCertContext,lpFindParam->strOID))
				{
					//NMS : Не прошли проверку на OID, сообщение в логе уже есть
					continue;
				}
			}
			//NMS : Проверим сертификат на валидность, а так же 
			//		проверим цепочку сертификата		
			CERTVALIDPARAM ValidParam;
			if (lpFindParam->bSkipCertIsValid==FALSE &&
				(!CertIsValid(pCertContext,&ValidParam)))
			{
				//NMS : Не валидный сертификат пропустим
				continue;
			}
			//NMS : Добавляем в список подходящих сертификатов
			PCCERT_CONTEXT pCertContextDup=::CertDuplicateCertificateContext(pCertContext);
			ASSERT(pCertContextDup!=NULL);
			lstCertContext.AddTail(pCertContextDup);
		} // for
	} // конец поиска, обрабатываем результат в lstCertContext
	
	
	//NMS : Теперь подведем результат
	long nResult=CCPC_NoError;
	//NMS : Нашли нужный сертификат
	if (lstCertContext.GetCount()==1)
	{
		if (ppCertContext!=NULL)
		{
			//NMS : Получем найденный сертификат из списка
			(*ppCertContext)=lstCertContext.GetHead();
		}
	}
	else if (lstCertContext.GetCount()>1)
	{		
		//NMS : Ищем сертификат последний по дате выпуска
		const LONG nCerts=lstCertContext.GetCount();
		pCertContext=NULL;
		PCCERT_CONTEXT pCertContextSel=NULL;
		POSITION pos=lstCertContext.GetHeadPosition();
		while(pos!=NULL)
		{
			if (pCertContextSel==NULL)
			{
				pCertContextSel=lstCertContext.GetNext(pos);
				continue;
			}
			else
			{
				pCertContext=lstCertContext.GetNext(pos);
			}
			CTime timeLeft(pCertContextSel->pCertInfo->NotBefore);
			CTime timeRight(pCertContext->pCertInfo->NotBefore);
			if (timeRight>timeLeft)
			{
				pCertContextSel=pCertContext;
			}
		}
		/*
		//NMS : Если было найдено больше одного сертификата, пишем об этом в лог
		const long nCertFind=lstCertContext.GetCount();
		if (nCertFind>1)
		{
			//NMS : Пишем в лог
			WriteToLog(_T("При поиске сертификата по \"%s\" было найдено %d валидных сертификата(ов), нет возможности автоматически определить нужный сертификат !"),
					   (LPCTSTR)lpFindParam->strCN,nCertFind);
		}
		*/
		//NMS : Освободить память занимаемую его элементами.
		//		Если множественный выбор, тогда ни чего не чистим
		if (lpFindParam->bSelAllCert==FALSE)
		{		
			pCertContext=NULL;
			pos=lstCertContext.GetHeadPosition();
			while(pos!=NULL)
			{
				pCertContext=lstCertContext.GetNext(pos);
				if (pCertContextSel==pCertContext)
				{
					//NMS : Выбраный элемент удалять не будем !
					continue;
				}
				::CertFreeCertificateContext(pCertContext);
			}
		}
#ifdef _DEBUG
		WriteToLog(_T("Из множества сертификатов выбран : \"%s\"."),CertGetName(pCertContextSel));		
#endif //_DEBUG
		//NMS : Присвоим
		if (ppCertContext!=NULL)
		{
			//NMS : Получем найденный сертификат из списка
			(*ppCertContext)=pCertContextSel;
		}
		//NMS : Будем писать в лог, о том, какой сертификат был выбран
		if (pCertContextSel!=NULL && lpFindParam->bSelAllCert==FALSE)
		{			
			COleDateTime CertTimeAfter(pCertContextSel->pCertInfo->NotBefore);
			WriteToLog(_T("Из %d сертификатов, был выбран сертификат старший по дате выпуска, который действителен с %s."),
					   nCerts,
					   CertTimeAfter.Format(_T("%d-%m-%Y %H:%M:%S")));
			m_strLastError.Empty();
		}
		//NMS : Установим результат работы функции
		nResult=CCPC_NoError;
	}
	else
	{
		//NMS : Установим результат работы функции
		nResult=CCPC_CertNotFind;		
	}
	//NMS : Если включен множественный выбор сертификатов,
	//		то прежде чем чистить список сертификатов необходимо
	//		собрать их в результирующий массив, если результат 
	//		возврата функции CCPC_NoError
	if (nResult==CCPC_NoError && lpFindParam->bSelAllCert!=FALSE)
	{		
		//NMS : Соберем в массив
		pCertContext=NULL;
		POSITION pos=lstCertContext.GetHeadPosition();
		while(pos!=NULL)
		{
			pCertContext=lstCertContext.GetNext(pos);
			lpFindParam->arrCerts.Add(pCertContext);
		}
		//NMS : Будем писать в лог, сколько найдено сертификатов
		WriteToLog(_T("При множественном выборе сертификатов, было выбрано сертификатов: %d"),lpFindParam->arrCerts.GetSize());
		m_strLastError.Empty();
	}
	//NMS : Почистим список
	lstCertContext.RemoveAll();
	//NMS : Возвращаем успех !
	return m_LastErrorCode = nResult;
}

//NMS : Позволяет получить отпечаток сертификата
bool ICPCryptoImpl::CertGetThumb(PCCERT_CONTEXT pCertContext,CRYPT_DATA_BLOB* pThumb)
{
	ASSERT(pCertContext!=NULL);
	ASSERT(pThumb!=NULL);
	bool bResult=false;
	if (pCertContext!=NULL &&
		pThumb!=NULL)
	{
		//NMS : Почистим
		ZeroMemory(pThumb,sizeof(CRYPT_DATA_BLOB));
		//NMS : Получаем длину отпечатка
		if (CertGetCertificateContextProperty(pCertContext,
											  CERT_SHA1_HASH_PROP_ID,
											  NULL,
											  &pThumb->cbData))
		{
			//NMS : Получили длину отпечатка, выделим память под него и считаем сам отпечаток
			pThumb->pbData=new BYTE[pThumb->cbData];
			ASSERT(pThumb->pbData!=NULL);
			bResult=true;
			if (!CertGetCertificateContextProperty(pCertContext,
												   CERT_SHA1_HASH_PROP_ID,
												   pThumb->pbData,
												   &pThumb->cbData))
			{
				WriteToLog(_T("ICPCryptoImpl::CertGetThumb => Не удалось прочитать отпечаток у сертификата !"));
				delete[] pThumb->pbData;
				pThumb->pbData=NULL;
				pThumb->cbData=0x00;
				bResult=false;
			}
		}
		else
		{
			WriteToLog(_T("ICPCryptoImpl::CertGetThumb => Не удалось прочитать длину отпечатка сертификата !"));
		}
	}
	else
	{
		WriteToLog(_T("ICPCryptoImpl::CertGetThumb => Переданы ошибочные параметры !"));
	}
	return bResult;
}

//NMS : Проверяет сертификат, а так же его цепочку сертификатов на валидность
bool ICPCryptoImpl::CertIsValid(PCCERT_CONTEXT pCertContext,
								PCERTVALIDPARAM pValidParam)
{
	ASSERT(pCertContext!=NULL);
	ASSERT(pValidParam!=NULL);
	//NMS : Проверку будем осущевствлять в 1 проход, но
	//		если CLR истек, тогда обновляем CLR для SST
	//		и производим проверку еще раз.
	bool bResult=FALSE;
	//NMS : Осущевствляем проверку сертификата и его цепочки для данного хранилища
	
	int nResult = CCPC_NoError;

	bResult=CertIsValidEx(pCertContext,pValidParam);
	nResult = pValidParam->nResultCode;

	//NMS : Если проверка завершилась успехом, тогда выходим из цикла
	if (bResult && (pValidParam->nResultCode==CCPC_NoError)) // все хорошо - выходим сразу
	{
		return true;
	}
	//NMS : Проверка провалилась,  потому что истек CLR,
	//		нужно обновить CLR и повторить попытку.
	if (pValidParam->bExpiredCRL==TRUE || 
		pValidParam->nResultCode==CCPC_CrlNotValid ||
		pValidParam->nResultCode==CCPC_CantVerifyCRL)
	{
#ifdef CTHREAD_UPDATE_CRL
		//NMS : Обновляем CRL'ли для хранилища сертификата, но кладем его в SST
		nResult = CertUpdateCRLs(pCertContext);
		pValidParam->nResultCode = nResult;
#else
		nResult = CCPC_NoError;
#endif //
	}

	if (nResult==CCPC_NoError)
	{
	//NMS : Проводим проверку еще раз
		bResult=CertIsValidEx(pCertContext,pValidParam);
		nResult = pValidParam->nResultCode;
	}

	if (pValidParam->nResultCode==CCPC_CrlNotValid ||
		pValidParam->nResultCode==CCPC_CantVerifyCRL||
		pValidParam->nResultCode==CCPC_CantUpdateCrl)
	{
		WriteToLog("Не удалось обновить CRL для сертификата %s, но принудительно продолжим",
			CertGetName(pCertContext));
		bResult = CertVerifyDateValid(pCertContext);
	}
	pValidParam->nResultCode = nResult;
	return bResult;
}

//NMS : Проверяет сертификат по CRL
bool ICPCryptoImpl::CertCheckCRL(HCERTSTORE hStore,
								 PCCERT_CONTEXT pIssuerCertContext,
								 PCCERT_CONTEXT pCertContext,
								 PCERTVALIDPARAM pValidParam,
								 const BOOL bReadOnly/*=TRUE*/)
{
//	ASSERT(hStore!=NULL);
	ASSERT(pIssuerCertContext!=NULL);
	ASSERT(pCertContext!=NULL);
	ASSERT(pValidParam!=NULL);
	if (m_Settings.bSkipCheckCRL!=FALSE)
	{
		WriteToLog(_T("Проверка CRL для сертификатов отключена настройками !"));
		return true;
	}
	
	pValidParam->nResultCode = CCPC_CantVerifyCRL;

	bool bResult=true;
	//NMS : Флаг о том, что у сертификата есть валидные CLR
	bool bHasValidCRL=false;
	//NMS : Флаг о том, что у сертификата есть CLR
	bool bHasCRL=false;
	//NMS : Счетчик кол-ва CRL
	LONG nCRLCount=0;
	//NMS : Указатель на следующий CLR
	PCCRL_CONTEXT pCRL=NULL;
	//NMS : Бежим по цепочке CLR'ов.

#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack && bReadOnly==FALSE)
	do
	{			
		// KAA : перебираем CRL во внешнем хранилище, если FALSE - перебираем в SST
		m_pCPCryptoCallBack->OnCertGetCRL(pIssuerCertContext,pCRL,bReadOnly);
		
		if (pCRL==NULL)
		{
			//NMS : Если нет ни одного CRL
			if (nCRLCount==0)
			{	
				bHasCRL=false;
				bHasValidCRL=false;
			}
			//NMS : У сертификата нет CLR
			
			break;
		}
		if (!bResult)
			continue;

		bHasCRL=true;// есть CRL !!!
		++nCRLCount;
		
		// KAA : Проверим валидность CRL по дате
		COleDateTime dtUpdate = pCRL->pCrlInfo->ThisUpdate;
		COleDateTime dtNextUpdate = pCRL->pCrlInfo->NextUpdate;
		if (!((dtNextUpdate>COleDateTime::GetCurrentTime()) && 
			(dtUpdate<COleDateTime::GetCurrentTime())))
		{
			WriteToLog(_T("CRL \"%s\" для БД не действительна, нужно обновление!"),
				CertGetName(pCRL));
			bHasValidCRL = false;
		}
		else
		{
			WriteToLog(_T("CRL \"%s\" для БД действительна"),
				CertGetName(pCRL));
			//NMS : Пробуем найти сертификат в CLR
			PCRL_ENTRY pEntry=NULL;
			::CertFindCertificateInCRL(pCertContext,pCRL,0,NULL,&pEntry);
			if (pEntry!=NULL)
			{
				//NMS : Сертификат отозван (найден в CLR)
				bResult=false;
				pValidParam->nResultCode=CCPC_CertNotValid;
				WriteToLog(_T("Cертификат \"%s\" отозван (найден в CLR) !"),
					CertGetName(pCertContext));
				continue;
			}else
				bHasValidCRL = true;
		}
	} while (pCRL!=NULL);
#endif // CTHREAD_UPDATE_CRL
	
	int nCRLCountSST = 0;
	if ((NULL!=hStore) && (bResult) && (!bHasCRL))
	do
	{
		DWORD dwCLRFlags=CERT_STORE_SIGNATURE_FLAG;
// KAA : перебираем CRL в SST
		
		pCRL=::CertGetCRLFromStore(hStore,pIssuerCertContext,pCRL,&dwCLRFlags);

		if (pCRL==NULL)
		{
			//NMS : Если нет ни одного CRL
			if (nCRLCountSST==0)
			{	
				bHasCRL=false;
				bHasValidCRL=false;
			}
			//NMS : У сертификата нет CLR

			break;
		}
		if (!bResult)
			continue;

		bHasCRL=true;// есть CRL !!!
		++nCRLCountSST;
		
		// KAA : Проверим валидность CRL по дате
		if (0!=CertVerifyCRLTimeValidity(NULL, pCRL->pCrlInfo))
		{
			WriteToLog(_T("CRL \"%s\" для хранилища %p не действительна, нужно обновление!"),
					   CertGetName(pCRL),hStore);
			bHasValidCRL = false;
		}
		else
		{
			WriteToLog(_T("CRL \"%s\" для хранилища %p действительна"),
					   CertGetName(pCRL),hStore);

			bHasValidCRL=true; // есть действительный

			//NMS : Пробуем найти сертификат в CLR
			PCRL_ENTRY pEntry=NULL;
			::CertFindCertificateInCRL(pCertContext,pCRL,0,NULL,&pEntry);
			if (pEntry!=NULL)
			{
				//NMS : Сертификат отозван (найден в CLR)
				bResult=false;
				pValidParam->nResultCode=CCPC_CertNotValid;
				WriteToLog(_T("Cертификат \"%s\" отозван (найден в CLR) !"),
					CertGetName(pCertContext));
				continue;
			}
		}
	}
	while (pCRL!=NULL);

	if (!bResult && pValidParam->nResultCode == CCPC_CertNotValid)
		return bResult;
	
	//NMS : Нет CRL или  нет валидного, нужно обновлять CRL, но делаем это
	//		только если мы не находимся в режиме только для чтения.	
	if ((bReadOnly==FALSE) && (!bHasCRL || (bHasCRL  && !bHasValidCRL)))
	{
		//NMS : Список CLR'ов есть,а валидного ни одного не нашли
		bResult=false;
		pValidParam->nResultCode=CCPC_CrlNotValid;
		pValidParam->bExpiredCRL=TRUE;
		if (!bHasCRL)
			WriteToLog(_T("Не найден CRL для издателя %s !"),
				CertGetName(pIssuerCertContext));		
	}
	else
	{
		if (bResult)
			pValidParam->nResultCode=CCPC_NoError;
		else
			pValidParam->nResultCode = CCPC_CantVerifyCRL;

	}
	return bResult;
}

//NMS : Проверяет сертификат, а так же его цепочку сертификатов
//		на валидность для конкретного хранилища
bool ICPCryptoImpl::CertIsValidEx(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam)
{	
	ASSERT(pValidParam!=NULL);
	//NMS : Обнулим
	pValidParam->Reset();	
	//NMS : Проверим настройки, а нужно ли проверять валидность сертификата
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("Проверка валидности сертификата отключена настройками, поэтому все сертификаты считаются валидными !"));
		m_strLastError.Empty();
		return TRUE;
	}
	ASSERT(pCertContext!=NULL);
	//NMS : Прочитаем Subject у сертификата
	CString strSubject=CertGetName(pCertContext);
	//NMS : Прочитаем серийный номер сертификата
	CBinData bdCertSerialNo(pCertContext->pCertInfo->SerialNumber.pbData,
							pCertContext->pCertInfo->SerialNumber.cbData);
#ifdef _DEBUG
	//NMS : Будем писать в лог, что вызывалась функция для сертификтата такого то, но только в отладке
	WriteToLog(_T("Вызов ICPCryptoImpl::CertIsValidEx => Для сертификата : \"%s\"."),strSubject);
#endif//_DEBUG
	//NMS : Время истекло, уничтожаем кэш, так как данные в нем могут устареть
	CTimeSpan ts=CTime::GetCurrentTime()-m_tValidCache;
	if (ts.GetTotalMinutes()>=5) // Пусть будет 5 минут - время хранения кэша
	{
		m_lstCertValid.RemoveAll();
	}
	//NMS : Установим время обновления кэша
	m_tValidCache=CTime::GetCurrentTime();
	//NMS : Посмотрим, а нет ли в кэше нашего сертификата
	POSITION pos=m_lstCertValid.GetHeadPosition();
	while(pos!=NULL)
	{
		CBinData& bdSerialNoNow=m_lstCertValid.GetNext(pos);
		if (bdSerialNoNow==bdCertSerialNo)
		{
			WriteToLog(_T("Сертификат \"%s\" найден в кэше валидных сертификатов !"),strSubject);			
			return true;
		}
	}	
	//NMS : Будем проверять сертификат по полной программе
	bool bResult=false;
	
	int nResult = CertCheckChain(pCertContext,pValidParam);

	if (CCPC_NoError==nResult) // цепочка действительна и CRL тоже
	{
		WriteToLog(_T("Цепочка сертификата \"%s\" действительна !"),CertGetName(pCertContext));
		//NMS : Если сертификат оказался хорошим, тогда проверим его срок действия
		bResult = CertVerifyDateValid(pCertContext);
		//NMS : Если сертификат валидный добавим его в кэш
		if (bResult)
		{		
			m_lstCertValid.AddTail(bdCertSerialNo);
			m_strLastError.Empty();
			pValidParam->Reset();
		}	
	}
	else if (nResult==CCPC_CantVerifyCRL || nResult==CCPC_CrlNotValid)
	{
		WriteToLog(_T("CRL для сертификата \"%s\" не действительна !"),CertGetName(pCertContext));
		bResult = CertVerifyDateValid(pCertContext); // KAA: делаем проверку только по времени
	}
	else
	{
		WriteToLog(_T("Цепочка сертификата \"%s\" не действительна, по причине: ") + m_strLastError,CertGetName(pCertContext));
 		bResult = false;// KAA: сертификат не действителен, т.к. не удалось построить валидную цепочку
	}
	//NMS : Возвратим результат
	return bResult;
}

//NMS : Позволяет получить из строки отпечаток сертификата
/*static*/ bool ICPCryptoImpl::GetThumbFromStr(CString strThumb,CRYPT_DATA_BLOB* pThumb)
{
	//NMS : Обнулим pThumb, если есть pThumb
	if (pThumb!=NULL)
	{
		ZeroMemory(pThumb,sizeof(CRYPT_DATA_BLOB));	
	}
	//NMS : Если отпечаток пустой, выходим
	if (strThumb.IsEmpty())
	{
		return false;
	}	
	//NMS : Алгоритм следующий :
	//		Если длина строки отпечатка больше 40 символов, тогда нужно удалить все пробелы
	//		и после этого длина должна быть ровна 40, если это не так это не отпечаток.
	//		Если длина строки уже 40 символов, тогда нужно конвертировать из HEX в BIN.
	//NMS : Проверяем длину, если больше 40 символов удаляем пробелы
	if (strThumb.GetLength()>40)
	{
		//NMS : Удаляем пробелы
		strThumb.Replace(_T(" "),_T(""));
	}
	bool bResult=false;
	//NMS : Если длина строки 40 символов, тогда
	//		конвертируем из HEX в BIN
	if (strThumb.GetLength()==40)
	{
		//NMS : Пытаемся конвертировать HEX в BIN
		CBinData bd;
		if (bd.FillFromHex(strThumb) && bd.Size()>0)
		{
			//NMS : Если удалось сконвертировать,
			//		заполняем структуру pThumb,
			//		если pThumb есть, иначе просто
			//		возвращаем успех.
			if (pThumb!=NULL)
			{
				//NMS : Выделяем память
				BYTE* pBytes=new BYTE[bd.Size()];
				ASSERT(pBytes!=NULL);
				if (pBytes!=NULL)
				{
					//NMS : Устанавливаем размер и копируем данные
					pThumb->cbData=bd.Size();
					CopyMemory(pBytes,bd.Buf(),bd.Size());
					pThumb->pbData=pBytes;
					//NMS : Устанавливаем успех
					bResult=true;
				}
			}
			else
			{
				//NMS : Устанавливаем успех
				bResult=true;
			}
		}
	}
	return bResult;
}

//AKV : Позволяет из отпечатка сертификата строку
/*static*/ bool ICPCryptoImpl::GetStrFromThumb(const CRYPT_DATA_BLOB* pThumb, CString& strThumb)
{
	ASSERT(pThumb);
	if (!pThumb)
		return false;
	ASSERT(pThumb->cbData == 20);
	if (pThumb->cbData != 20)
		return false;
	
	CBinData bdThumb(pThumb->pbData, pThumb->cbData);
	bdThumb.Encode2Hex(strThumb);
	strThumb.MakeUpper();

	return true;
}

//NMS : Корректирует префикс OID'а
void ICPCryptoImpl::CorrectOIDPrefix(CString& strOID,CString strReplacePrefix)
{
	//NMS : Если OID пустой ни чего не делаем
	if (strOID.IsEmpty())
	{
		return;
	}
	//NMS : Проверяем наш префикс
	if (!CStringProc::HavePrefix(strOID,strReplacePrefix))
	{
		//NMS : Меняем префикс на тот, который задан в лицензии
		strOID.Delete(0,min(strOID.GetLength(),strReplacePrefix.GetLength()));
		//NMS : Ставим префикс из лицензии
		strOID.Insert(0,strReplacePrefix);
	}
}

//NMS : Позволяет получить OID оп умолчанию.
//NMS : По умолчанию ставим OID, который принадлежит Taxcom 1.2.643.3.22
CString ICPCryptoImpl::GetDefaultOID(void)
{
	CString strResult;
	//NMS : Первая часть находится в strRight, а вторая в strLeft
	CString strLeft(_T("4332e332e3232")),strRight(_T("312e322e363"));
	//NMS : Собираем
	const CString strHex=strRight+strLeft;
	//NMS : Преобразуем в строку
	CBinData bd;
	if (bd.FillFromHex(strHex))
	{
		strResult=CString((TCHAR*)bd.Buf(),bd.Size());
	}
	//NMS : Возврощаем строку
	return strResult;
}


//NMS : Функция загружает настройки из INI файла
void ICPCryptoImpl::LoadSettings(void)
{	
//NMS : Определения для файла настроек
#define SECT_SETTINGS_NAME _T("Settings")
#define KEY_SETTINGS_VERSION _T("Version")
#define KEY_SETTINGS_USINGCUSTOMOPTIONS _T("UsingCustomOptions")
#define KEY_SETTINGS_SKIPUPDATECRL _T("SkipUpdateCRL")
#define KEY_SETTINGS_SKIPCHECKCERTVALID _T("SkipCheckCertValid")
#define KEY_SETTINGS_SKIPUPDATECRLININIT _T("SkipUpdateCRLInInit")
#define KEY_SETTINGS_SKIPCHECKCRL _T("SkipCheckCRL")
#define KEY_SETTINGS_OFFLOGFILE _T("OffLogFile")
#define KEY_SETTINGS_SKIPCHECKTIMEREMAINS _T("SkipCheckTimeRemains")
//NMS : Макрос преобразует значение из INI в BOOL
#define INIVALUE_2_BOOL(ini,key_name,def_val) _ttoi(ini.GetValue(SECT_SETTINGS_NAME,key_name,LONG_2_STR(def_val)))
//NMS : Макрос преобразования числа в строку
#define LONG_2_STR(nValue) CStringProc::Format(_T("%d"),nValue)
	//NMS : Сбрасываем настройки
	m_Settings.Reset();	
	//NMS : Формируем путь к файлу настроек
	CString strPF;

#ifdef CTHREAD_UPDATE_CRL
// KAA : запросим директорию Dipost
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : Проверим последний слэш
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif // CTHREAD_UPDATE_CRL

	// проверим это для Референта?
	m_IsReferent = FALSE;
	CIniMng iniS;
	CString strStartupFile;
	
	strStartupFile.Format(_T("%s\\app.info"),m_strRootPath);
	iniS.Open(strStartupFile);
	CString AppName = iniS.GetValue("Application","Name");
	AppName.MakeLower();
	if (AppName.Find("referent")>=0)
		m_IsReferent = TRUE;
	// если Референт изменим параметры поумолчанию
	if (m_IsReferent)
	{
		m_Settings.bUsingCustomOptions=FALSE;
		m_Settings.bSkipUpdateCRL=FALSE;
		m_Settings.bSkipCheckCertValid=FALSE;
		m_Settings.bSkipUpdateCRLInInit=TRUE;
		m_Settings.bSkipCheckCRL=FALSE;
		m_Settings.bOffLogFile=FALSE;
		m_Settings.bSkipCheckTimeRemains=FALSE;
	}

	strPF.Format(_T("%s\\CPCrypto.ini"),m_strRootPath);
	//NMS : Пытаемся загрузить файла
	CIniMng ini;
	ini.Open(strPF);
	//NMS : Смортим а включены ли настройки руками
	m_Settings.bUsingCustomOptions=INIVALUE_2_BOOL(ini,KEY_SETTINGS_USINGCUSTOMOPTIONS,m_Settings.bUsingCustomOptions);
	//NMS : Если включены читаем их из файла	
	if (m_Settings.bUsingCustomOptions!=FALSE)
	{
		WriteToLog(_T("Настройки будут считаны из файла CPCrypto.ini."));
		//NMS : Читаем настройки
		m_Settings.bSkipUpdateCRL=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPUPDATECRL,m_Settings.bSkipUpdateCRL);
		m_Settings.bSkipCheckCertValid=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKCERTVALID,m_Settings.bSkipCheckCertValid);
		m_Settings.bSkipUpdateCRLInInit=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPUPDATECRLININIT,m_Settings.bSkipUpdateCRLInInit);
		m_Settings.bSkipCheckCRL=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKCRL,m_Settings.bSkipCheckCRL);
		m_Settings.bOffLogFile=INIVALUE_2_BOOL(ini,KEY_SETTINGS_OFFLOGFILE,m_Settings.bOffLogFile);
		m_Settings.bSkipCheckTimeRemains=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKTIMEREMAINS,m_Settings.bSkipCheckTimeRemains);

	}
	else
	{
		WriteToLog(_T("Будут использоваться настройки по умолчанию, потому что значение ключа UsingCustomOptions в файле \"CPCrypto.ini\" равно \"0\"."));
	}
	//NMS : Почистим последнюю ошибку
	m_strLastError.Empty();
	//NMS : Настройки прочитали, теперь сохраним их в файл, тем
	//		самым создав новые ключи, которые могли добавится	
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_VERSION,LONG_2_STR(2));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_USINGCUSTOMOPTIONS,LONG_2_STR(m_Settings.bUsingCustomOptions));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPUPDATECRL,LONG_2_STR(m_Settings.bSkipUpdateCRL));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKCERTVALID,LONG_2_STR(m_Settings.bSkipCheckCertValid));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPUPDATECRLININIT,LONG_2_STR(m_Settings.bSkipUpdateCRLInInit));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKCRL,LONG_2_STR(m_Settings.bSkipCheckCRL));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_OFFLOGFILE,LONG_2_STR(m_Settings.bOffLogFile));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKTIMEREMAINS,LONG_2_STR(m_Settings.bSkipCheckTimeRemains));
	//NMS : Сохраняем настройки в файл
	ini.Save();	
}


bool ICPCryptoImpl::CertVerifyDateValid(PCCERT_CONTEXT pCert)
{
	//NMS : Проверим настройки, а нужно ли проверять валидность сертификата
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("Проверка валидности сертификата отключена настройками, поэтому все сертификаты считаются валидными !"));
		m_strLastError.Empty();
		m_LastErrorCode = 0;
		return true;
	}

	COleDateTime tmNow=COleDateTime::GetCurrentTime();
	if (tmNow<pCert->pCertInfo->NotBefore)
	{				
		m_strLastError.Format(_T("Срок действия сертификата \"%s\" еще не наступил !"),
				   CertGetName(pCert));
		WriteToLog(m_strLastError);
		m_LastErrorCode = CCPC_CertNotValid;
		return false;
	}

	if(tmNow>pCert->pCertInfo->NotAfter)
	{
		m_strLastError.Format(_T("Срок действия сертификата \"%s\" истек !"),
				   CertGetName(pCert));
		WriteToLog(m_strLastError);
		m_LastErrorCode = CCPC_CertNotValid;
		return false;
	}
	return true;
}

int ICPCryptoImpl::CertCheckCertRemain(PCCERT_CONTEXT pSigner)
{
	//NMS : Проверим настройки, а нужно ли проверять валидность сертификата
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("Проверка валидности сертификата отключена настройками, поэтому все сертификаты считаются валидными !"));
		m_strLastError.Empty();
		return CCPC_NoError;
	}
	if (m_Settings.bSkipCheckTimeRemains==TRUE)
	{
		WriteToLog(_T("Проверка срока действия сертификата отключена настройками"));
		m_strLastError.Empty();
		return CCPC_NoError;
	}
	
	if (NULL==pSigner) 
		return m_LastErrorCode = CCPC_CantFindCertInStore;

	COleDateTime dtAfter = COleDateTime(pSigner->pCertInfo->NotAfter);
	COleDateTime dtNow = COleDateTime::GetCurrentTime();
	COleDateTimeSpan dtCountDays = dtAfter - dtNow;
	// Разницу дней будем считать строго по дням как видит абонент
	long nCountOfDays = long(dtAfter.m_dt)-long(dtNow.m_dt);
	
	if (nCountOfDays<0) 
		return CCPC_CertNotValid;

	if ((dtCountDays.m_span<=7.0) && (m_IsReferent==TRUE))
	{
	// определим отпечаток и проверим его в кеше
		CRYPT_DATA_BLOB blob = {0};

		CString strSignerCN = GetCNFromCert(pSigner);
		CString strSignerThumb;
		if (CertGetThumb(pSigner, &blob))
		{
			GetStrFromThumb(&blob, strSignerThumb);
			delete[] blob.pbData;
		}

#ifdef CTHREAD_UPDATE_CRL
// KAA : запросим директорию Dipost
		if (NULL!=m_pCPCryptoCallBack)
		{
			if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
				m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
			//NMS : Проверим последний слэш
			m_strRootPath.TrimRight(_T('\\'));	
		}

		CINIFile ini;
		ini.Load(m_strRootPath+"\\remains.ini");
		CTime tmLastUpdate((time_t)ini.ReadINIInt("certs","LastUpdate",0));
		if (CTimeSpan(CTime::GetCurrentTime()-tmLastUpdate).GetDays()>7) 
			ini.DeleteINISection("certs");
			
		int nLastCountOfDays  = ini.ReadINIInt("certs",strSignerThumb,-1);
		if (nLastCountOfDays == nCountOfDays){ // мы уже спрашивали сегодня выходим
			return CCPC_NoError;
		}else{ // почистим сразу
			if (nLastCountOfDays>=0)
				ini.DeleteINIKey("certs",strSignerThumb);
		}

		
		CString sPrefix;
		switch (nCountOfDays)
		{
		case 0:
		case 1: 
			{
				if (dtCountDays.m_span>=1.0)
				{
					sPrefix.Format("ся %d день",nCountOfDays);break;
				}
				else
				{
					switch(dtCountDays.GetHours())
					{ 
					case 0: sPrefix = "ось меньше 1 часа";break;
					case 21:
					case 1: sPrefix.Format("ся %d час", dtCountDays.GetHours());break;
					case 2:
					case 3:
					case 22:
					case 23:
					case 4: sPrefix.Format("ось %d часа", dtCountDays.GetHours());break;
					default: sPrefix.Format("ось %d часов", dtCountDays.GetHours());break;
					}
				}
				break;
			}
		case 2:
		case 3:
		case 4: sPrefix.Format("ось %d дня",nCountOfDays);break;
		default: sPrefix.Format("ось %d дней",nCountOfDays);break;
		}
		m_strLastError.Format ("До окончания срока действия сертификата остал%s",sPrefix);
		WriteToLog(m_strLastError);
		AFX_MANAGE_STATE(AfxGetStaticModuleState());
		CString strText;
		strText = "Внимание: " + m_strLastError + "\r\n"
			"Рекомендуем Вам завершить документооборот по отчетности, отправленной ранее,\r\n"
			"а перед отправкой новой отчетности, обновить личный сертификат "+ CertGetName(pSigner,FALSE)+"\r\n"
			"(смотрите инструкцию по замене сертификата: http://www.taxcom.ru/centr/abonentam/ )\r\n"
			"\r\n"
			"Если на момент обработки отчетности в контролирующем органе срок действия Вашего \r\n"
			"сертификата будет просрочен, то такая отчетность обработана не будет.\r\n"
			"\r\n"
			"Вы все равно хотите отправить документ?\r\n"
			"Нажмите Да - для продолжения, Нет - для отмены отправки";
		if (::MessageBox(NULL,strText,m_strLastError,MB_ICONWARNING+MB_YESNO)==IDYES) 
		{
			// добавим в кеш сертификат
			ini.WriteINIInt("certs",strSignerThumb,nCountOfDays);
			ini.WriteINIInt("certs","LastUpdate",CTime::GetCurrentTime().GetTime());
			ini.Save("");
			return CCPC_NoError;
		}
#endif // CTHREAD_UPDATE_CRL

		return CCPC_CertIsRemainExpiered;
	}
	return CCPC_NoError;
}

CString GetCNFromCert(PCCERT_CONTEXT pCert)
{
	ASSERT(pCert!=NULL);
	CString strResult;
	if (pCert!=NULL)
	{
		LPCTSTR lpszFieldOID=szOID_COMMON_NAME;
		const LONG nBuffLen=1024;
		TCHAR szBuff[nBuffLen]={0};
		::CertGetNameString(pCert,
							CERT_NAME_ATTR_TYPE,
							0x00,
							(void*)lpszFieldOID,
							&szBuff[0],
							nBuffLen-1);
		strResult=&szBuff[0];	
	}
	return strResult;
}