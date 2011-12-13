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

//NMS : ����������� ������ ��� ����
static CCriticalSection g_csLog;

//*****************************************************************************
//* CCertFreeCertificateContext
//*****************************************************************************

//NMS : ������������� ����������� �������� �����������

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

//NMS : ������������� ����������� ����

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

//NMS : ������������� ����������� ���

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

//NMS : ������������� ����������� ����������������

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

//NMS : ������������� ����������� ���������� ������������������ ���������

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

//NMS : ��������� ������������� ��� �������� �������� ������������
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

//NMS : ������������� ��������� �� ������ � ����� ��������
void CCertAutoBytePtr::Attach(const BYTE* pPtr,const bool bFree/*=true*/)
{
	m_pPtr=const_cast<BYTE*>(pPtr);
	m_bFree=bFree;
}

//NMS : ������� � �������� ��������� �� ������
void CCertAutoBytePtr::Free(void)
{
	if (m_pPtr!=NULL)
	{
		//NMS : �������
		if (m_bFree)
		{
			free(m_pPtr);
		}
		else
		{
			delete[] m_pPtr;
		}
		//NMS : ��������
		m_pPtr=NULL;
	}
}

//*****************************************************************************
//* CCertAutoStore
//*****************************************************************************

//NMS : ������������� ��������� ���������

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

//NMS : ������������� ��������� ������ ��� ������ � ����������� ������,

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

//NMS : ����� ����� ��� ������, ������� ��������� CRL � ����
static UINT _ThreadEntryUpdateCRL(LPVOID pParam)
{	
	try
	{
		TRACE("\n���������� ����� ���������� CRL � ���� !\n");
		ICPCryptoImpl* pCPCryptoImpl=(ICPCryptoImpl*)pParam;
		VERIFY(pCPCryptoImpl!=NULL);
		pCPCryptoImpl->UpdateCRLs();
		TRACE("\n�������� ������ ����� ���������� CRL � ���� !\n");
	}
	catch(...)
	{
		TRACE("\n��� ���������� CRL � ���� ��������� ����������� ������ !\n");
	}	
	return 0;
}

//NMS : ������ ������, ������� ���������� ���������� CRL
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

	//NMS : ������� ����������� ������ � �������� � �������������
	ZeroMemory(&m_CS,sizeof(CRITICAL_SECTION));
	::InitializeCriticalSection(&m_CS);	
	//NMS : ������� ������� �� ���������
	m_arrOIDPrefix.Add(GetDefaultOID());
}
void ICPCryptoImpl::release()
{
    delete this;
}
ICPCryptoImpl::~ICPCryptoImpl()
{
	//NMS : �������� ���, ���� �� �� ���������
	CertCloseStore(CST_ALL);
	//NMS : ������ ��� ��������� �����
	DeleteAllTempFiles();
	//NMS : ��������� ����� ���������� CRL
#ifdef CTHREAD_UPDATE_CRL
	if (g_ThreadUpdateCRL.IsCreate())
	{
		g_ThreadUpdateCRL.Destroy();
	}
#endif // CTHREAD_UPDATE_CRL

	//NMS : ���, ��� ���� ���� ���������� � ����,
	//		������ ���� ��� �� ��������
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : ������ ��� Log
		CSingleLock LogLock(&g_csLog,TRUE);
		m_Log.WriteLog();
	}
	//NMS : ��������� ����������� ������
	::DeleteCriticalSection(&m_CS);
}

//NMS : ��������� ������ � �������
int	ICPCryptoImpl::LockMethods(void)
{
	//NMS : ���� � ����������� ������
	EnterCriticalSection(&m_CS);
	
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : ������������ ������ � �������
int	ICPCryptoImpl::UnLockMethods(void)
{
	//NMS : ���, ��� ���� ���� ���������� � ����, ���� ��� ���������
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : ������ ��� Log
		CSingleLock LogLock(&g_csLog,TRUE);
		m_Log.WriteLog();
	}	
	//NMS : ������ ��� ��������� �����
	DeleteAllTempFiles();
	//NMS : ����� �� ����������� ������
	::LeaveCriticalSection(&m_CS);
	return m_LastErrorCode = CCPC_NoError;
}

//**********************************************************
//NMS : �������������
//**********************************************************

#define STR_VALUE_LIC_OID		_T("LicOID")
#define STR_KEY_LIC_OID_PREFIX	_T("OIDPrefix")

/*virtual*/ int ICPCryptoImpl::Initialize(CString sRootPath, ICPCryptoCallBack* iCPCryptoCallBack/*=NULL*/)
{
// KAA : �������� ��������� ��������� ������
#ifdef CTHREAD_UPDATE_CRL
	m_pCPCryptoCallBack = iCPCryptoCallBack;
#endif // CTHREAD_UPDATE_CRL

#ifdef _DEBUG
	//__asm int 3;
#endif//_DEBUG


	//NMS : �������� ����
	m_strRootPath=sRootPath;

#ifdef CTHREAD_UPDATE_CRL
	// KAA : �������� ���������� Dipost-� 
	if (NULL!=m_pCPCryptoCallBack)
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
#endif // CTHREAD_UPDATE_CRL

	//NMS : �������� ��������� ����
	m_strRootPath.TrimRight(_T('\\'));
	
	//NMS : �������� ���������
	LoadSettings();
	//NMS : ��������� ���� � ��� �����, ������ ���� ��� �������
	if (m_Settings.bOffLogFile==FALSE)
	{
		//NMS : ������ ��� Log
		CSingleLock LogLock(&g_csLog,TRUE);
		//NMS : �������, �� ��� ���� � ����
		m_Log.WriteLog();
		//NMS : ��������� ����� ���� � ����
		m_Log.m_sPFNLog.Format(_T("%s\\CPCrypto.log"),m_strRootPath);
		//NMS : ��� ����� �� 100�� �� ���������, � 512 ��
		m_Log.SetLogSize(_T("512"));
	}	
	//NMS : ��������
	m_arrOIDPrefix.RemoveAll();
	m_arrOIDPrefix.Add(GetDefaultOID());	
#if 0 // not check license
	CLicValidator lic(sRootPath,STR_VALUE_LIC_OID,1);
    if (lic.IsValid())
	{
		m_arrOIDPrefix.RemoveAll();
		//NMS : ������ ������������� �� ������ ������� ������
		CString strPrefix=lic.GetValue(STR_KEY_LIC_OID_PREFIX);
		if (!strPrefix.IsEmpty())
		{
			m_arrOIDPrefix.Add(strPrefix);
		}
		LONG nPrefixNo=1;		
		for(;;)
		{
			//NMS : ������ �� ��������
			if (nPrefixNo>100)
			{
				break;
			}
			//NMS : ������
			strPrefix=lic.GetValue(CStringProc::Format(_T("%s_%d"),STR_KEY_LIC_OID_PREFIX,nPrefixNo));
			nPrefixNo++;
			//NMS : ���� ����� ����� �������
			if (strPrefix.IsEmpty())
			{
				break;
			}
			//NMS : ���� ���� ������, ������� �� � ������
			m_arrOIDPrefix.Add(strPrefix);
		}
		//NMS : ���� ������ ������ ������� OID �� ���������
		if (m_arrOIDPrefix.GetSize()<=0)
		{
			m_arrOIDPrefix.Add(GetDefaultOID());
		}
	}
	else
	{
		WriteToLog(_T("�� ������� �� ����� ����������� ��������, ��� �������� OID ����� �������������� ������� �� ��������� !"));
	}
	WriteToLog(_T("��� �������� OID ����� ������������ �������� \"%s\"."),((CStringArrayEx*)&m_arrOIDPrefix)->GetAsString(_T(";"),FALSE));
	m_strLastError.Empty();

	//NMS : �������� ���� �� �������������, �
	//		��� �� ��� �� �������� ����� (�����������)
	if (!CFileMng::IsDirExist(sRootPath))		
	{
		WriteToLog(_T("���� �� ���������� ��� �� �������� \"%s\" !"),sRootPath);
		//NMS : ��� ������� ������ ���� !
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}
	//NMS : ��������� certstore
	UpdateCertStore();
#endif // 0

// KAA : ������� �������������� ���������� CRL ��� �������������
/* 
#if 0
	//NMS : ��������� CRL � ����������� ������
	//NMS : ������ ��������� ������ ���, ��� ���
	//		�������� ��������� ������������ SST
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
// KAA : ���� �������������
	if (NULL!=m_pCPCryptoCallBack)
		Result = m_pCPCryptoCallBack->OnInitialize(Result);
#endif // CTHREAD_UPDATE_CRL

	//NMS : ������ �����
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
//NMS : Protected ������
//**********************************************************

//NMS : ���������� �������� ��������� ������
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

//NMS : ��������� ��������� � ������� ����� ������ ����������
//	bReOpen - ����������� ��� ��������� ������, � ��
//	����� ������ �� ����.
int ICPCryptoImpl::CertOpenStore(const DWORD dwType/*=CST_ALL*/,
								 const bool bReOpen/*=false*/)
{
//	WriteToLog(_T("����� ICPCryptoImpl::CertOpenStore"));
	//NMS : ���� ����� ��� �����������, ����� �������
	//		��� �������� ���������
	if (bReOpen)
	{
		WriteToLog(_T("������� ���� ������� �������� ������������ !"));
		CertCloseStore(dwType);
	}
	//NMS : ����� ��������� ��������� � ���������� ������ � ���
	HCERTSTORE hStore=NULL;
	//NMS : � ������ ������ ��������� ������� ��� �������� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ����� ������ ��������� certstore.sst
	if (dwType&CST_SST && CertGetHandleStoreByType(CST_SST)==NULL)
	{
		CString strCertStorePath;

#ifdef CTHREAD_UPDATE_CRL
// KAA : �������� ���� Dipost
		if (NULL!=m_pCPCryptoCallBack)
		{
			if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
					m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
			//NMS : �������� ��������� ����
			m_strRootPath.TrimRight(_T('\\'));	
		}
#endif // CTHREAD_UPDATE_CRL
		strCertStorePath.Format(_T("%s\\certstore.sst"),m_strRootPath);
		//NMS : �������� ���� � certstore.sst
		CertStoreVerifyExistPath(strCertStorePath);
		//NMS : ��������� ...	
		hStore=::CertOpenStore(CERT_STORE_PROV_FILENAME_A,
							   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
							   NULL,
							   CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_CREATE_NEW_FLAG,
							   (LPCSTR)strCertStorePath);
#ifdef CTHREAD_UPDATE_CRL
		if (hStore==NULL && m_pCPCryptoCallBack==NULL)
		{
			WriteToLog(_T("�� ������� ������� ��������� certstore.sst, ���� \"%s\", ������� : %s !"),
					   strCertStorePath,
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
#endif // CTHREAD_UPDATE_CRL
		//NMS : ������� �������, ��������� � ���
		m_mapCertStore.SetAt(CST_SST,hStore);
		hStore=NULL;
	}
	//NMS : ��������� ������ �����������
	if (dwType&CST_MY && CertGetHandleStoreByType(CST_MY)==NULL)
	{
		hStore=::CertOpenStore(CERT_STORE_PROV_SYSTEM,
							   0,
							   NULL,CERT_SYSTEM_STORE_CURRENT_USER,
							   L"My");
		if (hStore==NULL)
		{
			WriteToLog(_T("�� ������� ������� ��������� ������(My), ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : ������� �������, ��������� � ���
		m_mapCertStore.SetAt(CST_MY,hStore);
		hStore=NULL;
	}
	//NMS : ��������� root ����������� 
	if (dwType&CST_ROOT && CertGetHandleStoreByType(CST_ROOT)==NULL)
	{
		hStore=::CertOpenStore(CERT_STORE_PROV_SYSTEM,
							   0,
							   NULL,
							   CERT_SYSTEM_STORE_CURRENT_USER,
							   L"Root");
		if (hStore==NULL)
		{
			WriteToLog(_T("�� ������� ������� ��������� ���������� �������� ������ ������������(Root), ������� : %s !"),
					   GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : ������� �������, ��������� � ���
		m_mapCertStore.SetAt(CST_ROOT,hStore);
		hStore=NULL;
	}

	//  KAA: ��������� ����������� �� ������� ��������� CST_OWNER
	if (dwType&CST_OWNER && CertGetHandleStoreByType(CST_OWNER)==NULL)
	{
#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
			hStore=m_pCPCryptoCallBack->OnCertOpenStore();
#endif // CTHREAD_UPDATE_CRL

		if (hStore==NULL)
		{
			WriteToLog(_T("�� ������� ������� ���������"));
			return m_LastErrorCode = CCPC_CantOpenStore;
		}
		//NMS : ������� �������, ��������� � ���
		m_mapCertStore.SetAt(CST_OWNER,hStore);
		hStore=NULL;
	}


	//NMS : ��� ������ ���������, ������� ��������� �� ���� �� ����� !
	CertCloseCache.m_pCls=NULL;
	//NMS : ���������� ����� !
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : ��������� �������� ��������� ������������

void ICPCryptoImpl::CertCloseStore(const DWORD dwType/*=CST_ALL*/)
{
	//WriteToLog(_T("����� ICPCryptoImpl::CertCloseStore"));

	//NMS : ����� �� �����
	POSITION pos=m_mapCertStore.GetStartPosition();
	DWORD dwTypeKey;
	HCERTSTORE hStore=NULL;
	//NMS : ���� ���������� ������ CST_ALL ������ ������ ���
	const bool bClearAll=(dwType==CST_ALL) ? true:false;
	while(pos!=NULL)
	{
		hStore=NULL;
		dwTypeKey=0x00;
		m_mapCertStore.GetNextAssoc(pos,dwTypeKey,hStore);
// KAA : �������� �������� ���������
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
				//NMS : ���������  ���������
				::CertCloseStore(hStore,CERT_CLOSE_STORE_FORCE_FLAG);
			}
			else if (dwType&dwTypeKey)
			{
				//NMS : ���������  ���������
				::CertCloseStore(hStore,CERT_CLOSE_STORE_FORCE_FLAG);
				//NMS : ������� �� �����, ������ �� ��� ������,
				//		��� ��� � ����� ����� ������ � ������ ������
				m_mapCertStore.RemoveKey(dwTypeKey);
			}
		}
	}
	//NMS : ������ ��� �����
	if (bClearAll)
	{
		m_mapCertStore.RemoveAll();
	}
}

//NMS : ��������� �������� ����� ��������� �� ���� �� ����
HCERTSTORE ICPCryptoImpl::CertGetHandleStoreByType(const DWORD dwType)
{
	HCERTSTORE hResult=NULL;
	m_mapCertStore.Lookup(dwType,hResult);
	return hResult;
}

//NMS : ��������� ������������� SST �����, ���� �� ����������
//		�������, ������ ���� � ������ ����������.
void ICPCryptoImpl::CertStoreVerifyExistPath(CString strStoreFilePath)
{
	//NMS : ��������� ������������� SST �����
	CFileFind ff;
	if (!ff.FindFile(strStoreFilePath))
	{
		//NMS : ������� ����������, ���� ��� �� ���������� � ���� strStoreFilePath
		CString sStorePath="";
		while (strStoreFilePath.Find("\\")>=0)
		{
			sStorePath+=strStoreFilePath.Left(strStoreFilePath.Find("\\"));
			strStoreFilePath.Delete(0,1+strStoreFilePath.Find("\\"));
			CreateDirectory(sStorePath,NULL);
			sStorePath+="\\";
		}
		//NMS : ������� ��� ����
		CFile file;
		if (file.Open(sStorePath+strStoreFilePath,
					  CFile::modeWrite|CFile::modeCreate|CFile::modeNoTruncate|
					  CFile::shareDenyWrite))
		{
			file.Close();
		}
	}
}

//NMS : ������� ��������� � ���
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
	//NMS : ��������� ��������� ������
	m_strLastError=strResult;
	//NMS : ��� ��������
	if (m_Settings.bOffLogFile!=FALSE)
	{
		return;
	}
	try
	{	
		//NMS : � ������� ����� �������� ����
#ifdef _DEBUG
		CString strResult2(strResult);
		strResult2+=_T("\r\n");
		//NMS : TRACE ��� ��������
		::OutputDebugString(strResult2);
#endif //_DEBUG
		
// KAA : ����� � ��� ����������, ���� �������� � FALSE, �� ������ � ������� ��� �� �����  
		
		BOOL bResolved = TRUE;
#ifdef CTHREAD_UPDATE_CRL
		if (NULL!=m_pCPCryptoCallBack)
		{
			bResolved = m_pCPCryptoCallBack->WriteLog(strResult);
		}
#endif // CTHREAD_UPDATE_CRL
		if (bResolved)
		{
				//NMS : ����� � "�������" ���
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
		//NMS : ������ ���-�� ��������
		DWORD dwBuffLen=0x00;
		dwBuffLen=CertNameToStr(X509_ASN_ENCODING,
								const_cast<CERT_NAME_BLOB*>(pBlob),
								CERT_X500_NAME_STR,
								NULL,
								0);
		//NMS : ���� ����������� ��������������� ��� 345 �������,
		//		����� ������ ����� ������ ����������� ��
		//		DOS � Win ���������
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

//NMS : ��������� ���������� ��� CRL � ��������� (�� ������ ������ ��� ������ SST)
int ICPCryptoImpl::AddCertOrCRLToStore(const CRYPT_DATA_BLOB* pCertOrCRL,const int iType)
{
	ASSERT(pCertOrCRL!=NULL);
	//WriteToLog(_T("����� ICPCryptoImpl::AddCertOrCRLToStore"));
	//NMS : ��������� ������ SST
	BOOL bResolved = false;
	int nResult = CCPC_NoError;
	
// KAA : ��������� ������ ������(CRL ��� Cert) �� ������� ���������, ���� ��������� - FALSE ���� ������� ���������� 
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
	//NMS : ��������� SST ����� ���������
	CCertCloseCache CertCloseCache(this);
	//NMS : ������� ����� ��������� SST
	HCERTSTORE hSST=CertGetHandleStoreByType(CST_SST);
	ASSERT(hSST!=NULL);
	//NMS : ���������� ����� �������������� �������, ����� ��������
	//		���������� � ��������� SST
	nResult=AddCertOrCRLToStoreEx(hSST,pCertOrCRL,iType);
	//NMS : ����� ��������� ���������� ������
	if (nResult==CCPC_NoError)
	{
		nResult=SaveSSTInFile(hSST);
	}
	if (nResult==CCPC_NoError)
	{
		m_strLastError.Empty();
	}
	//NMS : ���������� ���������
	return m_LastErrorCode = nResult;
}

//NMS : ��������� ���������� ��� CRL � ��������� ���������
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

	//WriteToLog("����� ICPCryptoImpl::AddCertOrCRLToStoreEx");
	if (hStore==NULL) 
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	BOOL bResult=FALSE;
	LPCTSTR lpszName=NULL;
	long nResult=CCPC_NoError;
	//NMS : �������� ���������� �� ����
	switch (nType)
	{
	case CMSG_CTRL_ADD_CERT:
		{
			lpszName=_T("����������");
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
			WriteToLog("����� ICPCryptoImpl::AddCertOrCRLToStoreEx � ���������� nType=%d, ����� ��� ���������� !",nType);
			return m_LastErrorCode = CCPC_InternalError;			
		}
	}
	//NMS : ���� �� ������� �������� ������ � ���������
	if ((bResult==FALSE) && (::GetLastError()!=CRYPT_E_EXISTS))
	{
		WriteToLog(_T("�� ������� �������� %s � ���������, ������� : %s !"),
				   lpszName,GetSystemErrorDesc());
	}
	//NMS : ���������� ���������
	return m_LastErrorCode = nResult;
}

//NMS : ������� CRYPT_DATA_BLOB �� �����
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
			WriteToLog(_T("�� ������� ������� ���� \"%s\", ������� : %s !"),strFile,GetSystemErrorDesc());
			return m_LastErrorCode = CCPC_CantOpenFileRead;
		}

	CString strCertInBase64;	
	
	if (bdData.Find(CERT_IN_BASE64_BEGIN)>=0)
		strCertInBase64=bdData.GetStrBetween(CERT_IN_BASE64_BEGIN,CERT_IN_BASE64_END);
	else
		if (bdData.Find(CRL_IN_BASE64_BEGIN)>=0)
			strCertInBase64=bdData.GetStrBetween(CRL_IN_BASE64_BEGIN,CRL_IN_BASE64_END);

	//NMS : � ������, ���� ���� ���� ����������� ��� base64, ����� �� ����� ���������� � �������� "MII"
	if (strCertInBase64.IsEmpty() && bdData.Find(_T("MII"))==0) 
	{
		strCertInBase64=CString((CHAR*)bdData.Buf(),bdData.Size());
	}

	if (!strCertInBase64.IsEmpty())
	{
		CBinData bdCertInBase64;
		if (!CBase64Utils::DecodeFromB64(strCertInBase64,bdCertInBase64))
		{
			WriteToLog(_T("���� \"%s\" ����� ������ ������ !"),strFile);
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
		WriteToLog(_T("�� ������� �������� ������ ���������� ������ %d ���� ��� ����� \"%s\" !"),
				   bdData.Size(),strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	pCertOrCRL->cbData=bdData.Size();
	CopyMemory(pCertOrCRL->pbData,bdData.Buf(),bdData.Size());
	return m_LastErrorCode = CCPC_NoError;
}

//NMS : ��������� ���������� ��� CRL � ����
int ICPCryptoImpl::AddCertOrCRLToFile(CString strFile,
									  const CRYPT_DATA_BLOB* pCertOrCRL,
									  const int iType)
{
	CCertLockMethods CertLockMethods(this);
	if (!CertLockMethods.Check())
	{
		return m_LastErrorCode = CertLockMethods.m_nStatus;
	}

	//WriteToLog(_T("����� ICPCryptoImpl::AddCertOrCRLToFile"));	
	
	//NMS : �������� ���������� ���
	if (iType!=CMSG_CTRL_ADD_CERT && iType!=CMSG_CTRL_ADD_CRL)
	{
		//NMS : �� ������������ !!!
		WriteToLog("������ ICPCryptoImpl::AddCertOrCRLToFile � ���������� iType=%d, �������� �� �������������� !",iType);
		return m_LastErrorCode = CCPC_InternalError;
	}
	CFile file;
	if (!file.Open(strFile,CFile::modeRead|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� \"%s\", ������� : %s !"),strFile,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileRead;
	}
	//NMS : ������ ����� ����� � �������� �������� ��� ��� ����� ������
	BYTE* bAppendData=NULL;
	DWORD dwAppendDataLen=file.GetLength();
	bAppendData = (BYTE*)malloc(dwAppendDataLen);
	if (!bAppendData)
	{
		WriteToLog(_T("�� ������� �������� ������ ���������� ������ %d ���� ��� ����� \"%s\" !"),
				   dwAppendDataLen,
				   strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ������� ����� ��������� ����� �� ������ ������
	CCertAutoBytePtr bAppendDataPtr(bAppendData);
	//NMS : ������ ������ �� �����
	file.Read(bAppendData,dwAppendDataLen);
	file.Close();
	//NMS : ������� �����
	HCRYPTMSG hMsgAppend=::CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
												0,
												0,
												NULL,
												NULL,
												NULL);
	if (hMsgAppend==NULL)
	{
		WriteToLog(_T("�� ������� ������� ��������������� ��� �����������, �������: %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenToDecode;
	}
	CCertCryptMsgClose hMsgAppendClose(&hMsgAppend);
	//NMS : �������� �������� ������ � ���������			
	if (::CryptMsgUpdate(hMsgAppend,bAppendData,dwAppendDataLen,TRUE)==FALSE)
	{
		WriteToLog(_T("�� ������� �������� ������ � ���������������, �������: %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantAddDataToMessage;
	}
	//NMS : ��������� ������
	bAppendDataPtr.Free();
	//NMS : ����� ���� ��� �������� ������ � ���������,
	//		�������� pCertOrCRL			
	if (::CryptMsgControl(hMsgAppend,0,iType,pCertOrCRL)==FALSE)
	{
		WriteToLog(_T("�� ������� �������� ������������� � ���������, ������� : %s !"),GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantAddDataToMessage;
	}
	//NMS : �������� ����� ���������			
	if (::CryptMsgGetParam(hMsgAppend,CMSG_ENCODED_MESSAGE,0,NULL,&dwAppendDataLen))
	{
		WriteToLog(_T("�� ������� ���������� ������ ���������, ������� : %s !"),__LINE__,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantGetParamMessage;
	}
	//NMS : �������� �������� ������ �� ������� ���������			
	bAppendData=(BYTE*)malloc(dwAppendDataLen);
	if (bAppendData==NULL)
	{
		WriteToLog(_T("�� ������� �������� ������ ���������� ������ %d ���� ��� ����� \"%s\" !"),
				   dwAppendDataLen,
				   strFile);
		return m_LastErrorCode = CCPC_OutOfMemory;
	}
	//NMS : ��������� ��������� ������� ��������� ��������������, ��������� ���������
	bAppendDataPtr.Attach(bAppendData);
	//NMS : �������� ���� ���������			
	if (::CryptMsgGetParam(hMsgAppend,CMSG_ENCODED_MESSAGE,0,bAppendData,&dwAppendDataLen)==FALSE)
	{
		WriteToLog(_T("�� ������� ��������� ������ �� ���������, ������� : %s !"),__LINE__,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantGetParamMessage;
	}
	if (!file.Open(strFile,CFile::modeWrite|CFile::modeCreate|CFile::shareDenyWrite))
	{
		WriteToLog(_T("�� ������� ������� ���� ��������� ��� ���������� ������\"%s\", ������� : %s !"),strFile,GetSystemErrorDesc());
		return m_LastErrorCode = CCPC_CantOpenFileWrite;
	}	
	file.Write(bAppendData,dwAppendDataLen);
	file.Close();
	//NMS : ���������� ����� !
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
			strResult=_T("������");
			break;
		}
	case CST_ROOT:
		{
			strResult=_T("���������� �������� ������ ������������");
			break;
		}
	default:
		{
			strResult.Format(_T("����������� ��� ��������� (%d)"),dwType);
			break;
		}
	}
	return strResult;
}

//NMS : ���� ���������� � ���������
int ICPCryptoImpl::CertFind(LPCERTFINDPARAM lpFindParam,
							PCCERT_CONTEXT* ppCertContext)
{
	ASSERT(lpFindParam!=NULL);
	ASSERT(lpFindParam->dwFindInStore>0);	
	ASSERT(ppCertContext!=NULL);

	//WriteToLog(_T("����� ICPCryptoImpl::CertFind"));

	//NMS : ��������
	if (lpFindParam==NULL ||
		lpFindParam->dwFindInStore==0 ||		
		ppCertContext==NULL)
	{
		WriteToLog(_T("��� ������ ������� ������ ����������� ���� �� ���������� ����� �� ����� !"));
		return m_LastErrorCode = CCPC_InternalError;
	}
	long nResult=CCPC_NoError;	
	//NMS : ������� �������� ��������
	//		������ ������� ������ �����, � ������
	//		������ ����� ���� � SST, ���� ��� ��
	//		����� ����� ������� � MY, � ���� �� �����
	//		� MY ������� � ��������� ��������� ROOT
	CArray<DWORD,DWORD> arrType;
	arrType.SetSize(3);
	arrType[0]=CST_MY;
	arrType[1]=CST_SST;
	arrType[2]=CST_ROOT;
	//NMS : �������
	lpFindParam->ClearArrCerts();
	//NMS : ���������� ��������� ������
	LONG nPrevResult=CCPC_NotInit;
	//NMS : ��������� ������ �����������
	PCCERT_CONTEXT pCertContext=NULL;
	//NMS : ���� �� �����
	const long nTypes=arrType.GetSize();
	for(long nType=0;nType<nTypes;nType++)
	{
		const DWORD dwType=arrType[nType];
		//NMS : ��������, � ����� �� �������� �
		//		���� ��������� ����������
		if (!(lpFindParam->dwFindInStore&dwType))
		{
			continue;
		}
		//NMS : �������� �������� ����� ���������
		HCERTSTORE hStore=CertGetHandleStoreByType(dwType);
#ifdef CTHREAD_UPDATE_CRL
		if (hStore==NULL && m_pCPCryptoCallBack==NULL)
		{
			WriteToLog(_T("��� ������ ����������� � ���������� �� ������� �������� ����� ��� ��������� \"%s\" !"),
					   GetCertStoreNameByType(dwType));
			//NMS : ��������� �����
			continue;
		}
#endif // CTHREAD_UPDATE_CRL
		//NMS : ���� ���������� � ���������
		nResult=CertFindEx(hStore,lpFindParam,&pCertContext);
		//NMS : ���������� ������� ��� ������� ���������, ������ ���� � ������ ��������� ��� �����
		//		� my, ����� ������ ��� �� ��������������
		if ((*ppCertContext)==NULL && pCertContext!=NULL)
		{
			(*ppCertContext)=pCertContext;
		}
		//NMS : ���� ��� ������, ����� ������ ��� ��� ������ ����������(�)
		if (nResult==CCPC_NoError)
		{
			WriteToLog(_T("����������(�) ���(�) ������(�) � ��������� \"%s\"."),GetCertStoreNameByType(dwType));
			m_strLastError.Empty();
		}
		//NMS : ���� ����� ����� ������ �� ���� ��������, ����� ���� �� ���������
		if (lpFindParam->bSelFromAllStores!=FALSE &&
			(nResult==CCPC_NoError || nResult==CCPC_CertNotFind))//NMS : ������ ���� ��� ������ ��� ���������� �� ������
		{
			//NMS : ���� ��� ������, �������� ���������� ���������
			if (nResult==CCPC_NoError)
			{
				//NMS : �������� ���������� ���������
				nPrevResult=nResult;
			}			
			//NMS : �������� � ���������� ���������
			continue;
		}
		//NMS : ����������� ��������� ������ � ���������
		if (nResult==CCPC_CertNotFind)
		{
			//NMS : �� ����� ���������� � ������ ���������, ���� ������
			continue;
		}
		else
		{
			//NMS : ����� ������ ������ ���������� ��� ��������� ������, ������� �� ����� ������
			break;
		}
	}
	//NMS : ���� � ��������� ���������, �� �����, ����� �����
	//		������������ ���������� ���������, ���� �� ����
	if (nResult==CCPC_CertNotFind && nPrevResult!=CCPC_NotInit)
	{
		nResult=nPrevResult;
	}
	//NMS : ���������� ��������� ������ �����������
	return m_LastErrorCode = nResult;
}

//NMS : ��������� �� ���� ������� �������� ������ ��������.
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

//NMS : ��������� �������� ��� �����������
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
	// ���� CN
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

//NMS : ��������� ������� �����������
int ICPCryptoImpl::CertCheckChain(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pCertValidParam)
{
	CString strErrMsg;	
	LONG nResult=CCPC_NoError;
	HCERTCHAINENGINE hChainEngine=NULL;
	CERT_CHAIN_ENGINE_CONFIG ChainConfig;
	PCCERT_CHAIN_CONTEXT pChainContext=NULL;
	try
	{
		//NMS : �������������� ������ ������� ������������
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
			throw CStringProc::Format(_T("�� ������� ������������������� ������ ������� ������������, ������� : %s !"),
									  CStringProc::GetSystemError());
		}
		//NMS : ������� ������ ��� ��������� �������
		CERT_ENHKEY_USAGE EnhkeyUsage;
		CERT_USAGE_MATCH CertUsage;
		CERT_CHAIN_PARA ChainPara;		
		EnhkeyUsage.cUsageIdentifier=0;
		EnhkeyUsage.rgpszUsageIdentifier=NULL;
		CertUsage.dwType=USAGE_MATCH_TYPE_AND;
		CertUsage.Usage=EnhkeyUsage;
		ChainPara.cbSize=sizeof(CERT_CHAIN_PARA);
		ChainPara.RequestedUsage=CertUsage;
		//NMS : ����� �����
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
		//NMS : ������ �������		
		if(!::CertGetCertificateChain(NULL,pCertContext,NULL,hSST,&ChainPara,dwFlags,NULL,&pChainContext))
		{
			nResult=CCPC_CantGetTrustChain;
			pCertValidParam->nResultCode = nResult;
			throw CStringProc::Format(_T("�� ������� ��������� ������� ��� ����������� \"%s\", ������� : %s !"),
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
				//NMS : � ������� ���� ������, ������ � ���
				nResult=CCPC_CantGetTrustChain;
				pCertValidParam->nResultCode = nResult;
				throw CStringProc::Format(_T("��� �������� ������� ����������� \"%s\" ���� �������� ��������� ������ \"%s\" ! "),
										  CertGetName(pCertContext),GetTrustStatusAsStr(pChainContext->TrustStatus.dwErrorStatus));
			}
		}
		//NMS : ���� �������� � ����� ��������, ��� ��� ������ ����� �����������,
		//		� ������ ��� ������������ ��� !
		ASSERT(pChainContext->cChain==1);
		WriteToLog(_T("����� ����� %d ������� ��� ����������� \"%s\" !"),
				   pChainContext->cChain,CertGetName(pCertContext));
		const LONG nChains=min(1,pChainContext->cChain);
		PCCERT_CONTEXT pIssuerCertContext=NULL;
		//NMS : ����� �� �������� � ������ ��� ������ ������� ����� �
		//		������� ������ �������� ����������, � ��������� ��� ���������
		for(LONG nChain=0;nChain<nChains;nChain++)
		{
			typedef class std::map<PCCERT_CONTEXT,PCCERT_CONTEXT> MAPCERTANDCERTISSUER;
			MAPCERTANDCERTISSUER mapCertAndCertIssuer;
			BOOL bSetCertIssuer=FALSE;
			PCCERT_CONTEXT pCertContextKey=NULL;
			for(int nElement=0;nElement<pChainContext->rgpChain[nChain]->cElement;nElement++)
			{
				PCCERT_CONTEXT pCertInChain=pChainContext->rgpChain[nChain]->rgpElement[nElement]->pCertContext;
				WriteToLog(_T("���������� \"%s\"(%d) ��������� \"%s\", � ������� %d !"),
						   CertGetName(pCertInChain),nElement,CertGetName(pCertInChain,TRUE),nChain+1);
				//NMS : ��������� �����				
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
			//NMS : ��������� CRL
			for(MAPCERTANDCERTISSUER::iterator iter=mapCertAndCertIssuer.begin();
				iter!=mapCertAndCertIssuer.end();
				iter++)
			{
				PCCERT_CONTEXT pCert=iter->first;
				PCCERT_CONTEXT pCertIssuer=iter->second;
				ASSERT(pCert!=NULL && pCertIssuer!=NULL);
				HCERTSTORE hCertStore=pCert->hCertStore;				
				//NMS : �������� CRL ��� �������� ���������, �� ������ � ������ ReadOnly
				if (CertCheckCRL(hCertStore,pCertIssuer,pCert,pCertValidParam,TRUE))
				{					
					//NMS : �����, ���� �������, ��������� CRL � SST
					if (!CertCheckCRL(hSST,pCertIssuer,pCert,pCertValidParam,FALSE))
					{
						nResult=pCertValidParam->nResultCode;
						break;//NMS : �������� ������ ��� ���� � pCertValidParam
					}				
				}
				else
				{	// ���������� �������
					if (pCertValidParam->nResultCode==CCPC_CertNotValid)
					{
						nResult=pCertValidParam->nResultCode;
						break;//NMS : �������� ������ ��� ���� � pCertValidParam
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
		strErrMsg=_T("CertCheckChain => ����������� ������ !");
		nResult=CCPC_InternalError;
		pCertValidParam->nResultCode = nResult;
	}
	//NMS : ���� ����� ������ �� ������, ����� �������
	try
	{
		if (!strErrMsg.IsEmpty())
		{
			WriteToLog(strErrMsg);		
		}
		//NMS : ��������� �������
		if (pChainContext!=NULL)
		{
			::CertFreeCertificateChain(pChainContext); 
			pChainContext=NULL;
		}
		//NMS : ��������� ������ ������� ������������
		if (hChainEngine!=NULL)
		{
			::CertFreeCertificateChainEngine(hChainEngine);
			hChainEngine=NULL;
		}
	}
	catch (...)
	{
		strErrMsg=_T("CertCheckChain => ����������� ������ !");
		nResult=CCPC_InternalError;
		pCertValidParam->nResultCode = nResult;
	}
	return m_LastErrorCode = nResult;
}

//NMS : ���� ���������� � ��������� ����������� � � ������� ��������� (������ � ���)
int ICPCryptoImpl::CertFindEx(HCERTSTORE hStore,
							  LPCERTFINDPARAM lpFindParam,
							  PCCERT_CONTEXT* ppCertContext)
{
	ASSERT(lpFindParam!=NULL);	
	ASSERT(ppCertContext!=NULL);

	//WriteToLog(_T("����� ICPCryptoImpl::CertFindEx"));

	//NMS : ��������
	if (lpFindParam==NULL ||		
		ppCertContext==NULL)
	{
		WriteToLog(_T("��� ������ ������� ������ ����������� ���� �� ���������� ����� �� ����� !"));
		return m_LastErrorCode = CCPC_InternalError;
	}	
	//NMS : ���������� ����������� � ��������� � ������ ������ ����������
	PCCERT_CONTEXT pCertContext=lpFindParam->pCertPrev;
	//NMS : ������ � ����������� �������������
	CList<PCCERT_CONTEXT,PCCERT_CONTEXT> lstCertContext;
	
	BOOL bResolved = FALSE;

// KAA : ���� �� ������� ���������, ���� FALSE - ���������� �����
#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack)
	{
// KAA : ���� ������� ���� hStore == CertGetHandleStoreByType(CST_SST)
		if ((hStore == CertGetHandleStoreByType(CST_SST)) || (hStore == NULL))
		for (;;)
		{
			bResolved = m_pCPCryptoCallBack->OnCertFindEx(lpFindParam, pCertContext);

			if ((pCertContext == NULL) || (!bResolved))
			{
				break;
			}

			//NMS : ��������, ��������, ���� �� ����� ���������
			CString sKeyAlgID=pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
			if (sKeyAlgID.Find("1.2.643.2.2.")!=0)
			{
				WriteToLog(_T("���������� �� ������ �������� �� KeyAlgID, ������� KeyAlgID ����� \"%s\" !"),sKeyAlgID);
				continue;
			}
			//NMS : �������� OID, ���� �� �� ������
			if (!lpFindParam->strOID.IsEmpty())
			{
				if (!CertCheckOID(pCertContext,lpFindParam->strOID))
				{
					//NMS : �� ������ �������� �� OID, ��������� � ���� ��� ����
					continue;
				}
			}
			//NMS : �������� ���������� �� ����������, � ��� �� 
			//		�������� ������� �����������		
			CERTVALIDPARAM ValidParam;
			if (lpFindParam->bSkipCertIsValid==FALSE &&
				(!CertIsValid(pCertContext,&ValidParam)))
			{
				//NMS : �� �������� ���������� - �������
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
		//NMS : ������ �������� ���������� ���� ������ ����� �� ���� email
		CERT_RDN rdn;
		CERT_RDN_ATTR aRdnAttrs[1];
		ZeroMemory(&rdn,sizeof(CERT_RDN));
		ZeroMemory(&aRdnAttrs,sizeof(aRdnAttrs));
		//NMS : �������� ��������� ��������� �����������
		CRYPT_DATA_BLOB cdbThumb;
		cdbThumb.cbData=lpFindParam->cdbThumb.cbData;
		cdbThumb.pbData=lpFindParam->cdbThumb.pbData;	
		//NMS : ���� ����� ������ �� email, ����� ��������� ��������
		DWORD dwFindType=0x00;
		void* pFindParam=NULL;
		//NMS : ���� � CN ���������� @ ������ ������ �����
		//		�� ���� E � �������� ����������� Subject
		const bool bFindByEmail=(lpFindParam->strCN.Find(_T("@"))>0) ? true:false;
		bool bFindByThumb=false;
		CCertAutoBytePtr AutoClearThumb(NULL);
		if (bFindByEmail)
		{
			//NMS : ����� ����������� ����� �� ���� E
			aRdnAttrs[0].pszObjId=szOID_RSA_emailAddr;
			aRdnAttrs[0].dwValueType=CERT_RDN_IA5_STRING;
			aRdnAttrs[0].Value.pbData=(BYTE*)(LPCTSTR)lpFindParam->strCN;
			aRdnAttrs[0].Value.cbData=lpFindParam->strCN.GetLength();
			rdn.cRDNAttr=sizeof(aRdnAttrs)/sizeof(aRdnAttrs[0]);
			rdn.rgRDNAttr=&aRdnAttrs[0];
			//NMS : ��������� ������ ������
			dwFindType=CERT_FIND_SUBJECT_ATTR;
			pFindParam=&rdn;
		}
		else
		{
			//NMS : ���� ������ �������� �����������,
			//		����� ���� �� ����
			if (cdbThumb.pbData!=NULL && cdbThumb.cbData>0)
			{
				bFindByThumb=true;
			}
			else
			{
				//NMS : �������� �������� �� ������ ��������� �����������
				if (ICPCryptoImpl::GetThumbFromStr(lpFindParam->strCN,&cdbThumb))
				{
					//NMS : ������� ��������� ��������������, ��� ��� ������
					//		��� ���� ���������� ����������� ����� new.
					AutoClearThumb.Attach(cdbThumb.pbData,false);
					bFindByThumb=true;
				}
			}
			if (bFindByThumb)
			{
				//NMS : ����� ����������� ����� �� ��������� �����������
				dwFindType=CERT_FIND_SHA1_HASH;
				pFindParam=(void*)&cdbThumb;
				//#ifdef _DEBUG
				//NMS : � Debug ������ ����� �������� ��������� � ���� ������
				CBinData bdThumb(cdbThumb.pbData,cdbThumb.cbData);
				CString strThumbInHex;
				bdThumb.Encode2Hex(strThumbInHex);
				strThumbInHex.MakeUpper();
				//NMS : ���� ��������� ����� 40 ��������,
				//		�������� ������� ����� ������ 4 �������
				const long nThumbLen=strThumbInHex.GetLength();
				if (nThumbLen==40)
				{
					for(long nSpace=1;nSpace<=9;nSpace++)
					{
						strThumbInHex.Insert(nThumbLen-(nSpace*4),_T(' '));
					}
				}
				//NMS : ����� � ���
				WriteToLog(_T("����� ����������� ����� ������������� �� ��������� : \"%s\"."),strThumbInHex);
				//#endif
			}
			else
			{
				//NMS : ����� ����������� ����� �� ���� CN
				dwFindType=CERT_FIND_SUBJECT_STR_A;
				pFindParam=(void*)(LPCSTR)lpFindParam->strCN;
			}
		}
		//NMS : ���� ������ ������������		
		for(;;)
		{		
			pCertContext=::CertFindCertificateInStore(hStore,
				PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
				0x00,
				dwFindType,
				pFindParam, 
				pCertContext);
			//NMS : ���� NULL ��� ������, ��� � ��������� ��� ������������
			if (pCertContext==NULL)
			{
				break;
			}
			//NMS : � ������ ����� ������, ����� ���������� �����
#ifdef _DEBUG
			WriteToLog(_T("������ ���������� : \"%s\"."),
				CertGetName(pCertContext));
#endif //_DEBUG	
			if (dwFindType==CERT_FIND_SUBJECT_STR_A)
			{//NMS : ������� �������� �� CN, ��� ����� ���� ������
				//NMS : �������� CN
				CString strCN;
				const LONG nCNLen=1024;
				TCHAR szCN[nCNLen]={0};
				CertGetNameString(pCertContext,CERT_NAME_ATTR_TYPE,0x00,
					szOID_COMMON_NAME,&szCN[0],nCNLen-1);
				strCN=&szCN[0];
				if (strCN.CompareNoCase(lpFindParam->strCN)!=0)
				{
#ifdef _DEBUG
					WriteToLog(_T("C��������� �� ������ �������� �� CN, ������ ���� \"%s\", � � ����������� ������ \"%s\" !"),
						lpFindParam->strCN,strCN);
					
#endif //_DEBUG
					continue;
				}
			}
			//NMS : ��������, ��������, ���� ����� ���������
			CString sKeyAlgID=pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
			if (sKeyAlgID.Find("1.2.643.2.2.")!=0)
			{
				WriteToLog(_T("���������� �� ������ �������� �� KeyAlgID, ������� KeyAlgID ����� \"%s\" !"),sKeyAlgID);
				continue;
			}
			//NMS : �������� ��������� CN, ���� �� �����
			if (!m_strRootCN.IsEmpty())
			{
				CString strIssuer=CertNameBlob2Str(&pCertContext->pCertInfo->Issuer);
				CString strRootCN(m_strRootCN);
				strIssuer.MakeLower();
				strRootCN.MakeLower();
				if (strIssuer.Find(strRootCN)<0)
				{
					WriteToLog(_T("���������� �� ������ �������� �� Root CN !"));
					continue;
				}
			}
			//NMS : �������� ��������� �����������, ���� ��� ����� ���������
			if (bFindByThumb==false && //NMS : ������ ���� ���������� ����������� �� �� ��������� !
				lpFindParam->cdbThumb.cbData>0 &&
				lpFindParam->cdbThumb.pbData!=NULL)
			{
				CRYPT_DATA_BLOB bThumbCert;
				ZeroMemory(&bThumbCert,sizeof(CRYPT_DATA_BLOB));			
				//NMS : ������� �������� ���������			
				if (CertGetThumb(pCertContext,&bThumbCert)==false)
				{
					//NMS : ���, �� ������� �������� ��������� �����������, ��������� ���
					continue;
				}
				//NMS : ���������� ����������� ������� ���������� �������
				CCertAutoBytePtr pbDataPtr(bThumbCert.pbData,false);
				//NMS : ���������� ���������
				if (memcmp(lpFindParam->cdbThumb.pbData,
					bThumbCert.pbData,
					min(lpFindParam->cdbThumb.cbData,bThumbCert.cbData))!=0)
				{
					//NMS : ��������� �� �������, ���������
#ifdef _DEBUG
					WriteToLog(_T("���������� ����� ��������, ��� ��� ��������� �� ������� !"));
#endif //_DEBUG
					continue;
				}			
			}
			//NMS : �������� OID, ���� �� �� ������
			if (!lpFindParam->strOID.IsEmpty())
			{
				if (!CertCheckOID(pCertContext,lpFindParam->strOID))
				{
					//NMS : �� ������ �������� �� OID, ��������� � ���� ��� ����
					continue;
				}
			}
			//NMS : �������� ���������� �� ����������, � ��� �� 
			//		�������� ������� �����������		
			CERTVALIDPARAM ValidParam;
			if (lpFindParam->bSkipCertIsValid==FALSE &&
				(!CertIsValid(pCertContext,&ValidParam)))
			{
				//NMS : �� �������� ���������� ���������
				continue;
			}
			//NMS : ��������� � ������ ���������� ������������
			PCCERT_CONTEXT pCertContextDup=::CertDuplicateCertificateContext(pCertContext);
			ASSERT(pCertContextDup!=NULL);
			lstCertContext.AddTail(pCertContextDup);
		} // for
	} // ����� ������, ������������ ��������� � lstCertContext
	
	
	//NMS : ������ �������� ���������
	long nResult=CCPC_NoError;
	//NMS : ����� ������ ����������
	if (lstCertContext.GetCount()==1)
	{
		if (ppCertContext!=NULL)
		{
			//NMS : ������� ��������� ���������� �� ������
			(*ppCertContext)=lstCertContext.GetHead();
		}
	}
	else if (lstCertContext.GetCount()>1)
	{		
		//NMS : ���� ���������� ��������� �� ���� �������
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
		//NMS : ���� ���� ������� ������ ������ �����������, ����� �� ���� � ���
		const long nCertFind=lstCertContext.GetCount();
		if (nCertFind>1)
		{
			//NMS : ����� � ���
			WriteToLog(_T("��� ������ ����������� �� \"%s\" ���� ������� %d �������� �����������(��), ��� ����������� ������������� ���������� ������ ���������� !"),
					   (LPCTSTR)lpFindParam->strCN,nCertFind);
		}
		*/
		//NMS : ���������� ������ ���������� ��� ����������.
		//		���� ������������� �����, ����� �� ���� �� ������
		if (lpFindParam->bSelAllCert==FALSE)
		{		
			pCertContext=NULL;
			pos=lstCertContext.GetHeadPosition();
			while(pos!=NULL)
			{
				pCertContext=lstCertContext.GetNext(pos);
				if (pCertContextSel==pCertContext)
				{
					//NMS : �������� ������� ������� �� ����� !
					continue;
				}
				::CertFreeCertificateContext(pCertContext);
			}
		}
#ifdef _DEBUG
		WriteToLog(_T("�� ��������� ������������ ������ : \"%s\"."),CertGetName(pCertContextSel));		
#endif //_DEBUG
		//NMS : ��������
		if (ppCertContext!=NULL)
		{
			//NMS : ������� ��������� ���������� �� ������
			(*ppCertContext)=pCertContextSel;
		}
		//NMS : ����� ������ � ���, � ���, ����� ���������� ��� ������
		if (pCertContextSel!=NULL && lpFindParam->bSelAllCert==FALSE)
		{			
			COleDateTime CertTimeAfter(pCertContextSel->pCertInfo->NotBefore);
			WriteToLog(_T("�� %d ������������, ��� ������ ���������� ������� �� ���� �������, ������� ������������ � %s."),
					   nCerts,
					   CertTimeAfter.Format(_T("%d-%m-%Y %H:%M:%S")));
			m_strLastError.Empty();
		}
		//NMS : ��������� ��������� ������ �������
		nResult=CCPC_NoError;
	}
	else
	{
		//NMS : ��������� ��������� ������ �������
		nResult=CCPC_CertNotFind;		
	}
	//NMS : ���� ������� ������������� ����� ������������,
	//		�� ������ ��� ������� ������ ������������ ����������
	//		������� �� � �������������� ������, ���� ��������� 
	//		�������� ������� CCPC_NoError
	if (nResult==CCPC_NoError && lpFindParam->bSelAllCert!=FALSE)
	{		
		//NMS : ������� � ������
		pCertContext=NULL;
		POSITION pos=lstCertContext.GetHeadPosition();
		while(pos!=NULL)
		{
			pCertContext=lstCertContext.GetNext(pos);
			lpFindParam->arrCerts.Add(pCertContext);
		}
		//NMS : ����� ������ � ���, ������� ������� ������������
		WriteToLog(_T("��� ������������� ������ ������������, ���� ������� ������������: %d"),lpFindParam->arrCerts.GetSize());
		m_strLastError.Empty();
	}
	//NMS : �������� ������
	lstCertContext.RemoveAll();
	//NMS : ���������� ����� !
	return m_LastErrorCode = nResult;
}

//NMS : ��������� �������� ��������� �����������
bool ICPCryptoImpl::CertGetThumb(PCCERT_CONTEXT pCertContext,CRYPT_DATA_BLOB* pThumb)
{
	ASSERT(pCertContext!=NULL);
	ASSERT(pThumb!=NULL);
	bool bResult=false;
	if (pCertContext!=NULL &&
		pThumb!=NULL)
	{
		//NMS : ��������
		ZeroMemory(pThumb,sizeof(CRYPT_DATA_BLOB));
		//NMS : �������� ����� ���������
		if (CertGetCertificateContextProperty(pCertContext,
											  CERT_SHA1_HASH_PROP_ID,
											  NULL,
											  &pThumb->cbData))
		{
			//NMS : �������� ����� ���������, ������� ������ ��� ���� � ������� ��� ���������
			pThumb->pbData=new BYTE[pThumb->cbData];
			ASSERT(pThumb->pbData!=NULL);
			bResult=true;
			if (!CertGetCertificateContextProperty(pCertContext,
												   CERT_SHA1_HASH_PROP_ID,
												   pThumb->pbData,
												   &pThumb->cbData))
			{
				WriteToLog(_T("ICPCryptoImpl::CertGetThumb => �� ������� ��������� ��������� � ����������� !"));
				delete[] pThumb->pbData;
				pThumb->pbData=NULL;
				pThumb->cbData=0x00;
				bResult=false;
			}
		}
		else
		{
			WriteToLog(_T("ICPCryptoImpl::CertGetThumb => �� ������� ��������� ����� ��������� ����������� !"));
		}
	}
	else
	{
		WriteToLog(_T("ICPCryptoImpl::CertGetThumb => �������� ��������� ��������� !"));
	}
	return bResult;
}

//NMS : ��������� ����������, � ��� �� ��� ������� ������������ �� ����������
bool ICPCryptoImpl::CertIsValid(PCCERT_CONTEXT pCertContext,
								PCERTVALIDPARAM pValidParam)
{
	ASSERT(pCertContext!=NULL);
	ASSERT(pValidParam!=NULL);
	//NMS : �������� ����� ������������� � 1 ������, ��
	//		���� CLR �����, ����� ��������� CLR ��� SST
	//		� ���������� �������� ��� ���.
	bool bResult=FALSE;
	//NMS : ������������� �������� ����������� � ��� ������� ��� ������� ���������
	
	int nResult = CCPC_NoError;

	bResult=CertIsValidEx(pCertContext,pValidParam);
	nResult = pValidParam->nResultCode;

	//NMS : ���� �������� ����������� �������, ����� ������� �� �����
	if (bResult && (pValidParam->nResultCode==CCPC_NoError)) // ��� ������ - ������� �����
	{
		return true;
	}
	//NMS : �������� �����������,  ������ ��� ����� CLR,
	//		����� �������� CLR � ��������� �������.
	if (pValidParam->bExpiredCRL==TRUE || 
		pValidParam->nResultCode==CCPC_CrlNotValid ||
		pValidParam->nResultCode==CCPC_CantVerifyCRL)
	{
#ifdef CTHREAD_UPDATE_CRL
		//NMS : ��������� CRL'�� ��� ��������� �����������, �� ������ ��� � SST
		nResult = CertUpdateCRLs(pCertContext);
		pValidParam->nResultCode = nResult;
#else
		nResult = CCPC_NoError;
#endif //
	}

	if (nResult==CCPC_NoError)
	{
	//NMS : �������� �������� ��� ���
		bResult=CertIsValidEx(pCertContext,pValidParam);
		nResult = pValidParam->nResultCode;
	}

	if (pValidParam->nResultCode==CCPC_CrlNotValid ||
		pValidParam->nResultCode==CCPC_CantVerifyCRL||
		pValidParam->nResultCode==CCPC_CantUpdateCrl)
	{
		WriteToLog("�� ������� �������� CRL ��� ����������� %s, �� ������������� ���������",
			CertGetName(pCertContext));
		bResult = CertVerifyDateValid(pCertContext);
	}
	pValidParam->nResultCode = nResult;
	return bResult;
}

//NMS : ��������� ���������� �� CRL
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
		WriteToLog(_T("�������� CRL ��� ������������ ��������� ����������� !"));
		return true;
	}
	
	pValidParam->nResultCode = CCPC_CantVerifyCRL;

	bool bResult=true;
	//NMS : ���� � ���, ��� � ����������� ���� �������� CLR
	bool bHasValidCRL=false;
	//NMS : ���� � ���, ��� � ����������� ���� CLR
	bool bHasCRL=false;
	//NMS : ������� ���-�� CRL
	LONG nCRLCount=0;
	//NMS : ��������� �� ��������� CLR
	PCCRL_CONTEXT pCRL=NULL;
	//NMS : ����� �� ������� CLR'��.

#ifdef CTHREAD_UPDATE_CRL
	if (NULL!=m_pCPCryptoCallBack && bReadOnly==FALSE)
	do
	{			
		// KAA : ���������� CRL �� ������� ���������, ���� FALSE - ���������� � SST
		m_pCPCryptoCallBack->OnCertGetCRL(pIssuerCertContext,pCRL,bReadOnly);
		
		if (pCRL==NULL)
		{
			//NMS : ���� ��� �� ������ CRL
			if (nCRLCount==0)
			{	
				bHasCRL=false;
				bHasValidCRL=false;
			}
			//NMS : � ����������� ��� CLR
			
			break;
		}
		if (!bResult)
			continue;

		bHasCRL=true;// ���� CRL !!!
		++nCRLCount;
		
		// KAA : �������� ���������� CRL �� ����
		COleDateTime dtUpdate = pCRL->pCrlInfo->ThisUpdate;
		COleDateTime dtNextUpdate = pCRL->pCrlInfo->NextUpdate;
		if (!((dtNextUpdate>COleDateTime::GetCurrentTime()) && 
			(dtUpdate<COleDateTime::GetCurrentTime())))
		{
			WriteToLog(_T("CRL \"%s\" ��� �� �� �������������, ����� ����������!"),
				CertGetName(pCRL));
			bHasValidCRL = false;
		}
		else
		{
			WriteToLog(_T("CRL \"%s\" ��� �� �������������"),
				CertGetName(pCRL));
			//NMS : ������� ����� ���������� � CLR
			PCRL_ENTRY pEntry=NULL;
			::CertFindCertificateInCRL(pCertContext,pCRL,0,NULL,&pEntry);
			if (pEntry!=NULL)
			{
				//NMS : ���������� ������� (������ � CLR)
				bResult=false;
				pValidParam->nResultCode=CCPC_CertNotValid;
				WriteToLog(_T("C��������� \"%s\" ������� (������ � CLR) !"),
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
// KAA : ���������� CRL � SST
		
		pCRL=::CertGetCRLFromStore(hStore,pIssuerCertContext,pCRL,&dwCLRFlags);

		if (pCRL==NULL)
		{
			//NMS : ���� ��� �� ������ CRL
			if (nCRLCountSST==0)
			{	
				bHasCRL=false;
				bHasValidCRL=false;
			}
			//NMS : � ����������� ��� CLR

			break;
		}
		if (!bResult)
			continue;

		bHasCRL=true;// ���� CRL !!!
		++nCRLCountSST;
		
		// KAA : �������� ���������� CRL �� ����
		if (0!=CertVerifyCRLTimeValidity(NULL, pCRL->pCrlInfo))
		{
			WriteToLog(_T("CRL \"%s\" ��� ��������� %p �� �������������, ����� ����������!"),
					   CertGetName(pCRL),hStore);
			bHasValidCRL = false;
		}
		else
		{
			WriteToLog(_T("CRL \"%s\" ��� ��������� %p �������������"),
					   CertGetName(pCRL),hStore);

			bHasValidCRL=true; // ���� ��������������

			//NMS : ������� ����� ���������� � CLR
			PCRL_ENTRY pEntry=NULL;
			::CertFindCertificateInCRL(pCertContext,pCRL,0,NULL,&pEntry);
			if (pEntry!=NULL)
			{
				//NMS : ���������� ������� (������ � CLR)
				bResult=false;
				pValidParam->nResultCode=CCPC_CertNotValid;
				WriteToLog(_T("C��������� \"%s\" ������� (������ � CLR) !"),
					CertGetName(pCertContext));
				continue;
			}
		}
	}
	while (pCRL!=NULL);

	if (!bResult && pValidParam->nResultCode == CCPC_CertNotValid)
		return bResult;
	
	//NMS : ��� CRL ���  ��� ���������, ����� ��������� CRL, �� ������ ���
	//		������ ���� �� �� ��������� � ������ ������ ��� ������.	
	if ((bReadOnly==FALSE) && (!bHasCRL || (bHasCRL  && !bHasValidCRL)))
	{
		//NMS : ������ CLR'�� ����,� ��������� �� ������ �� �����
		bResult=false;
		pValidParam->nResultCode=CCPC_CrlNotValid;
		pValidParam->bExpiredCRL=TRUE;
		if (!bHasCRL)
			WriteToLog(_T("�� ������ CRL ��� �������� %s !"),
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

//NMS : ��������� ����������, � ��� �� ��� ������� ������������
//		�� ���������� ��� ����������� ���������
bool ICPCryptoImpl::CertIsValidEx(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam)
{	
	ASSERT(pValidParam!=NULL);
	//NMS : �������
	pValidParam->Reset();	
	//NMS : �������� ���������, � ����� �� ��������� ���������� �����������
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("�������� ���������� ����������� ��������� �����������, ������� ��� ����������� ��������� ��������� !"));
		m_strLastError.Empty();
		return TRUE;
	}
	ASSERT(pCertContext!=NULL);
	//NMS : ��������� Subject � �����������
	CString strSubject=CertGetName(pCertContext);
	//NMS : ��������� �������� ����� �����������
	CBinData bdCertSerialNo(pCertContext->pCertInfo->SerialNumber.pbData,
							pCertContext->pCertInfo->SerialNumber.cbData);
#ifdef _DEBUG
	//NMS : ����� ������ � ���, ��� ���������� ������� ��� ������������ ������ ��, �� ������ � �������
	WriteToLog(_T("����� ICPCryptoImpl::CertIsValidEx => ��� ����������� : \"%s\"."),strSubject);
#endif//_DEBUG
	//NMS : ����� �������, ���������� ���, ��� ��� ������ � ��� ����� ��������
	CTimeSpan ts=CTime::GetCurrentTime()-m_tValidCache;
	if (ts.GetTotalMinutes()>=5) // ����� ����� 5 ����� - ����� �������� ����
	{
		m_lstCertValid.RemoveAll();
	}
	//NMS : ��������� ����� ���������� ����
	m_tValidCache=CTime::GetCurrentTime();
	//NMS : ���������, � ��� �� � ���� ������ �����������
	POSITION pos=m_lstCertValid.GetHeadPosition();
	while(pos!=NULL)
	{
		CBinData& bdSerialNoNow=m_lstCertValid.GetNext(pos);
		if (bdSerialNoNow==bdCertSerialNo)
		{
			WriteToLog(_T("���������� \"%s\" ������ � ���� �������� ������������ !"),strSubject);			
			return true;
		}
	}	
	//NMS : ����� ��������� ���������� �� ������ ���������
	bool bResult=false;
	
	int nResult = CertCheckChain(pCertContext,pValidParam);

	if (CCPC_NoError==nResult) // ������� ������������� � CRL ����
	{
		WriteToLog(_T("������� ����������� \"%s\" ������������� !"),CertGetName(pCertContext));
		//NMS : ���� ���������� �������� �������, ����� �������� ��� ���� ��������
		bResult = CertVerifyDateValid(pCertContext);
		//NMS : ���� ���������� �������� ������� ��� � ���
		if (bResult)
		{		
			m_lstCertValid.AddTail(bdCertSerialNo);
			m_strLastError.Empty();
			pValidParam->Reset();
		}	
	}
	else if (nResult==CCPC_CantVerifyCRL || nResult==CCPC_CrlNotValid)
	{
		WriteToLog(_T("CRL ��� ����������� \"%s\" �� ������������� !"),CertGetName(pCertContext));
		bResult = CertVerifyDateValid(pCertContext); // KAA: ������ �������� ������ �� �������
	}
	else
	{
		WriteToLog(_T("������� ����������� \"%s\" �� �������������, �� �������: ") + m_strLastError,CertGetName(pCertContext));
 		bResult = false;// KAA: ���������� �� ������������, �.�. �� ������� ��������� �������� �������
	}
	//NMS : ��������� ���������
	return bResult;
}

//NMS : ��������� �������� �� ������ ��������� �����������
/*static*/ bool ICPCryptoImpl::GetThumbFromStr(CString strThumb,CRYPT_DATA_BLOB* pThumb)
{
	//NMS : ������� pThumb, ���� ���� pThumb
	if (pThumb!=NULL)
	{
		ZeroMemory(pThumb,sizeof(CRYPT_DATA_BLOB));	
	}
	//NMS : ���� ��������� ������, �������
	if (strThumb.IsEmpty())
	{
		return false;
	}	
	//NMS : �������� ��������� :
	//		���� ����� ������ ��������� ������ 40 ��������, ����� ����� ������� ��� �������
	//		� ����� ����� ����� ������ ���� ����� 40, ���� ��� �� ��� ��� �� ���������.
	//		���� ����� ������ ��� 40 ��������, ����� ����� �������������� �� HEX � BIN.
	//NMS : ��������� �����, ���� ������ 40 �������� ������� �������
	if (strThumb.GetLength()>40)
	{
		//NMS : ������� �������
		strThumb.Replace(_T(" "),_T(""));
	}
	bool bResult=false;
	//NMS : ���� ����� ������ 40 ��������, �����
	//		������������ �� HEX � BIN
	if (strThumb.GetLength()==40)
	{
		//NMS : �������� �������������� HEX � BIN
		CBinData bd;
		if (bd.FillFromHex(strThumb) && bd.Size()>0)
		{
			//NMS : ���� ������� ���������������,
			//		��������� ��������� pThumb,
			//		���� pThumb ����, ����� ������
			//		���������� �����.
			if (pThumb!=NULL)
			{
				//NMS : �������� ������
				BYTE* pBytes=new BYTE[bd.Size()];
				ASSERT(pBytes!=NULL);
				if (pBytes!=NULL)
				{
					//NMS : ������������� ������ � �������� ������
					pThumb->cbData=bd.Size();
					CopyMemory(pBytes,bd.Buf(),bd.Size());
					pThumb->pbData=pBytes;
					//NMS : ������������� �����
					bResult=true;
				}
			}
			else
			{
				//NMS : ������������� �����
				bResult=true;
			}
		}
	}
	return bResult;
}

//AKV : ��������� �� ��������� ����������� ������
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

//NMS : ������������ ������� OID'�
void ICPCryptoImpl::CorrectOIDPrefix(CString& strOID,CString strReplacePrefix)
{
	//NMS : ���� OID ������ �� ���� �� ������
	if (strOID.IsEmpty())
	{
		return;
	}
	//NMS : ��������� ��� �������
	if (!CStringProc::HavePrefix(strOID,strReplacePrefix))
	{
		//NMS : ������ ������� �� ���, ������� ����� � ��������
		strOID.Delete(0,min(strOID.GetLength(),strReplacePrefix.GetLength()));
		//NMS : ������ ������� �� ��������
		strOID.Insert(0,strReplacePrefix);
	}
}

//NMS : ��������� �������� OID �� ���������.
//NMS : �� ��������� ������ OID, ������� ����������� Taxcom 1.2.643.3.22
CString ICPCryptoImpl::GetDefaultOID(void)
{
	CString strResult;
	//NMS : ������ ����� ��������� � strRight, � ������ � strLeft
	CString strLeft(_T("4332e332e3232")),strRight(_T("312e322e363"));
	//NMS : ��������
	const CString strHex=strRight+strLeft;
	//NMS : ����������� � ������
	CBinData bd;
	if (bd.FillFromHex(strHex))
	{
		strResult=CString((TCHAR*)bd.Buf(),bd.Size());
	}
	//NMS : ���������� ������
	return strResult;
}


//NMS : ������� ��������� ��������� �� INI �����
void ICPCryptoImpl::LoadSettings(void)
{	
//NMS : ����������� ��� ����� ��������
#define SECT_SETTINGS_NAME _T("Settings")
#define KEY_SETTINGS_VERSION _T("Version")
#define KEY_SETTINGS_USINGCUSTOMOPTIONS _T("UsingCustomOptions")
#define KEY_SETTINGS_SKIPUPDATECRL _T("SkipUpdateCRL")
#define KEY_SETTINGS_SKIPCHECKCERTVALID _T("SkipCheckCertValid")
#define KEY_SETTINGS_SKIPUPDATECRLININIT _T("SkipUpdateCRLInInit")
#define KEY_SETTINGS_SKIPCHECKCRL _T("SkipCheckCRL")
#define KEY_SETTINGS_OFFLOGFILE _T("OffLogFile")
#define KEY_SETTINGS_SKIPCHECKTIMEREMAINS _T("SkipCheckTimeRemains")
//NMS : ������ ����������� �������� �� INI � BOOL
#define INIVALUE_2_BOOL(ini,key_name,def_val) _ttoi(ini.GetValue(SECT_SETTINGS_NAME,key_name,LONG_2_STR(def_val)))
//NMS : ������ �������������� ����� � ������
#define LONG_2_STR(nValue) CStringProc::Format(_T("%d"),nValue)
	//NMS : ���������� ���������
	m_Settings.Reset();	
	//NMS : ��������� ���� � ����� ��������
	CString strPF;

#ifdef CTHREAD_UPDATE_CRL
// KAA : �������� ���������� Dipost
	if (NULL!=m_pCPCryptoCallBack)
	{
		if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
			m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
		//NMS : �������� ��������� ����
		m_strRootPath.TrimRight(_T('\\'));	
	}
#endif // CTHREAD_UPDATE_CRL

	// �������� ��� ��� ���������?
	m_IsReferent = FALSE;
	CIniMng iniS;
	CString strStartupFile;
	
	strStartupFile.Format(_T("%s\\app.info"),m_strRootPath);
	iniS.Open(strStartupFile);
	CString AppName = iniS.GetValue("Application","Name");
	AppName.MakeLower();
	if (AppName.Find("referent")>=0)
		m_IsReferent = TRUE;
	// ���� �������� ������� ��������� �����������
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
	//NMS : �������� ��������� �����
	CIniMng ini;
	ini.Open(strPF);
	//NMS : ������� � �������� �� ��������� ������
	m_Settings.bUsingCustomOptions=INIVALUE_2_BOOL(ini,KEY_SETTINGS_USINGCUSTOMOPTIONS,m_Settings.bUsingCustomOptions);
	//NMS : ���� �������� ������ �� �� �����	
	if (m_Settings.bUsingCustomOptions!=FALSE)
	{
		WriteToLog(_T("��������� ����� ������� �� ����� CPCrypto.ini."));
		//NMS : ������ ���������
		m_Settings.bSkipUpdateCRL=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPUPDATECRL,m_Settings.bSkipUpdateCRL);
		m_Settings.bSkipCheckCertValid=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKCERTVALID,m_Settings.bSkipCheckCertValid);
		m_Settings.bSkipUpdateCRLInInit=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPUPDATECRLININIT,m_Settings.bSkipUpdateCRLInInit);
		m_Settings.bSkipCheckCRL=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKCRL,m_Settings.bSkipCheckCRL);
		m_Settings.bOffLogFile=INIVALUE_2_BOOL(ini,KEY_SETTINGS_OFFLOGFILE,m_Settings.bOffLogFile);
		m_Settings.bSkipCheckTimeRemains=INIVALUE_2_BOOL(ini,KEY_SETTINGS_SKIPCHECKTIMEREMAINS,m_Settings.bSkipCheckTimeRemains);

	}
	else
	{
		WriteToLog(_T("����� �������������� ��������� �� ���������, ������ ��� �������� ����� UsingCustomOptions � ����� \"CPCrypto.ini\" ����� \"0\"."));
	}
	//NMS : �������� ��������� ������
	m_strLastError.Empty();
	//NMS : ��������� ���������, ������ �������� �� � ����, ���
	//		����� ������ ����� �����, ������� ����� ���������	
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_VERSION,LONG_2_STR(2));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_USINGCUSTOMOPTIONS,LONG_2_STR(m_Settings.bUsingCustomOptions));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPUPDATECRL,LONG_2_STR(m_Settings.bSkipUpdateCRL));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKCERTVALID,LONG_2_STR(m_Settings.bSkipCheckCertValid));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPUPDATECRLININIT,LONG_2_STR(m_Settings.bSkipUpdateCRLInInit));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKCRL,LONG_2_STR(m_Settings.bSkipCheckCRL));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_OFFLOGFILE,LONG_2_STR(m_Settings.bOffLogFile));
	ini.SetValue(SECT_SETTINGS_NAME,KEY_SETTINGS_SKIPCHECKTIMEREMAINS,LONG_2_STR(m_Settings.bSkipCheckTimeRemains));
	//NMS : ��������� ��������� � ����
	ini.Save();	
}


bool ICPCryptoImpl::CertVerifyDateValid(PCCERT_CONTEXT pCert)
{
	//NMS : �������� ���������, � ����� �� ��������� ���������� �����������
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("�������� ���������� ����������� ��������� �����������, ������� ��� ����������� ��������� ��������� !"));
		m_strLastError.Empty();
		m_LastErrorCode = 0;
		return true;
	}

	COleDateTime tmNow=COleDateTime::GetCurrentTime();
	if (tmNow<pCert->pCertInfo->NotBefore)
	{				
		m_strLastError.Format(_T("���� �������� ����������� \"%s\" ��� �� �������� !"),
				   CertGetName(pCert));
		WriteToLog(m_strLastError);
		m_LastErrorCode = CCPC_CertNotValid;
		return false;
	}

	if(tmNow>pCert->pCertInfo->NotAfter)
	{
		m_strLastError.Format(_T("���� �������� ����������� \"%s\" ����� !"),
				   CertGetName(pCert));
		WriteToLog(m_strLastError);
		m_LastErrorCode = CCPC_CertNotValid;
		return false;
	}
	return true;
}

int ICPCryptoImpl::CertCheckCertRemain(PCCERT_CONTEXT pSigner)
{
	//NMS : �������� ���������, � ����� �� ��������� ���������� �����������
	if (m_Settings.bSkipCheckCertValid==TRUE)
	{
		WriteToLog(_T("�������� ���������� ����������� ��������� �����������, ������� ��� ����������� ��������� ��������� !"));
		m_strLastError.Empty();
		return CCPC_NoError;
	}
	if (m_Settings.bSkipCheckTimeRemains==TRUE)
	{
		WriteToLog(_T("�������� ����� �������� ����������� ��������� �����������"));
		m_strLastError.Empty();
		return CCPC_NoError;
	}
	
	if (NULL==pSigner) 
		return m_LastErrorCode = CCPC_CantFindCertInStore;

	COleDateTime dtAfter = COleDateTime(pSigner->pCertInfo->NotAfter);
	COleDateTime dtNow = COleDateTime::GetCurrentTime();
	COleDateTimeSpan dtCountDays = dtAfter - dtNow;
	// ������� ���� ����� ������� ������ �� ���� ��� ����� �������
	long nCountOfDays = long(dtAfter.m_dt)-long(dtNow.m_dt);
	
	if (nCountOfDays<0) 
		return CCPC_CertNotValid;

	if ((dtCountDays.m_span<=7.0) && (m_IsReferent==TRUE))
	{
	// ��������� ��������� � �������� ��� � ����
		CRYPT_DATA_BLOB blob = {0};

		CString strSignerCN = GetCNFromCert(pSigner);
		CString strSignerThumb;
		if (CertGetThumb(pSigner, &blob))
		{
			GetStrFromThumb(&blob, strSignerThumb);
			delete[] blob.pbData;
		}

#ifdef CTHREAD_UPDATE_CRL
// KAA : �������� ���������� Dipost
		if (NULL!=m_pCPCryptoCallBack)
		{
			if (!m_pCPCryptoCallBack->GetDipostDir().IsEmpty())
				m_strRootPath = m_pCPCryptoCallBack->GetDipostDir();
			//NMS : �������� ��������� ����
			m_strRootPath.TrimRight(_T('\\'));	
		}

		CINIFile ini;
		ini.Load(m_strRootPath+"\\remains.ini");
		CTime tmLastUpdate((time_t)ini.ReadINIInt("certs","LastUpdate",0));
		if (CTimeSpan(CTime::GetCurrentTime()-tmLastUpdate).GetDays()>7) 
			ini.DeleteINISection("certs");
			
		int nLastCountOfDays  = ini.ReadINIInt("certs",strSignerThumb,-1);
		if (nLastCountOfDays == nCountOfDays){ // �� ��� ���������� ������� �������
			return CCPC_NoError;
		}else{ // �������� �����
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
					sPrefix.Format("�� %d ����",nCountOfDays);break;
				}
				else
				{
					switch(dtCountDays.GetHours())
					{ 
					case 0: sPrefix = "��� ������ 1 ����";break;
					case 21:
					case 1: sPrefix.Format("�� %d ���", dtCountDays.GetHours());break;
					case 2:
					case 3:
					case 22:
					case 23:
					case 4: sPrefix.Format("��� %d ����", dtCountDays.GetHours());break;
					default: sPrefix.Format("��� %d �����", dtCountDays.GetHours());break;
					}
				}
				break;
			}
		case 2:
		case 3:
		case 4: sPrefix.Format("��� %d ���",nCountOfDays);break;
		default: sPrefix.Format("��� %d ����",nCountOfDays);break;
		}
		m_strLastError.Format ("�� ��������� ����� �������� ����������� �����%s",sPrefix);
		WriteToLog(m_strLastError);
		AFX_MANAGE_STATE(AfxGetStaticModuleState());
		CString strText;
		strText = "��������: " + m_strLastError + "\r\n"
			"����������� ��� ��������� ��������������� �� ����������, ������������ �����,\r\n"
			"� ����� ��������� ����� ����������, �������� ������ ���������� "+ CertGetName(pSigner,FALSE)+"\r\n"
			"(�������� ���������� �� ������ �����������: http://www.taxcom.ru/centr/abonentam/ )\r\n"
			"\r\n"
			"���� �� ������ ��������� ���������� � �������������� ������ ���� �������� ������ \r\n"
			"����������� ����� ���������, �� ����� ���������� ���������� �� �����.\r\n"
			"\r\n"
			"�� ��� ����� ������ ��������� ��������?\r\n"
			"������� �� - ��� �����������, ��� - ��� ������ ��������";
		if (::MessageBox(NULL,strText,m_strLastError,MB_ICONWARNING+MB_YESNO)==IDYES) 
		{
			// ������� � ��� ����������
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