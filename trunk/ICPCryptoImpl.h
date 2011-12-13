#pragma once;

#ifndef ICPCRYPTOIMPL_H
#define ICPCRYPTOIMPL_H

#if _MSC_VER > 1000
	#pragma once
#endif // _MSC_VER > 1000

#include <vector>
#include <afxtempl.h>
#include "LogFile.h"
#include "BinData.h"
#include "StringArrayEx.h"
#include "FileMng.h"
#include "CBase64Utils.h"
#include "IniMng.h"

// My additionals
#define CCPC_NoError 0
#define ICPCryptoCallBack void
#define KILL_STREAM_INTERFACE

class 	CERTFINDPARAM 
{
public:
	DWORD dwFindInStore;
	
	CString strCN;
	CString strOID;
	
	PCCERT_CONTEXT pCertPrev;
	CRYPT_DATA_BLOB cdbThumb;
	
	BOOL bSelAllCert;
	BOOL bSelFromAllStores;
	BOOL bSkipCertIsValid;

	CArray<PCCERT_CONTEXT, PCCERT_CONTEXT> arrCerts;
	
	CERTFINDPARAM()
	{
		dwFindInStore = 0;
		pCertPrev = NULL;
		bSkipCertIsValid = TRUE;
		bSelFromAllStores = TRUE;
		bSelAllCert = TRUE;
		cdbThumb.cbData = 0;
		cdbThumb.pbData = 0;
	}

	void ClearArrCerts() 
	{
		arrCerts.RemoveAll ();	
	};

	BOOL IsSetThumb () const
	{
		return TRUE;
	}
};

#define LPCERTFINDPARAM CERTFINDPARAM*

#ifndef KILL_STREAM_INTERFACE
#include <assert.h>
#endif

//NMS : ��������� �������� CN �����������
CString GetCNFromCert(PCCERT_CONTEXT pCert);

class CCertCloseCache;
class CCertLockMethods;

//NMS : ���������

typedef struct _TAGCERTVALIDPARAM
{
//NMS : ������
	_TAGCERTVALIDPARAM()
	{
		Reset();
	}

	void Reset(void)
	{
		nResultCode=CCPC_NoError;		
		bExpiredCRL=FALSE;		
	}
//NMS : �����������
	LONG nResultCode;			//NMS : �������������� ��� ��������	
	BOOL bExpiredCRL;			//NMS : �����-�� ��������� CRL
} CERTVALIDPARAM,*PCERTVALIDPARAM;

typedef struct _TAGCPCRYPTOSETTINGS
{
	_TAGCPCRYPTOSETTINGS()
	{	
		Reset();
	}

	void Reset(void)
	{
		bUsingCustomOptions=FALSE;
		bSkipUpdateCRL=TRUE;
		bSkipCheckCertValid=FALSE;
		bSkipUpdateCRLInInit=TRUE;
		bSkipCheckCRL=TRUE;
		bOffLogFile=FALSE;
		bSkipCheckTimeRemains = FALSE;
	}

//NMS : ����������
	//NMS : ���� � ���, ��� ����� ������������ ��������� �� �����
	BOOL bUsingCustomOptions;
	//NMS : ���� � ���, ��� ����� �� ��������� CRL ��� ���
	BOOL bSkipUpdateCRL;
	//NMS : ���� � ���, ����� �� ��������� ���������� �����������
	BOOL bSkipCheckCertValid;
	//NMS : ���� � ���, ��� ��� ������ CRL, ��������� �� �����
	BOOL bSkipUpdateCRLInInit;
	//NMS : ����, � ���, ��� �� ����� ��������� CRL ��� ������������
	BOOL bSkipCheckCRL;
	//NMS : ����, � ���, ��� ��� ������ �� �����
	BOOL bOffLogFile;

	BOOL bSkipCheckTimeRemains;
} CPCRYPTOSETTINGS,*PCPCRYPTOSETTINGS;

//NMS : ����� ��� �������� ��������,
// ����� ��������� ������ ����� �������
// CST_ - Cert store type
#define CST_SST		0x00000001
#define CST_MY		0x00000002
#define CST_ROOT	0x00000004
#define CST_OWNER	0x00000008

#define CST_ALL		(CST_SST|CST_MY|CST_ROOT) // ��� ������������� ���� ��� � �������

//NMS : ����� ��� ����������
#define CPF_FIND_SST_MY 0x00000001

class ICPCryptoImpl //: public ICPCrypto
{
	friend CCertCloseCache;
	friend CCertLockMethods;
	friend class CPhpCrypto;
public:
    virtual void release();
	ICPCryptoImpl();
	virtual ~ICPCryptoImpl();

//NMS : �������������
	virtual int Initialize (CString sRootPath,ICPCryptoCallBack* iCPCryptoCallBack=NULL);
	virtual BOOL IsInitialized();

//NMS : ������� ������ (ICPCryptoImpl_EDS.cpp)
	// sSender == Subject\tOID
	virtual int SignFileA(CString sSender, CString datasignFileName);
	virtual int SignFileD(CString sSender, CString dataFileName, CString signFileName);
 	virtual int CheckFileA(CString signFileName, CString dataFileName, CStringArray& saSignInfos, BOOL bShowDlg); // ���� dataFileName!="" �� � dataFileName ����� ���� ��� �������
 	virtual int CheckFileD(CString dataFileName, CString signFileName, CStringArray& saSignInfos, BOOL bShowDlg);

	// �������� ������� ������� (Subject\tOID) � �����
	// � sSenderInfo ������������ �������� Subject �����������
	virtual int CheckFileA(CString signFileName, CString& sSenderInfo);
	virtual int CheckFileD(CString dataFileName, CString signFileName, CString& sSenderInfo);

	virtual int UnpackSignedFile(CString datasignFileName, CString dataFileName);

	// saRecepientIDs == Array of (Subject\tOID)
	virtual int EncryptFile(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	virtual int DecryptFile(CString cryptoFileName, CString plainFileName);
/*
//NMS : �������������� ������ ������� ��������� ����� (ICPCryptoImpl_EDS2.cpp)
	virtual int SignFileAlt(CString sSender, CString datasignFileName);
	virtual int CheckFileAlt(CString datasignFileName, CStringArray& saSignInfos, BOOL bShowDlg);
	virtual int CheckFileAlt(CString datasignFileName, CString& sSenderInfo);
	virtual int UnpackSignedFileAlt (CString datasignFileName, CString dataFileName, CStringArray& saSigIDs, BOOL bRemoveSignatures);
	virtual int EncryptFileAlt(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	virtual int DecryptFileAlt(CString cryptoFileName, CString plainFileName);

//NMS : ��������������-2 (������ 345) ������ ������� ��������� ����� (ICPCryptoImpl_EDS_345.cpp)
	virtual int SignFileAlt2(CString sSender, CString dataFileName, CString signFileName);
	virtual int CheckFileAlt2(CString dataFileName, CString signFileName, CString& sSignInfo, BOOL bShowDlg);
	virtual int EncryptFileAlt2(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	virtual int DecryptFileAlt2(CString cryptoFileName, CString plainFileName);
*/	
//NMS : Tools (ICPCryptoImpl_Tools.cpp)
	virtual int ViewStore(CStringArray& saResult);
	virtual int UpdateCRLs();
	virtual int	AddCertToFile(CString sFile, CString sCertFile);
	virtual int	AddCertToFile(CString sFile, CRYPT_DATA_BLOB* pCert);
	virtual int	AddCRLToFile(CString sFile, CString sCRLFile);
	virtual int	AddCRLToFile(CString sFile, CRYPT_DATA_BLOB* pCRL);
	virtual int	AddCertToStore(CString sCertFile);
	virtual int	AddCertToStore(CRYPT_DATA_BLOB* pCert);
	virtual int	AddCRLToStore(CString sCRLFile);
	virtual int	AddCRLToStore(CRYPT_DATA_BLOB* pCRL);	
	virtual CString GetLastCryptoError();
    virtual std::string getLastError();
	//NMS : �������� ���������� ������ �� SST �����
	virtual int DelCertFromStore(CString strCN);
	//NMS : ��������� �������� ���������� �� ��������� �� subject,email,thumb
	virtual int GetCertFromStore(CString strSubjectOrEmail,CRYPT_DATA_BLOB* pCert);
//NMS :  Universal crypto function (ICPCryptoImpl_UniFunc.cpp)

	virtual int FindCertificate(LPCTSTR szThumbprint, PCCERT_CONTEXT& pCertContext);
	//KAA : ��������� ���������� �� ���������� ��� ��� �������� ��� ����������, ���������� CCPC_NoError ��� ��� ������
	virtual int CheckCertificate(const PCCERT_CONTEXT pCertContext);
	//KAA : �������� ��������� ������������ (� ������� HEX), �������������� ��� ���������� �� 141, ���������� CCPC_NoError ��� ��� ������
//	virtual int GetCertificateForDecryptFileAlt2(LPCTSTR szCryptedFileName, CRYPTALT2THUMBPRINTS* pCryptAlt2Thumbprints);

#ifdef CTHREAD_UPDATE_CRL
	virtual bool IsFoundUniFunc(CString sFuncName);
	virtual void UniFunc(CString sFuncName,CString sXMLIn,CString& sXMLOut);
#endif //

#ifndef KILL_STREAM_INTERFACE
    // LLP
    // ����������
    // recepientIDs == vector of (Subject\tOID)
    // cryptoStream - ������������� �����
    // plainFileName - �������������� ����� 
    virtual int encrypt(std::istream& plainStream, std::ostream& cryptoStream,
        std::vector<std::string>& recepientIDs, ICPCrypto::Cryptography crypt = Default);
    virtual int decrypt(std::istream& cryptoStream, std::ostream& plainStream, 
        ICPCrypto::Cryptography crypt = Default);
    
    virtual int signStreamAttach (const std::string &sender, std::istream& dataStream,
        std::ostream& datasignStream);
    virtual int signStreamDetach (const std::string &sender, std::istream& dataStream,
        std::ostream& signStream);

    virtual int signStreamAlt (const std::string &sender, std::istream& dataStream,
        std::ostream& datasignStream);
    virtual int signStreamAlt2 (const std::string &sender, std::istream& dataStream,
        std::ostream& signStream);

    virtual int checkStreamAttach (std::istream& signStreamName, std::ostream& dataStreamName,
        std::vector<std::string>& signInfos, bool bShowDlg);
    virtual int checkStreamDetach (std::istream& dataStreamName, std::istream& signStreamName,
        std::vector<std::string>& saSignInfos, bool bShowDlg);

    virtual int checkStreamAttach (std::istream& signStreamName, std::string& sSenderInfo);
    virtual int checkStreamDetach (std::istream& dataStreamName, std::istream& signStreamName,
        std::string& sSenderInfo);

    virtual int checkStreamAlt(std::istream& signStreamName, std::vector<std::string>& signInfos,
        bool bShowDlg);
    virtual int checkStreamAlt(std::istream& signStreamName, std::string& sSenderInfo);
    
    virtual int checkStreamAlt2(std::istream& dataStreamName, std::istream& signStreamName, 
        std::string& sSignInfo, bool bShowDlg);
#endif
protected:
public:
//NMS : ������
	int EncryptFileEx(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs, CArray<PCCERT_CONTEXT,PCCERT_CONTEXT> * pArrCertRcpt = NULL);
	int DecryptFileEx(CString cryptoFileName, CString plainFileName);
	int UnpackSignedFileEx(CString datasignFileName, CString dataFileName);

	int SignFileAltEx(CString sSender, CString datasignFileName);
	int CheckFileAltEx(CString datasignFileName, CStringArray& saSignInfos, BOOL bShowDlg);
	int CheckFileAltEx(CString datasignFileName, CString& sSenderInfo);
	int UnpackSignedFileAltEx (CString datasignFileName, CString dataFileName, CStringArray& saSigIDs, BOOL bRemoveSignatures);
	int EncryptFileAltEx(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	int DecryptFileAltEx(CString cryptoFileName, CString plainFileName);

	int SignFileAlt2Ex(CString sSender, CString dataFileName, CString signFileName);
	int CheckFileAlt2Ex(CString dataFileName, CString signFileName, CString& sSignInfo, BOOL bShowDlg);
	int EncryptFileAlt2Ex(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	int DecryptFileAlt2Ex(CString cryptoFileName, CString plainFileName);

	static void FreeCertsArray(CArray<PCCERT_CONTEXT,PCCERT_CONTEXT>& arrCertRcpt);
	// KAA : �������� ������ ���� OID
	bool CertGetOIDs(HCRYPTMSG hMsg, PCCERT_CONTEXT pCertContext,CStringArray& saOIDs);

	//NMS : ��������� �������� ��� �����������
	CString CertGetName(PCCERT_CONTEXT pCertContext,const BOOL bIssuer=FALSE);
	CString CertGetName(PCCRL_CONTEXT  pCrlContext);
	//NMS : ��������� ������� �����������
	int CertCheckChain(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pCertValidParam);
	//NMS : ��������� ��������� �� ������
	CString GetSystemErrorDesc(const DWORD dwError=::GetLastError());
	//NMS : ������� ��������� � ���� �������(���)
	void WriteToLog(LPCTSTR lpszFormat,...);
	//NMS : ��������� ��������� � ������� ����� ������ ����������
	int CertOpenStore(const DWORD dwType=CST_ALL,const bool bReOpen=false);
	//NMS : ��������� �������� ��������� ������������
	void CertCloseStore(const DWORD dwType=CST_ALL);
	//NMS : ��������� �������� ����� �� ���� �� �����
	HCERTSTORE CertGetHandleStoreByType(const DWORD dwType);
	//NMS : ��������� ������������� SST �����, ���� �� ����������
	//		�������, ������ ���� � ������ ����������.
	void CertStoreVerifyExistPath(CString strStoreFilePath);	
	//NMS : ��������� ���������� ��� CRL � ��������� (�� ������ ������ ��� ������ SST)
	int AddCertOrCRLToStore(const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
	//NMS : ��������� ���������� ��� CRL � ��������� ���������
	int AddCertOrCRLToStoreEx(HCERTSTORE hStore,const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
	//NMS : ������� CRYPT_DATA_BLOB �� �����
//	int CryptDataBlobFromFile(CString strFile,CRYPT_DATA_BLOB* pCertOrCRL);
	int CryptDataBlobFromFile(CString strFile,CRYPT_DATA_BLOB* pCertOrCRL, CBinData* pbnData = NULL);
	//NMS : ��������� ���������� ��� CRL � ����
	int AddCertOrCRLToFile(CString strFile,const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
public:
	//NMS : ����������� ����
	int SignFileEx(CString sSender,CString dataFileName,CString signFileName,BOOL bDetached);
	//NMS : ���� ���������� � ��������� �����������
protected:
	int CertFind(LPCERTFINDPARAM lpFindParam,PCCERT_CONTEXT* ppCertContext);
	//NMS : ���� ���������� � ��������� ����������� � � ������� ��������� (������ � ���)
	int CertFindEx(HCERTSTORE hStore,LPCERTFINDPARAM lpFindParam,PCCERT_CONTEXT* ppCertContext);
	//NMS : ��������� �������� ��������� �����������
	bool CertGetThumb(PCCERT_CONTEXT pCertContext,CRYPT_DATA_BLOB* pThumb);
	//NMS : ��������� ����������, � ��� �� ��� ������� ������������ �� ����������
	bool CertIsValid(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam);
	//NMS : ��������� ����������, � ��� �� ��� ������� ������������ �� ���������� ��� ����������� ���������
	bool CertIsValidEx(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam);

#ifdef CTHREAD_UPDATE_CRL
	//NMS : ��������� CRLs ��� CST_SST
	int CertUpdateCRLs(void);
#endif //

	//KAA : ������������� ��������� CRLs ��� ����������� ����������� 
	int CertUpdateCRLs(PCCERT_CONTEXT pCert);
	//KAA : ��������� ������ �� ����
	bool CertVerifyDateValid(PCCERT_CONTEXT pCert);
	//NMS : ��������� CRLs ��� ����������� ���������
	int CertUpdateCRLsEx(HCERTSTORE hStore);
	int CertUpdateCRLsEx(HCERTSTORE hScanStore,HCERTSTORE hAddCRLStore);	
	//NMS : ��������� � ��������� CRL, ������� ����� � Web
	int CertAddCRLInStoreFromURL(HCERTSTORE hStore,LPCTSTR lpszURL);
	//NMS : ���������� ���� � ���������� �����
	CString GetTempFilePath(void);
	//NMS : ������� ��� �������� ����� � ������� ������
	void DeleteAllTempFiles(void);
	//NMS : �������� OID ��� �����������
	bool CertCheckOID(PCCERT_CONTEXT pCertContext,CString strOID);
	//NMS : ��������� ���������� �� CRL
	bool CertCheckCRL(HCERTSTORE hStore,PCCERT_CONTEXT pIssuerCertContext,PCCERT_CONTEXT pCertContext,
					  PCERTVALIDPARAM pValidParam,const BOOL bReadOnly=TRUE);
	//NMS : ��������� ��������, ������ ������������ ������ ��� ����������� OID's
	CString CertGetEKUs(PCCERT_CONTEXT pCertContext);
	//NMS : ��������� �������� ����� �������
	CString GetSignTime (HCRYPTMSG hMsg,DWORD dwSigner);
	//NMS : ��������� �������	
	int CertCheckFileEx(CString dataFileName,CString signFileName,CString& sSignerInfo, BOOL bDetached);
	int CertCheckFileEx(CString dataFileName,CString signFileName,CStringArray& saSignInfos,BOOL bShowDlg,BOOL bDetached);
	//NMS : ��������� ������ � �������
	int	LockMethods(void);
	//NMS : ������������ ������ � �������
	int	UnLockMethods(void);
	//NMS : � ������� ���
	int CertDeleteFromStore(const LPCERTFINDPARAM lpCertFindParam);
	//NMS : ��������� ������ SST � ����
	int SaveSSTInFile(HCERTSTORE hStore=NULL);
	//NMS : ������������ ������� OID'�
	void CorrectOIDPrefix(CString& strOID,CString strReplacePrefix);	
	//NMS : ��������� �������� OID �� ���������
	CString GetDefaultOID(void);

#ifdef CTHREAD_UPDATE_CRL
	//NMS : ���������� certstore
	void UpdateCertStore(void);
#endif //

	//NMS : ������� ��������� ��������� �� INI �����
	void LoadSettings(void);	
//NMS : ����������� ��� UniFunc
	void OnAlertWhen2WeekRemain(CString sXMLIn,CString& sXMLOut);
	// �������� �� ���� ��������� �����������
	int CertCheckCertRemain(PCCERT_CONTEXT pSigner);

//NMS : ����������� ������
	//NMS : ��������� �������� ������ �� CERT_NAME_BLOB 
	static CString CertNameBlob2Str(const CERT_NAME_BLOB* pBlob,const bool b345=false);
	//NMS : ��������� �������� ��� ��������� �� ����
	static CString GetCertStoreNameByType(const DWORD dwType);
	//NMS : ��������� �������� �� ������ ��������� �����������
	static bool GetThumbFromStr(CString strThumb,CRYPT_DATA_BLOB* pThumb);
	//AKV : ��������� �� ��������� ����������� ������
	static bool GetStrFromThumb(const CRYPT_DATA_BLOB* pThumb, CString& strThumb);
//NMS : �����������
	//NMS : ���� � �������� �����
	CString m_strRootPath;
	//NMS : �������� CN
	CString m_strRootCN;
	//NMS : ����� ���������� ���������� CRL
	CTime m_tmLastCRLCheck;
	//NMS : ����� ���������� ���� �������� ������������
	CTime m_tValidCache;
	//NMS : ���� �������� ������������	
	CList<CBinData,CBinData&> m_lstCertValid;
	//NMS : ������ � ������� ��������� ���� � ��������� ������
	CStringArray m_saTempFiles;
	//NMS : ����������� ������ ��� ������ �������
	CRITICAL_SECTION m_CS;
	//NMS : ������ (���)
	CLogFile m_Log;
	//NMS : ��������� ������, ������� ���� �������� � ���.
	CString m_strLastError;
	//NMS : ����� � �������� �������� ��������
	CMap<DWORD,DWORD,HCERTSTORE,HCERTSTORE> m_mapCertStore;	
	//NMS : ������ OID'� ��� ��������
	CStringArrayEx m_arrOIDPrefix;
	//NMS : ��������� ��� ����������
	CPCRYPTOSETTINGS m_Settings;

	int m_LastErrorCode;

	BOOL m_IsReferent;
};

//NMS : ���� ������� ������������ �� �������
#define CCPC_NotInitialized				1
#define CCPC_CantLoadCSP				2
//#define CCPC_CryptoError				3 // KAA: ������� �.�. �� ������������
#define CCPC_CantOpenFileRead			4
#define CCPC_CantOpenFileWrite			5
#define CCPC_OutOfMemory				6
#define CCPC_FileNotSigned				7
#define CCPC_VerifyFailed				8
#define CCPC_InternalError				9
#define CCPC_CantUnLoadCSP				10
#define CCPC_InvalidAltFileFormat		11
#define CCPC_InvalidFileFormat			12
#define CCPC_CertNotFind				13
#define CCPC_CertNotValid				14
#define CCPC_CantOpenStore				15
#define CCPC_CantCloseStore				16
#define CCPC_CantFindCertInStore		17
#define CCPC_CantFindCRLInStore  		18
#define CCPC_CantAddCRLInStore  		19
#define CCPC_CantAddCertInStore  		20
#define CCPC_CantOpenToDecode			21
#define CCPC_CantAddDataToMessage		22
#define CCPC_CantGetParamMessage		23
#define CCPC_CantGetTrustChain			24
#define CCPC_CantVerifyCRL  			25
#define CCPC_NoSender		  			26
#define CCPC_CantFindPrivateKey			27
#define CCPC_CantGetThumb				28
#define CCPC_CantFindPublicKey			29
#define CCPC_CantOpenToEncode			30
#define CCPC_CantGetHash				31
#define CCPC_CantCreateCert				32
#define CCPC_CantCreateCRL				33
#define CCPC_CantGetProv				34
#define CCPC_URLError					35
#define CCPC_CantSaveStore				36
#define CCPC_CantDeleteCertFromStore	37
#define CCPC_DecryptError				38
#define CCPC_CantFindCoordinationKey	39
#define CCPC_CantFindSessionKey			40
#define CCPC_CantSetKeyParam			41
#define CCPC_CryptError					42
#define CCPC_CrlNotValid				43
#define CCPC_CantUpdateCrl				44
#define CCPC_CertIsRemainExpiered		45


#define CCPC_FunctionNotImplemented		-1
#define CCPC_NotInit					-2

//NMS : ��������������� ������� ��� ������ ICPCryptoImpl::UniFunc

#define	STR_ALERT_WHEN_2WEEK_REMAIN _T("�������� �� 2 ������ �� ��������� ����� �������� �����������")
#define	STR_SET_ROOT_CN				_T("��������� ��������� CN")

//NMS : ����� XML ����������
#define	STR_TAG_RESULT_NOTAFTER	_T("IDNOTAFTER")

//NMS : ��������������� ������

//*****************************************************************************
//* CCertCloseCache
//*****************************************************************************

//NMS : ��������� ������������� ��� �������� �������� ������������
class CCertCloseCache
{
public:
//NMS : ������
	CCertCloseCache(ICPCryptoImpl* pCls,const DWORD dwType=CST_ALL);
	~CCertCloseCache();
//NMS : ����������
	//NMS : ��������� �� �����
	ICPCryptoImpl* m_pCls;
	//NMS : ���� ��������, ������� ����� �������
	DWORD m_dwType;
};

//*****************************************************************************
//* CCertAutoBytePtr
//*****************************************************************************

//NMS : ������������� ������� ������������ ���������
class CCertAutoBytePtr
{
public:
//NMS : ������
	CCertAutoBytePtr(const BYTE* pPtr,const bool bFree=true);
	~CCertAutoBytePtr();
	//NMS : ������������� ��������� �� ������ � ����� ��������
	void Attach(const BYTE* pPtr,const bool bFree=true);
	//NMS : ������� � �������� ��������� �� ������
	void Free(void);		
//NMS : ����������
	//NMS : ��������� �� ������
	BYTE* m_pPtr;
	//NMS : ����� ������������ ��������� : free ��� delete[]
	bool m_bFree;
};

//*****************************************************************************
//* CCertAutoStore
//*****************************************************************************

//NMS : ������������� ��������� ���������
class CCertAutoStore
{
public:
//NMS : ������
	CCertAutoStore(HCERTSTORE hStore);
	~CCertAutoStore();
	void Attach(HCERTSTORE hStore);
	void Close();
//NMS : ����������	
	HCERTSTORE m_hStore;
};

//*****************************************************************************
//* CCertLockMethods
//*****************************************************************************

//NMS : ������������� ��������� ������ ��� ������ � ����������� ������,
class CCertLockMethods
{
public:
//NMS : ������
	CCertLockMethods(const ICPCryptoImpl* pICPCryptoImpl);
	~CCertLockMethods();	
	bool Check(void) const;
//NMS : ����������	
	long m_nStatus;
	ICPCryptoImpl* m_pICPCryptoImpl;
};

//*****************************************************************************
//* CCertCryptMsgClose
//*****************************************************************************

//NMS : ������������� ����������� ���������� ������������������ ���������
class CCertCryptMsgClose
{
public:
//NMS : ������
	CCertCryptMsgClose(HCRYPTMSG* phMsg);
	~CCertCryptMsgClose();
//NMS : ����������
	HCRYPTMSG* m_phMsg;
};

//*****************************************************************************
//* CCertCryptProv
//*****************************************************************************

//NMS : ������������� ����������� ����������������
class CCertCryptProv
{
public:
//NMS : ������
	CCertCryptProv(HCRYPTPROV* phProv);
	~CCertCryptProv();
//NMS : ����������
	HCRYPTPROV* m_phProv;
};

//*****************************************************************************
//* CCertCryptDestroyHash
//*****************************************************************************

//NMS : ������������� ����������� ���
class CCertCryptDestroyHash
{
public:
//NMS : ������
	CCertCryptDestroyHash(HCRYPTHASH* phHash);
	~CCertCryptDestroyHash();
//NMS : ����������
	HCRYPTHASH* m_phHash;
};

//*****************************************************************************
//* CCertCryptDestroyKey
//*****************************************************************************

//NMS : ������������� ����������� ����
class CCertCryptDestroyKey
{
public:
//NMS : ������
	CCertCryptDestroyKey(HCRYPTKEY* phKey);
	~CCertCryptDestroyKey();
//NMS : ����������
	HCRYPTKEY* m_phKey;
};

//*****************************************************************************
//* CCertFreeCertificateContext
//*****************************************************************************

//NMS : ������������� ����������� �������� �����������

class CCertFreeCertificateContext
{
public:
//NMS : ������
	CCertFreeCertificateContext(PCCERT_CONTEXT* ppCert);
	~CCertFreeCertificateContext();
//NMS : ����������
	PCCERT_CONTEXT* m_ppCert;
};
#ifndef KILL_STREAM_INTERFACE
class AutoDeleterFile
{
public:
    AutoDeleterFile(std::string &filename)
        : _filename(filename)
    {

    }
    ~AutoDeleterFile()
    {
       remove(_filename.c_str());
    }
private:
    std::string _filename;
};
#endif

#endif //ICPCRYPTOIMPL_H