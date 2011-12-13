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

//NMS : Позволяет получить CN сертификата
CString GetCNFromCert(PCCERT_CONTEXT pCert);

class CCertCloseCache;
class CCertLockMethods;

//NMS : Структуры

typedef struct _TAGCERTVALIDPARAM
{
//NMS : Методы
	_TAGCERTVALIDPARAM()
	{
		Reset();
	}

	void Reset(void)
	{
		nResultCode=CCPC_NoError;		
		bExpiredCRL=FALSE;		
	}
//NMS : Перемменные
	LONG nResultCode;			//NMS : Результирующий код возврата	
	BOOL bExpiredCRL;			//NMS : Нужно-ли обновлять CRL
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

//NMS : Переменные
	//NMS : Флаг о том, что нужно использовать настройки из файла
	BOOL bUsingCustomOptions;
	//NMS : Флаг о том, что нужно ли обновлять CRL или нет
	BOOL bSkipUpdateCRL;
	//NMS : Флаг о том, нужно ли проверять валидность сертификата
	BOOL bSkipCheckCertValid;
	//NMS : Флаг о том, что при старте CRL, обновлять не нужно
	BOOL bSkipUpdateCRLInInit;
	//NMS : Флаг, о том, что не нужно проверять CRL для сертификатов
	BOOL bSkipCheckCRL;
	//NMS : Флаг, о том, что лог писать не нужно
	BOOL bOffLogFile;

	BOOL bSkipCheckTimeRemains;
} CPCRYPTOSETTINGS,*PCPCRYPTOSETTINGS;

//NMS : Флаги для открытия хранилищ,
// какие хранилища именно нужно открыть
// CST_ - Cert store type
#define CST_SST		0x00000001
#define CST_MY		0x00000002
#define CST_ROOT	0x00000004
#define CST_OWNER	0x00000008

#define CST_ALL		(CST_SST|CST_MY|CST_ROOT) // для совместимости пока так и оставим

//NMS : Флаги для управления
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

//NMS : Инициализация
	virtual int Initialize (CString sRootPath,ICPCryptoCallBack* iCPCryptoCallBack=NULL);
	virtual BOOL IsInitialized();

//NMS : Базовая версия (ICPCryptoImpl_EDS.cpp)
	// sSender == Subject\tOID
	virtual int SignFileA(CString sSender, CString datasignFileName);
	virtual int SignFileD(CString sSender, CString dataFileName, CString signFileName);
 	virtual int CheckFileA(CString signFileName, CString dataFileName, CStringArray& saSignInfos, BOOL bShowDlg); // если dataFileName!="" то в dataFileName будет файл без подписи
 	virtual int CheckFileD(CString dataFileName, CString signFileName, CStringArray& saSignInfos, BOOL bShowDlg);

	// проверка наличия подписи (Subject\tOID) в файле
	// в sSenderInfo возвращается значение Subject сертификата
	virtual int CheckFileA(CString signFileName, CString& sSenderInfo);
	virtual int CheckFileD(CString dataFileName, CString signFileName, CString& sSenderInfo);

	virtual int UnpackSignedFile(CString datasignFileName, CString dataFileName);

	// saRecepientIDs == Array of (Subject\tOID)
	virtual int EncryptFile(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	virtual int DecryptFile(CString cryptoFileName, CString plainFileName);
/*
//NMS : Альтернативная версия формата выходного файла (ICPCryptoImpl_EDS2.cpp)
	virtual int SignFileAlt(CString sSender, CString datasignFileName);
	virtual int CheckFileAlt(CString datasignFileName, CStringArray& saSignInfos, BOOL bShowDlg);
	virtual int CheckFileAlt(CString datasignFileName, CString& sSenderInfo);
	virtual int UnpackSignedFileAlt (CString datasignFileName, CString dataFileName, CStringArray& saSigIDs, BOOL bRemoveSignatures);
	virtual int EncryptFileAlt(CString plainFileName, CString cryptoFileName, CStringArray& saRecepientIDs);
	virtual int DecryptFileAlt(CString cryptoFileName, CString plainFileName);

//NMS : Альтернативная-2 (приказ 345) версия формата выходного файла (ICPCryptoImpl_EDS_345.cpp)
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
	//NMS : Удаление происходит только из SST файла
	virtual int DelCertFromStore(CString strCN);
	//NMS : Позволяет получить сертификат из хранилища по subject,email,thumb
	virtual int GetCertFromStore(CString strSubjectOrEmail,CRYPT_DATA_BLOB* pCert);
//NMS :  Universal crypto function (ICPCryptoImpl_UniFunc.cpp)

	virtual int FindCertificate(LPCTSTR szThumbprint, PCCERT_CONTEXT& pCertContext);
	//KAA : Проверяет сертификат на валидность как это делается при шифровании, возвращает CCPC_NoError или код ошибки
	virtual int CheckCertificate(const PCCERT_CONTEXT pCertContext);
	//KAA : Получает отпечатки сертификатов (в формате HEX), использованные при шифровании по 141, возвращает CCPC_NoError или код ошибки
//	virtual int GetCertificateForDecryptFileAlt2(LPCTSTR szCryptedFileName, CRYPTALT2THUMBPRINTS* pCryptAlt2Thumbprints);

#ifdef CTHREAD_UPDATE_CRL
	virtual bool IsFoundUniFunc(CString sFuncName);
	virtual void UniFunc(CString sFuncName,CString sXMLIn,CString& sXMLOut);
#endif //

#ifndef KILL_STREAM_INTERFACE
    // LLP
    // Шифрование
    // recepientIDs == vector of (Subject\tOID)
    // cryptoStream - зашифрованный поток
    // plainFileName - расшифрованный поток 
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
//NMS : Методы
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
	// KAA : Получает список всех OID
	bool CertGetOIDs(HCRYPTMSG hMsg, PCCERT_CONTEXT pCertContext,CStringArray& saOIDs);

	//NMS : Позволяет получить имя сертификата
	CString CertGetName(PCCERT_CONTEXT pCertContext,const BOOL bIssuer=FALSE);
	CString CertGetName(PCCRL_CONTEXT  pCrlContext);
	//NMS : Проверяет цепочку сертификата
	int CertCheckChain(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pCertValidParam);
	//NMS : Заполняет сообщение об ошибке
	CString GetSystemErrorDesc(const DWORD dwError=::GetLastError());
	//NMS : Выводит сообщение в файл журнала(лог)
	void WriteToLog(LPCTSTR lpszFormat,...);
	//NMS : Открываем хранилища в которых будем искать сертификат
	int CertOpenStore(const DWORD dwType=CST_ALL,const bool bReOpen=false);
	//NMS : Закрываем открытые хранилища сертификатов
	void CertCloseStore(const DWORD dwType=CST_ALL);
	//NMS : Позволяет получить хэндл из кэша по имени
	HCERTSTORE CertGetHandleStoreByType(const DWORD dwType);
	//NMS : Проверяем существование SST файла, если не существует
	//		создаем, причем даже с учетом директорий.
	void CertStoreVerifyExistPath(CString strStoreFilePath);	
	//NMS : Добавляет сертификат или CRL в хранилище (на данный момент это только SST)
	int AddCertOrCRLToStore(const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
	//NMS : Добавляет сертификат или CRL в указанное хранилище
	int AddCertOrCRLToStoreEx(HCERTSTORE hStore,const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
	//NMS : Создает CRYPT_DATA_BLOB из файла
//	int CryptDataBlobFromFile(CString strFile,CRYPT_DATA_BLOB* pCertOrCRL);
	int CryptDataBlobFromFile(CString strFile,CRYPT_DATA_BLOB* pCertOrCRL, CBinData* pbnData = NULL);
	//NMS : Добавляет сертификат или CRL в файл
	int AddCertOrCRLToFile(CString strFile,const CRYPT_DATA_BLOB* pCertOrCRL,const int iType);
public:
	//NMS : Подписывает файл
	int SignFileEx(CString sSender,CString dataFileName,CString signFileName,BOOL bDetached);
	//NMS : Ищет сертификат с заданными параметрами
protected:
	int CertFind(LPCERTFINDPARAM lpFindParam,PCCERT_CONTEXT* ppCertContext);
	//NMS : Ищет сертификат с заданными параметрами и в заданом хранилище (только в нем)
	int CertFindEx(HCERTSTORE hStore,LPCERTFINDPARAM lpFindParam,PCCERT_CONTEXT* ppCertContext);
	//NMS : Позволяет получить отпечаток сертификата
	bool CertGetThumb(PCCERT_CONTEXT pCertContext,CRYPT_DATA_BLOB* pThumb);
	//NMS : Проверяет сертификат, а так же его цепочку сертификатов на валидность
	bool CertIsValid(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam);
	//NMS : Проверяет сертификат, а так же его цепочку сертификатов на валидность для конкретного хранилища
	bool CertIsValidEx(PCCERT_CONTEXT pCertContext,PCERTVALIDPARAM pValidParam);

#ifdef CTHREAD_UPDATE_CRL
	//NMS : Обновляет CRLs для CST_SST
	int CertUpdateCRLs(void);
#endif //

	//KAA : Принудительно обновляет CRLs для конкретного сертификата 
	int CertUpdateCRLs(PCCERT_CONTEXT pCert);
	//KAA : Проверяет только по дате
	bool CertVerifyDateValid(PCCERT_CONTEXT pCert);
	//NMS : Обновляет CRLs для конкретного хранилища
	int CertUpdateCRLsEx(HCERTSTORE hStore);
	int CertUpdateCRLsEx(HCERTSTORE hScanStore,HCERTSTORE hAddCRLStore);	
	//NMS : Добавляет в хранилище CRL, который лежит в Web
	int CertAddCRLInStoreFromURL(HCERTSTORE hStore,LPCTSTR lpszURL);
	//NMS : Возвращает путь к временному файлу
	CString GetTempFilePath(void);
	//NMS : Удаляет все временые файлы и очищает массив
	void DeleteAllTempFiles(void);
	//NMS : Проверка OID для сертификата
	bool CertCheckOID(PCCERT_CONTEXT pCertContext,CString strOID);
	//NMS : Проверяет сертификат по CRL
	bool CertCheckCRL(HCERTSTORE hStore,PCCERT_CONTEXT pIssuerCertContext,PCCERT_CONTEXT pCertContext,
					  PCERTVALIDPARAM pValidParam,const BOOL bReadOnly=TRUE);
	//NMS : Позволяет получить, список используемых ключей для сертификата OID's
	CString CertGetEKUs(PCCERT_CONTEXT pCertContext);
	//NMS : Позволяет получить время подписи
	CString GetSignTime (HCRYPTMSG hMsg,DWORD dwSigner);
	//NMS : Проверяет подпись	
	int CertCheckFileEx(CString dataFileName,CString signFileName,CString& sSignerInfo, BOOL bDetached);
	int CertCheckFileEx(CString dataFileName,CString signFileName,CStringArray& saSignInfos,BOOL bShowDlg,BOOL bDetached);
	//NMS : Блокирует доступ к методам
	int	LockMethods(void);
	//NMS : Разблокирует доступ к методам
	int	UnLockMethods(void);
	//NMS : И удаляет его
	int CertDeleteFromStore(const LPCERTFINDPARAM lpCertFindParam);
	//NMS : Сохраняет данные SST в файл
	int SaveSSTInFile(HCERTSTORE hStore=NULL);
	//NMS : Корректирует префикс OID'а
	void CorrectOIDPrefix(CString& strOID,CString strReplacePrefix);	
	//NMS : Позволяет получить OID оп умолчанию
	CString GetDefaultOID(void);

#ifdef CTHREAD_UPDATE_CRL
	//NMS : Обновление certstore
	void UpdateCertStore(void);
#endif //

	//NMS : Функция загружает настройки из INI файла
	void LoadSettings(void);	
//NMS : Обработчики для UniFunc
	void OnAlertWhen2WeekRemain(CString sXMLIn,CString& sXMLOut);
	// Проверка на срок окончания сертификата
	int CertCheckCertRemain(PCCERT_CONTEXT pSigner);

//NMS : Статические методы
	//NMS : Возволяет получить строку из CERT_NAME_BLOB 
	static CString CertNameBlob2Str(const CERT_NAME_BLOB* pBlob,const bool b345=false);
	//NMS : Позволяет получить имя хранилища по типу
	static CString GetCertStoreNameByType(const DWORD dwType);
	//NMS : Позволяет получить из строки отпечаток сертификата
	static bool GetThumbFromStr(CString strThumb,CRYPT_DATA_BLOB* pThumb);
	//AKV : Позволяет из отпечатка сертификата строку
	static bool GetStrFromThumb(const CRYPT_DATA_BLOB* pThumb, CString& strThumb);
//NMS : Перерменные
	//NMS : Путь к корневой папке
	CString m_strRootPath;
	//NMS : Корневой CN
	CString m_strRootCN;
	//NMS : Время последного обновления CRL
	CTime m_tmLastCRLCheck;
	//NMS : Время обновления кэша валидных сертификатов
	CTime m_tValidCache;
	//NMS : Лист валидных сертификатов	
	CList<CBinData,CBinData&> m_lstCertValid;
	//NMS : Массив в котором храняться пути к временным файлам
	CStringArray m_saTempFiles;
	//NMS : Критическая секция для защиты методов
	CRITICAL_SECTION m_CS;
	//NMS : Журнал (лог)
	CLogFile m_Log;
	//NMS : Последняя ошибка, которая была записана в лог.
	CString m_strLastError;
	//NMS : Карта с хендлами открытых хранилищ
	CMap<DWORD,DWORD,HCERTSTORE,HCERTSTORE> m_mapCertStore;	
	//NMS : Список OID'а для проверки
	CStringArrayEx m_arrOIDPrefix;
	//NMS : Настройки для библиотеки
	CPCRYPTOSETTINGS m_Settings;

	int m_LastErrorCode;

	BOOL m_IsReferent;
};

//NMS : Коды которые возвращаются из функций
#define CCPC_NotInitialized				1
#define CCPC_CantLoadCSP				2
//#define CCPC_CryptoError				3 // KAA: удалено т.к. не информативно
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

//NMS : Индентификаторы функций для метода ICPCryptoImpl::UniFunc

#define	STR_ALERT_WHEN_2WEEK_REMAIN _T("Сообщать за 2 недели об истечении срока действия сертификата")
#define	STR_SET_ROOT_CN				_T("Установка корневого CN")

//NMS : Имена XML параметров
#define	STR_TAG_RESULT_NOTAFTER	_T("IDNOTAFTER")

//NMS : Вспомогательные классы

//*****************************************************************************
//* CCertCloseCache
//*****************************************************************************

//NMS : Закрывает автоматически кэш открытых хранилищ сертификатов
class CCertCloseCache
{
public:
//NMS : Методы
	CCertCloseCache(ICPCryptoImpl* pCls,const DWORD dwType=CST_ALL);
	~CCertCloseCache();
//NMS : Переменные
	//NMS : Указатель на класс
	ICPCryptoImpl* m_pCls;
	//NMS : Типы хранилищ, которые нужно закрыть
	DWORD m_dwType;
};

//*****************************************************************************
//* CCertAutoBytePtr
//*****************************************************************************

//NMS : Автоматически удаляет динамические указатели
class CCertAutoBytePtr
{
public:
//NMS : Методы
	CCertAutoBytePtr(const BYTE* pPtr,const bool bFree=true);
	~CCertAutoBytePtr();
	//NMS : Устанавливаем указатель на данные и метод удаления
	void Attach(const BYTE* pPtr,const bool bFree=true);
	//NMS : Удаляем и обнуляем указатель на данные
	void Free(void);		
//NMS : Переменные
	//NMS : Указатель на данные
	BYTE* m_pPtr;
	//NMS : Метод освобождения указателя : free или delete[]
	bool m_bFree;
};

//*****************************************************************************
//* CCertAutoStore
//*****************************************************************************

//NMS : Автоматически закрывает хранилище
class CCertAutoStore
{
public:
//NMS : Методы
	CCertAutoStore(HCERTSTORE hStore);
	~CCertAutoStore();
	void Attach(HCERTSTORE hStore);
	void Close();
//NMS : Переменные	
	HCERTSTORE m_hStore;
};

//*****************************************************************************
//* CCertLockMethods
//*****************************************************************************

//NMS : Автоматически блокирует доступ для других к вызываемому методу,
class CCertLockMethods
{
public:
//NMS : Методы
	CCertLockMethods(const ICPCryptoImpl* pICPCryptoImpl);
	~CCertLockMethods();	
	bool Check(void) const;
//NMS : Переменные	
	long m_nStatus;
	ICPCryptoImpl* m_pICPCryptoImpl;
};

//*****************************************************************************
//* CCertCryptMsgClose
//*****************************************************************************

//NMS : Автоматически освобождает дискриптор криптографического сообщения
class CCertCryptMsgClose
{
public:
//NMS : Методы
	CCertCryptMsgClose(HCRYPTMSG* phMsg);
	~CCertCryptMsgClose();
//NMS : Переменные
	HCRYPTMSG* m_phMsg;
};

//*****************************************************************************
//* CCertCryptProv
//*****************************************************************************

//NMS : Автоматически освобождает криптопровайдера
class CCertCryptProv
{
public:
//NMS : Методы
	CCertCryptProv(HCRYPTPROV* phProv);
	~CCertCryptProv();
//NMS : Переменные
	HCRYPTPROV* m_phProv;
};

//*****************************************************************************
//* CCertCryptDestroyHash
//*****************************************************************************

//NMS : Автоматически освобождает хэш
class CCertCryptDestroyHash
{
public:
//NMS : Методы
	CCertCryptDestroyHash(HCRYPTHASH* phHash);
	~CCertCryptDestroyHash();
//NMS : Переменные
	HCRYPTHASH* m_phHash;
};

//*****************************************************************************
//* CCertCryptDestroyKey
//*****************************************************************************

//NMS : Автоматически освобождает ключ
class CCertCryptDestroyKey
{
public:
//NMS : Методы
	CCertCryptDestroyKey(HCRYPTKEY* phKey);
	~CCertCryptDestroyKey();
//NMS : Переменные
	HCRYPTKEY* m_phKey;
};

//*****************************************************************************
//* CCertFreeCertificateContext
//*****************************************************************************

//NMS : Автоматически освобождает контекст сертификата

class CCertFreeCertificateContext
{
public:
//NMS : Методы
	CCertFreeCertificateContext(PCCERT_CONTEXT* ppCert);
	~CCertFreeCertificateContext();
//NMS : Переменные
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