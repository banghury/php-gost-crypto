// 03.10.2009 MODIF CSimpleLogFile for using m_sLogCurrent
// Use Settings : Preprocessor : Add include path = <path to project>
#include "stdafx.h"
#include <process.h>
#include "LogFile.h"
#include "StringArrayEx.h"
#include "FileMng.h"

#ifdef _DEBUG
	#undef THIS_FILE
	static char THIS_FILE[]=__FILE__;
	#define new DEBUG_NEW
#endif

//#define _LOGFILE_FOR_MULTI_THREADS_

CLogFile::CLogFile() : 
	m_uSize(__N_SIZE_LOG_FILE_IN_KB__*1024), 
	m_bWriteLogInvert(FALSE),
	m_bCopyLogFileWhenOverflow(FALSE)
{}

CLogFile::~CLogFile()
{
	WriteLog();
	//NMS : Чистим лог
	ClearLines();
}

void CLogFile::ViewLog ()
{
	WriteLog ();
	_spawnlp( _P_NOWAIT, "notepad.exe", "notepad.exe", (LPCSTR)m_sPFNLog, NULL);
}

// AKV: Через Mutex
class CLogFileLock
{
public:
	explicit CLogFileLock(const CLogFile *pLogFile);
	~CLogFileLock(void);
	
	BOOL	Lock(void);
	BOOL	Unlock(void);
	BOOL	IsLocked(void) const { return (m_hMutex != NULL); };
protected:
	// в качестве имени будем использовать полное имя файла, заменяя '\' на '/' и ' ' на '_'
	const CString	m_strMutexName;
	HANDLE	m_hMutex;
};

CLogFileLock::CLogFileLock(const CLogFile *pLogFile)
			: m_strMutexName(pLogFile->m_sPFNLog)
			, m_hMutex(NULL)
{
	CString *pstrMutexName = const_cast<CString *>(&m_strMutexName);
	pstrMutexName->Replace((TCHAR)_T('\\'), _T('/'));
	pstrMutexName->Replace(_T(' '), _T('_'));
}

CLogFileLock::~CLogFileLock()
{
	if (IsLocked())
		Unlock();
}

BOOL CLogFileLock::Lock()
{
	m_hMutex = ::CreateMutex(NULL, FALSE, m_strMutexName);
	if (m_hMutex == NULL)
		return FALSE;
	// AKV: Исправлено - учтен код WAIT_ABANDONED
	//if (::WaitForSingleObject(m_hMutex, 3000) != WAIT_OBJECT_0)
	DWORD dwWaitRes = ::WaitForSingleObject(m_hMutex, 3000);
	if ((dwWaitRes != WAIT_OBJECT_0) && (dwWaitRes != WAIT_ABANDONED))
	{
		::CloseHandle(m_hMutex);
		m_hMutex = NULL;
		return FALSE;
	}

	return TRUE;
}

BOOL CLogFileLock::Unlock()
{
	if (!IsLocked())
		return TRUE;
	::ReleaseMutex(m_hMutex);
	::CloseHandle(m_hMutex);
	m_hMutex = NULL;
	return TRUE;
}
// AKV End

BOOL CLogFile::WriteLog()
{
	CString str;
	return WriteLog (str);
}

BOOL CLogFile::WriteLog (CString& sSavedLogFile)
{	
	if (m_sPFNLog.IsEmpty () || m_lstLines.GetCount () == 0) 
		return TRUE;

	// proc lock logfile
	CString sPostfixForDump;

#ifdef _LOGFILE_FOR_MULTI_THREADS_
	CLogFileLock lock (this);
	
	if (!lock.Lock ())
		sPostfixForDump = CFileMng::GetUnicName ().Left (9);
#endif // _LOGFILE_FOR_MULTI_THREADS_

	CString sCurLog;
	if (m_bWriteLogInvert)
	{
// SMU: Читаем предыдущий лог если файл-журнал не был заблокирован. Что бы не дублировать предыдущий лог...
		if (sPostfixForDump.IsEmpty ()) 
			CStringProc::fRead (m_sPFNLog, sCurLog);

		POSITION pos=m_lstLines.GetHeadPosition();
		while(pos!=NULL)
		{
			sCurLog+=m_lstLines.GetNext(pos)+_T("\r\n");
		}	
	}
	else
	{
		CString sPrevLog;		
		POSITION pos=m_lstLines.GetTailPosition();
		while(pos!=NULL)
		{
			sCurLog+=m_lstLines.GetPrev(pos)+_T("\r\n");
		}

// SMU: Читаем предыдущий лог если файл-журнал не был заблокирован. Что бы не дублировать предыдущий лог...
		if (sPostfixForDump.IsEmpty ()) 
		{
			if (CStringProc::fRead (m_sPFNLog, sPrevLog))
				sCurLog += sPrevLog;
		}
	}

	const int nSize = sCurLog.GetLength ();
	if ((unsigned)nSize > m_uSize && m_uSize != __NOT_CUT_LOG__) 
	{
		if ( m_bCopyLogFileWhenOverflow )
		{
			// Semenov : Сохраняем старый лог 
			sSavedLogFile = m_sPFNLog;
			if ( !sPostfixForDump.IsEmpty() )
				sSavedLogFile += '.' + sPostfixForDump + ".log";
			sSavedLogFile += CStringProc::GetStrFileExtDateTimeCur();	
			if ( !CStringProc::fWrite (sSavedLogFile, sCurLog) )
				return FALSE;
			sCurLog.Empty();	
		}
		else if (m_bWriteLogInvert)
		{
			sCurLog.Delete (0, nSize - m_uSize);
		}
		else
		{
			sCurLog.Delete (m_uSize, nSize - m_uSize);
		}
	}
	
	if (!CStringProc::fWrite (sPostfixForDump.IsEmpty () ? m_sPFNLog : 
			m_sPFNLog + '.' + sPostfixForDump + ".log", sCurLog))
		return FALSE;
	
	//NMS : Чистим лог
	ClearLines();
	return TRUE;
}

CString	CLogFile::SetLogSize (CString sSizeInKB)
{
	DWORD nSizeKB = 0;
	if (1 != sscanf ((LPCSTR)sSizeInKB, 
			"%d", &nSizeKB) || nSizeKB <= __N_SIZE_LOG_FILE_IN_KB__ 
			|| nSizeKB > 50000)
		nSizeKB = __N_SIZE_LOG_FILE_IN_KB__;

	m_uSize = nSizeKB*1024;
	CString sResult;
	sResult.Format ("%d", nSizeKB);
	return sResult;
}

void CLogFile::AddLine(LPCSTR lpMsg)
{	
	//NMS : Пустое не добавляем
	if (lpMsg==NULL || *lpMsg==_T('\0'))
	{
		return ;
	}
	//NMS : Формируем сообщение и записываем его в лог
	CString strMsg;
	strMsg.Format(_T("%s %s"),CTime::GetCurrentTime().Format("%b%d %H:%M:%S"),lpMsg);
	m_lstLines.AddTail(strMsg);	
}

void CLogFile::AddLineF(LPCSTR lpszFormat,...)
{
	va_list pList=NULL;
	va_start(pList,lpszFormat);
	AddLineF(lpszFormat,pList);
	va_end(pList);
}

void CLogFile::AddLineF(LPCSTR lpszFormat,va_list argsList)
{
	CString strMsg;
	strMsg.FormatV(lpszFormat,argsList);
	AddLine(strMsg);
}

//NMS : Возвращает кол-во сообщений в логе
DWORD CLogFile::GetNoOfLines(void) const
{
	return m_lstLines.GetCount();	
}

//NMS : Очищает список
void CLogFile::ClearLines(void)
{
	m_lstLines.RemoveAll();	
}

//////////////////////////////////////////////////////////////////////////
// AKV: CSimpleLog class implementation
CSimpleLogFile::CSimpleLogFile()
				: m_uSize(__NOT_CUT_LOG__)
				, m_bWriteLogInvert(TRUE)
{
}

CSimpleLogFile::~CSimpleLogFile()
{
	WriteLog();
}

void CSimpleLogFile::ViewLog()
{
	WriteLog();
	_spawnlp( _P_NOWAIT, "notepad.exe", "notepad.exe", (LPCSTR)m_sPFNLog, NULL);
}

CString	CSimpleLogFile::SetLogSize(const CString& sSizeInKB)
{
	DWORD nSizeKB = 0;
	if (1 != sscanf ((LPCSTR)sSizeInKB, 
			"%d", &nSizeKB) || nSizeKB <= __N_SIZE_LOG_FILE_IN_KB__ 
			|| nSizeKB > 50000)
		nSizeKB = __N_SIZE_LOG_FILE_IN_KB__;
	m_uSize = nSizeKB * 1024;
	CString sResult;
	sResult.Format ("%d", nSizeKB);
	WriteLog();
	return sResult;
}

BOOL CSimpleLogFile::WriteLog()
{
	CSingleLock lock(&m_mutex);
	if (!lock.Lock(1000))
		return FALSE;
	try
	{
// SMU: write current log
		if (!m_sLogCurrent.IsEmpty() && WriteLine (m_sLogCurrent)) 
			m_sLogCurrent.Empty();
	}
	catch (CFileException *pErr)
	{
		pErr->Delete();
		return FALSE;
	}

	return TRUE;
}

void CSimpleLogFile::AddLine(LPCSTR lpMsg)
{
	if (lpMsg == NULL || *lpMsg == _T('\0'))
	{
		return;
	}
	CString strMsg;
	strMsg.Format(_T("%s %s\n"), CTime::GetCurrentTime().Format("%b%d %H:%M"), lpMsg);
	m_sLogCurrent += strMsg;
//	WriteLine(strMsg);
}

void CSimpleLogFile::AddLineF(LPCSTR lpszFormat, ...)
{
	va_list pList = NULL;
	va_start(pList, lpszFormat);
	AddLineF(lpszFormat, pList);
	va_end(pList);
}

void CSimpleLogFile::AddLineF(LPCSTR lpszFormat, va_list argsList)
{
	CString strMsg;
	strMsg.FormatV(lpszFormat, argsList);
	AddLine(strMsg);
}

BOOL CSimpleLogFile::WriteLine(LPCTSTR cszLine)
{
	ASSERT(cszLine);
	if (*cszLine == 0)
		return FALSE;
	CSingleLock lock(&m_mutex);
	if (!lock.Lock(1000))
		return FALSE;
	try
	{
		CStdioFile file;
		if (!file.Open(m_sPFNLog, CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite))
			return FALSE;
		// AKV: Проверяем размер файла
		ULONGLONG ullFileSize = file.GetLength();
		if ((m_uSize != __NOT_CUT_LOG__) && (ullFileSize >= m_uSize))
		{
			file.Close();
			TCHAR szDrive[_MAX_DRIVE], szDir[_MAX_DIR], szFName[_MAX_FNAME], szExt[_MAX_EXT];
			_tsplitpath(m_sPFNLog, szDrive, szDir, szFName, szExt);
			unsigned iFileNo = 0;
			const unsigned nMaxFiles = 50;
			TCHAR szPath[_MAX_PATH];
			do 
			{
				++iFileNo;
				_tmakepath(szPath, szDrive, szDir, CStringProc::Format(_T("%s_%i"), szFName, iFileNo), szExt);
			}
			while (CFileMng::IsFileExist(szPath) && (iFileNo <= nMaxFiles));
			// AKV: Новое имя файла только в этом случае, иначе - пусть растет дальше
			if (iFileNo <= nMaxFiles)
			{
				::MoveFile(m_sPFNLog, szPath);
			}
			// AKV: Переоткрываем файл
			if (!file.Open(m_sPFNLog, CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite))
				return FALSE;
		}
		// AKV End
		file.SeekToEnd();
		file.WriteString(cszLine);
//SMU: new line added early
//		file.WriteString(_T("\n"));
		file.Flush();
		file.Close();
	}
	catch (CFileException *pErr)
	{
		pErr->Delete();
		return FALSE;
	}
	return TRUE;
}

// AKV End
