#ifndef LOG_FILE_H
#define LOG_FILE_H

// Class for work with LOG file
// 31 aug 2004
// 23 dec 2004 MODIFY AdLine : not add empty line
// 29 nov 2004 ADD __NOT_CUT_LOG__
// 09 nov 2004 MODIF BOOL	WriteLog ();
// 31 aug 2004 ADD SetSize
// 03 nov 2009 MODIF CSimpleLogFile for using m_sLogCurrent

#pragma once

#include <afxtempl.h>
#include <afxmt.h>

#define	__NOT_CUT_LOG__				(-1)
#define	__N_SIZE_LOG_FILE_IN_KB__	10000

class CLogFile
{
public:
	CLogFile();
	~CLogFile();
//NMS : Методы
	//NMS : Добавляет строчку в лог
	void AddLine(LPCSTR pStr);
	void AddLineF(LPCSTR lpszFormat,...);
	void AddLineF(LPCSTR lpszFormat,va_list argsList);
	//NMS : Позволяет посмотреть лог с помощью блокнота
	void ViewLog();
	//NMS : Записывает содержимое лога в файл
	BOOL WriteLog(); // clear all cur lines
	BOOL WriteLog(CString& sSavedLogFile);
	//NMS : Устанавливает предельный размер лог файла
	CString SetLogSize (CString sSizeInKB);	
	//NMS : Возвращает кол-во сообщений в логе
	DWORD GetNoOfLines(void) const;
//NMS : Переменные
	//NMS : Путь к файлу лога 
	CString	m_sPFNLog;
	//NMS : Максимальный размер лог файла
	DWORD m_uSize;	// size of log file
	//NMS : Флаг о том, что последнее сообщение записывать в конец,
	//		по умолчанию пишется в начало (лог читается сверху вниз)
	BOOL m_bWriteLogInvert; // TRUE - last msg write to end
	CString m_sEventLogIOName;
	BOOL	m_bCopyLogFileWhenOverflow; // Semenov : Если файл лога превысил максимальный размер, 
										// то он копируется, а не перезаписывается

protected:
//NMS : Методы
	//NMS : Очищает список
	void ClearLines(void);
//NMS : Переменные
	//NMS : Лист, который хранит строки лога, до записи в файл	
	CList<CString,CString&> m_lstLines;
};

// AKV: Простой лог, без промежуточного сохранения. Интерфейс тот же, что и у CLogFile.
class CSimpleLogFile
{
public:
	CSimpleLogFile();
	~CSimpleLogFile();
	void AddLine(LPCSTR pStr);
	void AddLineF(LPCSTR lpszFormat,...);
	void AddLineF(LPCSTR lpszFormat,va_list argsList);
	void ViewLog();
	BOOL WriteLog();
	CString SetLogSize(const CString& sSizeInKB);
	DWORD GetNoOfLines(void) const { return 0; };
	CString	m_sPFNLog;
	DWORD m_uSize;
	BOOL m_bWriteLogInvert; // Ignore
protected:
	BOOL WriteLine(LPCTSTR cszLine);
	CMutex m_mutex;
	CString m_sLogCurrent; // SMU: for not call in AddLogLine write line to file 
};
// AKV End

#endif//LOG_FILE_H