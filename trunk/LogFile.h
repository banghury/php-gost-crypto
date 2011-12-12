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
//NMS : ������
	//NMS : ��������� ������� � ���
	void AddLine(LPCSTR pStr);
	void AddLineF(LPCSTR lpszFormat,...);
	void AddLineF(LPCSTR lpszFormat,va_list argsList);
	//NMS : ��������� ���������� ��� � ������� ��������
	void ViewLog();
	//NMS : ���������� ���������� ���� � ����
	BOOL WriteLog(); // clear all cur lines
	BOOL WriteLog(CString& sSavedLogFile);
	//NMS : ������������� ���������� ������ ��� �����
	CString SetLogSize (CString sSizeInKB);	
	//NMS : ���������� ���-�� ��������� � ����
	DWORD GetNoOfLines(void) const;
//NMS : ����������
	//NMS : ���� � ����� ���� 
	CString	m_sPFNLog;
	//NMS : ������������ ������ ��� �����
	DWORD m_uSize;	// size of log file
	//NMS : ���� � ���, ��� ��������� ��������� ���������� � �����,
	//		�� ��������� ������� � ������ (��� �������� ������ ����)
	BOOL m_bWriteLogInvert; // TRUE - last msg write to end
	CString m_sEventLogIOName;
	BOOL	m_bCopyLogFileWhenOverflow; // Semenov : ���� ���� ���� �������� ������������ ������, 
										// �� �� ����������, � �� ����������������

protected:
//NMS : ������
	//NMS : ������� ������
	void ClearLines(void);
//NMS : ����������
	//NMS : ����, ������� ������ ������ ����, �� ������ � ����	
	CList<CString,CString&> m_lstLines;
};

// AKV: ������� ���, ��� �������������� ����������. ��������� ��� ��, ��� � � CLogFile.
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