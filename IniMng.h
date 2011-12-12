// Class for work with ini files

// 05 feb 2008 ADD m_nLastSect
// 23 may 2006 MODIF GetKeysInSection and GetSections
// 20 jan 2006 MODIF Replace const CString& -> LPCSTR
// 10 nov 2005 MODIF include fast find line
// 10 nov 2005 MODIF all const CString&
// 01 nov 2004 MODIF GetKeysInSections : remove comment keys
// 11 oct 2004 ADD func for flags operations
// 08 oct 2004 DEL CIniMng::OpenFastAsRO
// 08 oct 2004 MODIF CIniMng::Save () const
// 08 oct 2004 ADD CString	GetPathFile ()
// 08 oct 2004 MODIF DWORD	GetParam ()
// 08 oct 2004 MODIF CIniMng (const CIniMng& ini)	{	m_dwParam = 0; this->Copy (ini);	};
// 08 oct 2004 ADD Clear ()
// 06 oct 2004 ADD FillFromString (CString sContent, DWORD dwParam = INIMNG_READ_ONLY)
// 05 oct 2004 ADD GetParam (CString& sPFRes, DWORD& dwParamRes)
// 24 aug 2004 ADD OpenWOClear (CString sPFIni)
// 24 aug 2004 MODIF FindStartSect 
// 18 feb 2004 ADD CIniBase
// 18 feb 2004 ADD const functions

#ifndef __INIMNG_H__
#define __INIMNG_H__

#pragma once

#include "FileMng.h"
#include "StringArrayEx.h"
// #include "IniRO.h"

#define		INIMNG_READ_ONLY					0x00000001
#define		INIMNG_CREATE_IF_NOT_EXIST		0x00000002
#define		INIMNG_CASE_SENS					0x00000004
#define		INIMNG_WAS_MODIF					0x00000008
 
class			CIniMng
{
public:
	CIniMng ();
	CIniMng (const CIniMng& ini)	{	m_dwParam = 0; this->Copy (ini);	};
	~CIniMng ();
	
	BOOL		Open (CString sPFIni, DWORD dwParam = INIMNG_CREATE_IF_NOT_EXIST);
	BOOL		OpenAtExeDir (CString sFN, DWORD dwParam = INIMNG_CREATE_IF_NOT_EXIST);
	BOOL 		Save () const;

	void		ClearCommentLines ();
	void		Clear ();
	void		Clear (const std::list<CPairString> lstNotClearingFields);

	void		FillFromString (CString sContent, CString sPF, DWORD dwParam = INIMNG_READ_ONLY);
	void		Copy (const CIniMng& iniSrc);

	void		SetValue (LPCSTR psSect, LPCSTR psKey, LPCSTR sValue);
	void		SetValue (LPCSTR psSect, LPCSTR psKey, char chValue)
	{
		SetValue (psSect, psKey, (CString)chValue);
	};

	CString	GetValue (LPCSTR psSect, LPCSTR psKey) const;
	CString	GetValue (LPCSTR psSect, LPCSTR psKey, LPCSTR psDefValue) const
	{
		CString sValue = GetValue (psSect, psKey);
		return !sValue.IsEmpty () ? sValue : psDefValue;
	}

// return FALSE if CStringArrayEx is empty
	BOOL		GetKeysInSection	(LPCSTR psSect, CStringArrayEx& saKeysRet) const;
	BOOL		GetSections			(CStringArrayEx &saSectRet) const;

	void		RemoveKey			(LPCSTR psSect, LPCSTR psKey);
	void		RemoveSection		(LPCSTR psSect);

	DWORD		GetParam () const	{	return m_dwParam;		};
	DWORD&	GetParam ()			{	return m_dwParam;		};

	CString	GetPathFile () const	{	return m_sPF;		};
	CString&	GetPathFile ()			{	return m_sPF;		};

	const CStringArrayEx& GetStringArray () const {	return m_saIni;	};

// for flags
#ifdef	_DEBUG
	BOOL		FlagIsTurnOn(DWORD dwFlag);
	void		FlagTurnOn	(DWORD dwFlag);
	void		FlagTurnOff	(DWORD dwFlag);
#else		// _DEBUG
	BOOL		FlagIsTurnOn(DWORD dwFlag)	{		return m_dwParam & dwFlag;	};
	void		FlagTurnOn	(DWORD dwFlag) {		m_dwParam |= dwFlag;			};
	void		FlagTurnOff	(DWORD dwFlag) {		m_dwParam &= ~dwFlag;		};
#endif	// _DEBUG

protected:
	int		FindLineForKey (LPCSTR psSect, LPCSTR psKey) const;
	int		FindStartSect  (LPCSTR psSect) const;
	
	int		FindLineForKey_NoCaseSense	(CString sSect, CString sKey) const;
	int		FindStartSect_NoCaseSense	(CString sSect) const;

	DWORD				m_dwParam;
	CStringArrayEx m_saIni;
	CString			m_sPF;
//	mutable int		m_nLastSect;
};

#endif // __INIMNG_H__
