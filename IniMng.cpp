// 28.02.2008 ADD		GetKeyForStrValue (const CIniMng& ini, CString sSect, const CString& sStrInValue)
// 10.01.2008 ADD		_USE_FAST_FIND_START_SECT_
// 04.07.2007 MODIF	GetKeysInSection for comment in start of line
#include "stdafx.h"
#include "IniMng.h"

#pragma warning (disable : 4786) 

#define _N_START_SIZE_	255

#define _USE_FAST_FIND_SECT_

#ifdef _USE_FAST_FIND_SECT_
//static int m_nLastSect;
#define _SET_BLOCK_FAST_FIND_START_SECT_(nNewStartSect) *(DWORD*)((int)&m_dwParam) = (nNewStartSect << 16 | (m_dwParam & 0x000000ff));
//#define _SET_BLOCK_FAST_FIND_START_SECT_(nNewStartSect) m_nLastSect = nNewStartSect;
#define _CHECK_BLOCK_FAST_FIND_START_SECT_(sSect)  \
	UINT nStartSect = m_dwParam >> 16; /* m_nLastSect; /*get start sect from first 16 bites */ \
	if (/*0 < nStartSect && */nStartSect < m_saIni.GetSize () && *(m_saIni[nStartSect]) == '[') \
	{ /* fast find start sect place */ \
		LPCSTR pStrLine = (LPCSTR)m_saIni[nStartSect] + 1; \
		LPCSTR pStrSect = sSect; \
		while (*(++pStrLine) == *(++pStrSect) && *pStrLine != '\0'); \
		if (*pStrLine == ']' && *pStrSect == '\0') \
		{\
			TRACE ("IniFastFind=%d\n",nStartSect);\
			return nStartSect;\
		}\
	};
#else	// _USE_FAST_FIND_SECT_
#define _SET_BLOCK_FAST_FIND_START_SECT_(nNewStartSect)
#define _CHECK_BLOCK_FAST_FIND_START_SECT_(sSect)
#endif	// _USE_FAST_FIND_SECT_

// SMU for example:
//	CString sKey = GetKeyForStrValue (m_iniEDO, STR_SECT_COL, "<NAME>Отметка</NAME>");
// now sKey will have value COL_CHECK
extern CString GetKeyForStrValue (const CIniMng& ini, CString sSect, const CString& sStrInValue);
CString GetKeyForStrValue (const CIniMng& ini, CString sSect, const CString& sStrInValue)
{
	class DummyForGetKeyForStrValue{ 
		public: int nStartSect; 
		DummyForGetKeyForStrValue(const CIniMng& ini, const CString& sSect) 
		{	FRIEND_PTR (pIni, ini, CIniMng, DummyForGetKeyForStrValue); 
			nStartSect = pIni->FindStartSect_NoCaseSense (sSect); };
		};

	DummyForGetKeyForStrValue dummy(ini, sSect);

	if (dummy.nStartSect == -1 || sStrInValue.IsEmpty ()) 
		return ""; // sect not found

	for (const CString* pStrLine = ini.GetStringArray ().Begin () + dummy.nStartSect + 1;
			pStrLine != ini.GetStringArray ().End(); pStrLine++)
	{
		if (*(LPCSTR)*pStrLine == '[')
			break; // it's new sect
		
		if (pStrLine->Find (sStrInValue) == -1)
			continue;
		
		CString sKey = CStringProc::GetStrBefore (*pStrLine, '=');
		if (sKey.Find (sStrInValue) >= 0 && // sStrInValue found in sKey
				CStringProc::GetStrAfter (*pStrLine, '=').Find (sStrInValue) == -1) // found in Value
			continue;

		return sKey;
	}
	return "";
}

CIniMng::CIniMng () 
{
	m_dwParam = 0;
}

CIniMng::~CIniMng () 
{
	Save ();
}

BOOL	CIniMng::OpenAtExeDir (CString sFN, DWORD dwParam)
{
	CString sPF;
	if (!CFileMng::GetDirExe (sPF))
		return FALSE;
	sPF += '\\';
	sPF += sFN;
	return Open (sPF, dwParam);
}


BOOL	CIniMng::Open (CString sPFIni, DWORD dwParam)
{
	m_sPF = sPFIni;
	m_dwParam = dwParam;
	if (!CFileMng::IsFileExist (sPFIni))
	{
		if (!(m_dwParam & INIMNG_CREATE_IF_NOT_EXIST))
			return FALSE;
		return TRUE;
	}
	
	CString sFile;
	if (!CStringProc::fRead (sPFIni, sFile))
		return FALSE;

	sFile.Replace ('\t',' ');
	sFile.Replace ('\r',' ');
	if (m_saIni.GetSize () == 0) 
		m_saIni.SetSize (_N_START_SIZE_, _N_START_SIZE_*10);
	
	m_saIni.FillFromString (sFile, '\n');
	m_saIni.RemoveEmptyString ();
	return TRUE;
}

int		CIniMng::FindStartSect_NoCaseSense (CString sSect) const
{
//	ASSERT (!(m_dwParam & INIMNG_CASE_SENS));
//	_CHECK_BLOCK_FAST_FIND_START_SECT_ (sSect);

//	int nStartSect = m_dwParam >> 8; /* get start sect from first 3 bytes */
//	if (0 < nStartSect && nStartSect < m_saIni.GetSize () && *(m_saIni[nStartSect]) == '[')
//	{ /* fast find start sect place */
//		LPCSTR pStrLine = (LPCSTR)m_saIni[nStartSect] + 1;
//		LPCSTR pStrSect = sSect;
//		while (*(++pStrLine) == *(++pStrSect) && *pStrLine != '\0');
//		if (*pStrLine == ']' && *pStrSect == '\0')
//			return nStartSect;
//	}

	sSect = (CString)'[' + sSect + ']';

	const CString *pStr__END__ = m_saIni.End ();
	for(const CString* pLine = m_saIni.Begin (); pLine != pStr__END__; pLine++)
	{
		if (*(LPCSTR)*pLine != '[')
			continue;
		
		if (CStringProc::IsIdent (*pLine, sSect)) 
		{
			int nNewStartSect = pLine - m_saIni.Begin ();
			_SET_BLOCK_FAST_FIND_START_SECT_(nNewStartSect);
			return nNewStartSect;
		}
	}
	
	return -1;
}

int		CIniMng::FindStartSect  (LPCSTR psSect) const
{
	if (*psSect == '\0') 
		return -1;

	_CHECK_BLOCK_FAST_FIND_START_SECT_(psSect);

	if (!(m_dwParam & INIMNG_CASE_SENS))
		return FindStartSect_NoCaseSense (psSect);

	const CString *pStr__END__ = m_saIni.End ();
	for(const CString* pLine = m_saIni.Begin (); pLine != pStr__END__; pLine++)
	{
		if (*(LPCSTR)*pLine != '[' || *((LPCSTR)*pLine + 1) != *psSect)
			continue;
		LPCSTR pStrLine = (LPCSTR)*pLine + 1;
		LPCSTR pStrSect = psSect;
		while (*(++pStrLine) == *(++pStrSect) && *pStrLine != '\0');
		if (*pStrLine == ']' && *pStrSect == '\0')
		{
			int nNewStartSect = pLine - m_saIni.Begin ();
			_SET_BLOCK_FAST_FIND_START_SECT_(nNewStartSect);
			return nNewStartSect;
		}
	}
	
// in CaseSens not found and must in NoCaseSens not found
	ASSERT (FindStartSect_NoCaseSense (psSect) == -1); 
	
	return -1;
}

int		CIniMng::FindLineForKey_NoCaseSense (CString sSect, CString sKey) const
{
//	ASSERT (!(m_dwParam & INIMNG_CASE_SENS));

	int nIndexSect = FindStartSect_NoCaseSense (sSect);
	if (nIndexSect == -1 || sKey.IsEmpty ()) 
		return -1;	

	sKey.MakeLower ();
	const int nKeyLen = sKey.GetLength ();

	const CString *pStr__END__ = m_saIni.End ();
	for(const CString* pLine = m_saIni.Begin () + nIndexSect + 1; pLine != pStr__END__; pLine++)
	{
		const int nCurLen = pLine->GetLength ();

		if (*(LPCSTR)*pLine == '[') // it's next section
			return -1;

		if (nCurLen > nKeyLen && (*pLine)[nKeyLen] == '=')
		{
			CString sTemp;
			sTemp = *pLine;
			sTemp.MakeLower ();
			
			if (strncmp ((LPCSTR)sKey, (LPCSTR)sTemp, nKeyLen) == 0)
			{
				int nNewStartSect = pLine - m_saIni.Begin ();
				return nNewStartSect;
			}
		}
	}
	return -1;
}

int		CIniMng::FindLineForKey (LPCSTR psSect, LPCSTR psKey) const
{
	if (!(m_dwParam & INIMNG_CASE_SENS))
		return FindLineForKey_NoCaseSense (psSect, psKey);

	int nIndexSect = FindStartSect (psSect);
	if (nIndexSect == -1 || *psKey == '\0') 
		return -1;	

	const CString *pLine__END__ = m_saIni.End ();
	ASSERT (m_saIni.Begin () + nIndexSect + 1 <= m_saIni.End ());
	for(const CString* pLine = m_saIni.Begin () + nIndexSect + 1; pLine != pLine__END__; pLine++)
	{
		if (*(LPCSTR)*pLine == '[')
			return -1;

		if (*(LPCSTR)*pLine != *psKey) 
			continue;
		
		LPCSTR pStrLine = (LPCSTR)*pLine;
		LPCSTR pStrKey = psKey;
		while (*(++pStrLine) == *(++pStrKey) && *pStrLine != '\0');
		if (*pStrLine == '=' && *pStrKey == '\0')
			return pLine - m_saIni.Begin ();

	}

// in CaseSens not found and must in NoCaseSens not found
	ASSERT (FindLineForKey_NoCaseSense (psSect, psKey) == -1);

	return -1;
}

CString	CIniMng::GetValue (LPCSTR psSect, LPCSTR psKey) const
{
	int nIndexKey = FindLineForKey (psSect, psKey);
	if (nIndexKey == -1)		return "";

	CString sRet((LPCSTR)(m_saIni[nIndexKey]) + strlen (psKey) + 1);
	int nFindComment = sRet.Find (';', 0);
	if (nFindComment != -1) sRet.Delete (nFindComment, sRet.GetLength() - nFindComment);
	sRet.TrimLeft ();
	sRet.TrimRight ();
	return sRet;
}

void		CIniMng::SetValue (LPCSTR psSect, LPCSTR psKey, LPCSTR psValue)
{
	if (*psSect == '\0' || *psKey == '\0' || m_dwParam & INIMNG_READ_ONLY)	
		return ;

	int nIndexSect = FindStartSect (psSect);
	CString sSectAdv(psSect);
	CString sNewLine = psKey + (CString)'=' + psValue;
	if (nIndexSect == -1)
	{
		sSectAdv = '[' + (CString)psSect + ']';
		m_saIni.Add (sSectAdv);
		m_saIni.Add (sNewLine);
		return;
	}

	int nIndexKey = FindLineForKey (psSect, psKey);
	if (nIndexKey == -1)
		m_saIni.InsertAt (nIndexSect + 1, sNewLine);
	else
		m_saIni[nIndexKey] = sNewLine;
}

BOOL	CIniMng::GetKeysInSection (LPCSTR psSect, CStringArrayEx& saKeysRet) const
{
	saKeysRet.RemoveAll ();
	int nSect = FindStartSect (psSect);
	if (nSect == -1) 	
		return FALSE;

	const CString *pLine__END__ = m_saIni.End ();

	for(const CString* pLine = m_saIni.Begin () + nSect + 1; pLine != pLine__END__; pLine++)
	{
		if (*(LPCSTR)*pLine == '[')
			break ;
		if (*(LPCSTR)(*pLine) != ';') // may be comment line
			saKeysRet.Add (*pLine);
	}

	for (int i = 0; i < saKeysRet.GetSize (); )
	{
// remove comment keys
		int nFindComent = saKeysRet[i].Find (';', 0);
		if (nFindComent >= 0)
			saKeysRet[i].Delete (nFindComent, saKeysRet[i].GetLength () - nFindComent);

// remove value fields
		int nFindEq = saKeysRet[i].Find ('=', 0);
		if (nFindEq >= 0)
			saKeysRet[i].Delete (nFindEq, saKeysRet[i].GetLength () - nFindEq);
		saKeysRet[i].TrimLeft ();
		saKeysRet[i].TrimRight ();
		if (saKeysRet[i].IsEmpty ()) 
		{
			// AKV: Похоже на багу
			//saKeysRet[i] = saKeysRet.GetSize () - 1;
			saKeysRet[i] = saKeysRet[saKeysRet.GetSize () - 1];
			saKeysRet.RemoveAt (saKeysRet.GetSize () - 1);
		}	else
			i++;
	}
	saKeysRet.RemoveEmptyString ();
	return saKeysRet.GetSize () > 0;
}

BOOL 	CIniMng::Save () const
{
	if (m_sPF.IsEmpty () || m_dwParam & INIMNG_READ_ONLY) 
		return FALSE;

	return  CStringProc::fWrite (m_sPF, m_saIni.GetAsString ("\r\n"));
//	FOR_ALL_CONST_STR (pStr, m_saIni)
//	{
//		sRes += *pStr;
//		sRes += "\r\n";
//	}
//	while (sRes.Replace (" \r\n", "\r\n")); // trim right
//	return  CStringProc::fWrite (m_sPF, sRes);
}

BOOL	CIniMng::GetSections (CStringArrayEx &saSectRet) const
{
	saSectRet.Copy (m_saIni);
	saSectRet.ProcWithHeader ("[", SARRST_STAY | 
		(m_dwParam & INIMNG_CASE_SENS ? 0 : SARRST_NOCASESENS));
	
	FOR_ALL_STR (pStr, saSectRet)
		*pStr = CStringProc::GetStrBtw (*pStr, '[', ']');
	
	saSectRet.RemoveEmptyString ();
	return saSectRet.GetSize () > 0;
}

void	CIniMng::RemoveKey (LPCSTR psSect, LPCSTR psKey)
{
	if (m_dwParam & INIMNG_READ_ONLY)	
		return ;
	
	int nIndexKey = FindLineForKey (psSect, psKey);
	if (nIndexKey == -1)	
		return ;
	m_saIni.RemoveAt (nIndexKey);
}

void	CIniMng::RemoveSection (LPCSTR psSect)
{
	if (m_dwParam & INIMNG_READ_ONLY)	return ;

	int nSect = FindStartSect (psSect);
	if (nSect == -1) 
		return ;

	m_saIni.RemoveAt (nSect);
	while (nSect < m_saIni.GetSize ())
	{
		if (!m_saIni[nSect].IsEmpty () && m_saIni[nSect][0] == '[')
			return ;
		m_saIni.RemoveAt (nSect);
	}
}

void	CIniMng::Copy (const CIniMng& iniSrc) 
{
	if (m_dwParam & INIMNG_READ_ONLY)	
		return ;

	m_saIni.RemoveAll ();
	m_saIni.Copy (iniSrc.m_saIni);
	m_dwParam = iniSrc.m_dwParam;
	m_sPF = iniSrc.m_sPF;
}

void	CIniMng::FillFromString (CString sContent, CString sPF, DWORD dwParam)
{
	if (m_dwParam & INIMNG_READ_ONLY)	
		return ;
	
	if (m_saIni.GetSize () == 0) 
		m_saIni.SetSize (_N_START_SIZE_, _N_START_SIZE_*10);

	m_dwParam = dwParam;
	m_sPF = sPF;

	sContent.Replace ('\t',' ');
	sContent.Replace ('\r',' ');
	m_saIni.FillFromString (sContent, '\n');
	m_saIni.RemoveEmptyString (); // trim left right and del if is empty
}

void	CIniMng::Clear ()
{
	m_saIni.RemoveAll ();
	m_dwParam = 0;
	m_sPF.Empty ();
}

void	CIniMng::Clear (const std::list<CPairString> lstNotClearingFields)
{
// save params
	std::list<CTripleString> lstFieldsAndValues;
	for (std::list<CPairString>::const_iterator itPair = lstNotClearingFields.begin ();
		itPair != lstNotClearingFields.end (); itPair++)
	{
			const CString sValue = this->GetValue (itPair->first, itPair->second);
			if (sValue.IsEmpty ()) 
				continue;

			lstFieldsAndValues.push_back (CTripleString (*itPair, sValue));
	}

	Clear ();

// restore params
	for (std::list<CTripleString>::iterator itTriple = lstFieldsAndValues.begin ();
		itTriple != lstFieldsAndValues.end (); itTriple++)
	{
		this->SetValue (itTriple->first.first, itTriple->first.second, itTriple->second);
	}		
}

void	CIniMng::ClearCommentLines ()
{
	m_saIni.ProcWithHeader (";", SARRST_REMOVE);
}

#ifdef	_DEBUG
BOOL	CIniMng::FlagIsTurnOn(DWORD dwFlag)
{
	ASSERT (0x00000100 > dwFlag); // check for fast find
	return m_dwParam & dwFlag;
};

void	CIniMng::FlagTurnOn	(DWORD dwFlag) 
{		
	ASSERT (0x00000100 > dwFlag); // check for fast find
	m_dwParam |= dwFlag;			
};

void	CIniMng::FlagTurnOff	(DWORD dwFlag) 
{		
	ASSERT (0x00000100 > dwFlag); // check for fast find
	m_dwParam &= ~dwFlag;		
};
#endif		// _DEBUG
