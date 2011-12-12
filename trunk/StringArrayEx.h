/************************************************************************\
	Class CStringArray as std::vector<CString>
	Author Simvolokov Michael. E-Mail: simvolokov@yandex.ru

   13 feb 2009 ADD	GetMID
   16 jan 2009 ADD   IsINN
   16 jan 2009 ADD   IsKPP
   16 jan 2009 ADD   IsThumb
   11 nov 2008 ADD	IsEMail (CString sEMail) and IsCodeIFNS (LPCSTR lpCode)
	05 jun 2008 ADD	CStringArrayEx& operator = (const CStringArrayEx& saSrc)
	18 feb 2008	ADD	GetStrAfterLastSymbol (LPCSTR lpStr, UCHAR ch)
   27 nov 2007 ADD	GetStrBtw (const CString& sSource, char chBefore, char chAfter)
   27 nov 2007 ADD	GetStrBefore (const CString& sSource, char chSeparator)
	27 nov 2007 ADD	GetStrAfter (const CString& sSource, char chSeparator)
   27 nov 2007 MODIF GetStrAfter (const CString& sSource, CString sSeparator)
	01 oct 2007 MODIF ClearWhiteSpaces (CString& str) using GetBuffer ReleaseBuffer
	05 sep 2007 MODIF GetSystemError : Add number of error code
   21 aug 2007 ADD	GetSystemError
   09 aug 2007 MODIFY ConvertStr2CTime for proc XMLTime format
   19 jul 2007 ADD	ConvertFullMonthNameToShort (CStringArrayEx& saMonthNameRet)
   19 jul 2007 ADD	FillByFullMonthName (CStringArrayEx& saMonthNameRet, BOOL bRusName)
   30 may 2007 ADD	Format(LPCTSTR lpszFormat,...)
   06 apr 2007 MODIF IsCorrectForMask for mask witout star
   05 mar 2007 ADD	IsCorrectForExtMask (CString sSrc, CString sMask, BOOL bCaseSense = FALSE)
   15 aug 2006 ADD	FillByLinesWithStrFragment (const CString& sAllText, const CString& sFragment)
   07 aug 2006 ADD	ConvertStr2CTime (CString sWithDotDDMMYYYY, CTime& tmRet)
   03 jul 2006 MODIF FillFromString (CString sSrc, CString sSeparator)
	21 nov 2005 ADD   FRIEND_PTR definition
	11 nov 2005 MODIF IsIdent (CString sOne, CString sTwo, const int nChar = -1)
   21 jun 2005 ADD	CStringArrayEx::RemoveDuplicate ()
	01 jun 2005 MODIF CStringArrayEx::Find	{ if (CStringProc::IsIdent ((LPCSTR)(*this)[nIndex], str)) }
	16 may 2005 ADD	RemoveTag (CString & sSrc, CString sTag)
	16 may 2005 ADD	GetTagList (const CString & sSrc, CStringArrayEx& saTagListRet)
   29 apr 2005 ADD	Constructor CStringArrayEx	(const CString sString, const char chSeparator)
	20 apr 2005 ADD   CopyItemsCorrectForMasks for one mask
	29 mar 2005 ADD   SetTagValue (CString& sSource, CString sTag, CString sValueNew)
	29 mar 2005 ADD   GetTagValue (CString& sSource, CString sTag)
	24 jan 2005 ADD	CStringArrayEx	(const CStringArray& saList)
	17 jan 2004 MODIF void RemoveEmptyString () // and TrimAll
	18 nov 2004 ADD	CopyItemsCorrectForMasks
   24 aug 2004 ADD	IsIdentWithWS
	16 jan 2004 ADD	GetStrBefore GetStrAfter
	22 dec 2003 MODIF FillFromString (CString sSrc, CString sSeparator)
	03 nov 2003 ADD 	void SetStrForTag (CString& sSource, CString sTag, CString sContent)
	03 nov 2003 ADD 	void GetStrForTag (const CString& sSource, CString sTag)
\************************************************************************/

#ifndef __STRING_ARRAY_EX__
	#define __STRING_ARRAY_EX__

#define		FOR_ALL_STR(pStr,arr) 	for(CString* pStr=arr.Begin(), *pStr##__END__=arr.End(); pStr!=pStr##__END__; pStr++)
#define		FOR_ALL_CONST_STR(pStr,arr) 	for(const CString* pStr=arr.Begin(), *pStr##__END__=arr.End(); pStr!=pStr##__END__; pStr++)

#define		FRIEND_PTR(pRes, Object, NameClassProtect, NameClassCur) class NameClassProtect##Friend : public NameClassProtect { friend class NameClassCur; }; NameClassProtect##Friend * pRes = (NameClassProtect##Friend *)&(Object);

#define		SARRST_REMOVE		0x0001
#define		SARRST_STAY			0x0002
#define		SARRST_NOCASESENS	0x0004
#define		SARRST_EXT_MASK	0x0008
#define		SARR_NCST		(SARRST_NOCASESENS | SARRST_STAY)
#define		SARR_NCRM		(SARRST_NOCASESENS | SARRST_REMOVE)

#include <algorithm>
#include <vector>
#include <stdlib.h>

typedef std::pair<CString, CString> CPairString;
typedef std::pair<CPairString, CString> CTripleString;

class CStringArrayEx;

class CStringProc
{
public:
	static BOOL	ConvertStr2CTime (const CString& sTime, CTime& tmRet);
	static BOOL	IsEMail (CString sEMail);
	static BOOL	IsCodeIFNS (LPCSTR lpCode);
	static BOOL IsINN (const CString& strIn);
	static BOOL IsKPP (const CString& strIn);
	static BOOL IsThumb (const CString& strIn);
	static BOOL ConvertCStringToCTime(const CString& sTime, CTime& tmRet); //КПМ: Для конвертации DD.MM.YYYY HH:MM:SS

	static CString GetMID (const CString& sPostfix, int nMaxLen = 0);

	// GAV : Конвертирует дату из формата DD.MM.YYY в YYYY.MM.DD ()
	static BOOL GetDateString4Compare(const CString &sDate, CString &sResult);
	
	static LPCSTR GetStrAfterLastSymbol (LPCSTR lpStr, UCHAR ch)
	{
		LPCSTR pCur = lpStr, pLast = NULL;
		while (*pCur != '\0')
			if ((UCHAR)*(pCur++) == ch)
				pLast = pCur;

		return pLast;
	}

	static void	RemoveTag (CString & sSrc, CString sTag)
	{
		while (sSrc.Find ((CString)'<' + sTag + '>') >= 0)
		{
			CString sTagValue = CStringProc::GetTagValue (sSrc, sTag);
			sSrc.Replace ((CString)'<' + sTag + '>' + sTagValue + "</" + sTag + '>', "");
		}
	};

	static void	GetTagList (const CString & sSrc, CStringArray& saTagListRet);

	static void SetTagValue (CString& sSource, CString sTag, CString sValueNew)
	{
	#define _N_ADD_LEN_OPEN_TAG_		2
	#define _N_ADD_LEN_CLOSE_TAG_		3
		if (sTag.IsEmpty ()) 
			return ;

		CString sOpenTag((CString)'<' + sTag + '>');
		CString sCloseTag((CString)"</" + sTag + '>');
		int nLenTag = sTag.GetLength ();
		// AKV: Для совместимости с правильным SDK
		//LPSTR pStart = strstr (sSource, (LPCSTR)sOpenTag);
		LPSTR pStart = strstr (sSource.GetBuffer(sSource.GetLength()), (LPCSTR)sOpenTag);
		LPCSTR pEnd = NULL;
		if (pStart != NULL)
		{
			pStart += nLenTag + _N_ADD_LEN_OPEN_TAG_;
			pEnd = strstr (pStart, (LPCSTR)sCloseTag);
		}
		
		int nSourceLen;
		const int nLenValueNew = sValueNew.GetLength ();
		if (pStart && pEnd) // tag found, cutting old tags and value
		{
			if (nLenValueNew == (int)(pEnd - pStart)) // len of old and new value is equiv
			{
				pEnd = (LPCSTR)sValueNew;
				while (*pEnd != '\0')	*(pStart++) = *(pEnd++);
				return ;
			}
			pStart -= nLenTag + _N_ADD_LEN_OPEN_TAG_;
			pEnd += nLenTag + _N_ADD_LEN_CLOSE_TAG_;
			while (*pEnd != '\0')	*(pStart++) = *(pEnd++);
			nSourceLen = (int)(pStart - (LPCSTR)sSource);
		}	else		// tag not found. Add new value to end.
			nSourceLen = sSource.GetLength ();

	// setup pStart to end of string
		pStart = (LPSTR)sSource.GetBufferSetLength (nSourceLen + 2*nLenTag + 
			_N_ADD_LEN_OPEN_TAG_ + _N_ADD_LEN_CLOSE_TAG_ + nLenValueNew) + nSourceLen;
	// copy tag and value to end of string
		pEnd = (LPCSTR)sOpenTag;
		while (*pEnd != '\0') *(pStart++) = *(pEnd++);

		pEnd = (LPCSTR)sValueNew; 
		while (*pEnd != '\0') *(pStart++) = *(pEnd++);

		pEnd = (LPCSTR)sCloseTag;
		while (*pEnd != '\0') *(pStart++) = *(pEnd++);
	};

	static CString GetTagValue (const CString& sSource, CString sTag)
	{
		if (sTag.IsEmpty ())
			return _T("");

		CString sValue;
		sValue.Format(_T("<<%s>"),sTag);

		int npos = sSource.Find((LPCTSTR)((LPCTSTR)sValue + 1));
		if(npos == -1)
			return _T("");
		npos += sTag.GetLength() + 2;
		sValue.SetAt (1, '/');
		int npos_end = sSource.Find(sValue, npos);
		if (npos_end < 0)
			return _T("");
		return sSource.Mid(npos, npos_end - npos);
	};

	static void	ClearWhiteSpaces (CString& str)	
//	{		CStringProc::Clear (str);	};
//	static void	Clear (CString& str)
	{
		
		char* pStr = str.GetBuffer (0); // (LPSTR)(LPCSTR)str;
		while (*pStr != '\0')
		{
			if (*pStr == '\n' || *pStr == '\r' || *pStr == '\t' ||*pStr == '\n')
				*pStr = ' ';
			pStr++;
		}
		str.ReleaseBuffer ();

		while (str.Replace ("  ", " "));
		str.TrimLeft ();
		str.TrimRight();
	};

// Is identical strings with white spaces
	static BOOL	IsIdentWithWS (CString sOne, CString sTwo, const int nChar = -1)
	{
		if (nChar == 0) return TRUE;
		sOne.MakeLower	();		
		sTwo.MakeLower	();	
		return nChar < 0 ? sOne == sTwo : 0 == strncmp (sOne, sTwo, nChar);
	};

	static BOOL	IsIdent (CString sOne, CString sTwo, const int nChar = -1)
	{
		if (nChar == 0) return TRUE;
		if (TRUE) //nChar != - 1)
		{
			CStringProc::ClearWhiteSpaces (sOne);
			CStringProc::ClearWhiteSpaces (sTwo);
			sOne.MakeLower	();		
			sTwo.MakeLower	();	
			
			return nChar < 0 ? sOne == sTwo : 0 == strncmp (sOne, sTwo, nChar);
		};
/*
// one string
		LPCSTR pSrcOne = (LPCSTR)sOne;
		LPTSTR pDstOne = (LPTSTR)pSrcOne;
		if (pSrcOne == 0) pSrcOne = pDstOne;

		BOOL wrSpace = *pSrcOne != ' ';
		for (; *pSrcOne; pSrcOne++)
			if (*pSrcOne != ' ')  { *pDstOne++ = *pSrcOne; wrSpace = TRUE;  }
		else if (wrSpace) { *pDstOne++ = *pSrcOne; wrSpace = FALSE; }

		if ((LPCSTR)sOne == pDstOne || wrSpace)
			*pDstOne = '\0';
		else
			*--pDstOne = '\0';

	// two string
		LPCSTR pSrcTwo = (LPCSTR)sTwo;
		LPTSTR pDstTwo = (LPTSTR)pSrcTwo;
		if (pSrcTwo == 0) pSrcTwo = pDstTwo;

		wrSpace = *pSrcTwo != ' ';
		for (; *pSrcTwo; pSrcTwo++)
			if (*pSrcTwo != ' ')  { *pDstTwo++ = *pSrcTwo; wrSpace = TRUE;  }
			else if (wrSpace) { *pDstTwo++ = *pSrcTwo; wrSpace = FALSE; }

		if ((LPCSTR)sTwo == pDstTwo || wrSpace)
			*pDstTwo = '\0';
		else
			*--pDstTwo = '\0';

	// compare in different case
		if (pDstOne - (LPCSTR)sOne != pDstTwo - (LPCSTR)sTwo) // compare length
			return FALSE;

		return stricmp ((LPCSTR)sOne, (LPCSTR)sTwo) == 0;
*/
	};

	static	BOOL	HavePrefix (
		const CString& sSrc, CString sPrefix, const BOOL bCaseSens = FALSE)
	{
		const int nLenPrefix = sPrefix.GetLength ();
		if (nLenPrefix > sSrc.GetLength ()) 
			return FALSE;

		if (nLenPrefix == 0) 
			return TRUE;

		if (bCaseSens) 
			return 0 == strncmp (sSrc, sPrefix, nLenPrefix);
		
		CString sTemp(sSrc);
		sTemp.MakeLower ();
		sPrefix.MakeLower ();
		return 0 == strncmp (sTemp, sPrefix, nLenPrefix);
	};

	static	BOOL	HavePostfix (
		const CString& sSrc, CString sPostfix, const BOOL bCaseSens = FALSE)
	{
		const int nLenPostfix = sPostfix.GetLength ();
		const int nLenSrc = sSrc.GetLength ();
		if (nLenPostfix > nLenSrc)
			return FALSE;

		if (nLenPostfix == 0) 
			return TRUE;
		
		if (bCaseSens)
			return 0 == strncmp ((LPCSTR)sSrc + nLenSrc - nLenPostfix, 
				sPostfix, nLenPostfix);		
		
		return  CStringProc::IsIdent ((LPCSTR)sSrc + nLenSrc - nLenPostfix, 
						sPostfix, nLenPostfix);
	};

	static	void InsertSpaces (CString & str, const int nInField = 3)
	{
		ASSERT (nInField > 0);
		const int nLen = str.GetLength ();
		for (int nIndex = 1 ; nIndex < nLen; nIndex++)
				if ((nLen - nIndex)%nInField == 0)
					str.Insert (nIndex++, ' ');		
	}

	static	void		ClearPaperNameFromBadSymbol (CString& sPaperName)
	{
		for (LPSTR pStr = (LPSTR)(LPCSTR)sPaperName; *pStr != '\0'; pStr++)
			if (/* *pStr == '.' || */ *pStr == '*' || *pStr == '?' || 
					*pStr == '\\' || *pStr == '/' || *pStr == ':')
				*pStr = ' ';
	};

	static	CString GetStrBtw (const CString & sSrc, CString sBefore, 
		CString sAfter, const BOOL bAtStartOfLine = FALSE)
	{
		int nPosStart = -1, nPosEnd;
		CString sRet;
		while (TRUE) 
		{
			if (-1 == (nPosStart = sSrc.Find (sBefore, ++nPosStart)))
				break;

			if (bAtStartOfLine && !(nPosStart == 0 || sSrc[nPosStart-1] == '\n'))
				continue;

			nPosStart += sBefore.GetLength ();
			if (-1 != (nPosEnd = sSrc.Find (sAfter, nPosStart)) && nPosEnd != nPosStart)
				sRet = sSrc.Mid(nPosStart, (nPosEnd - nPosStart));
//				strncpy_s (sRet.GetBufferSetLength (nPosEnd - nPosStart), nPosEnd - nPosStart,
//							(LPCSTR)sSrc + nPosStart, nPosEnd - nPosStart);
			break;
		}
		return sRet;		
	}

	static	void SetStrBtw (CString & sSrc, CString sBefore, CString sAfter, const CString sContent)
	{
		CString sOld = sBefore + GetStrBtw (sSrc, sBefore, sAfter) + sAfter;
		CString sNew = sBefore + sContent + sAfter;
		if (-1 == sSrc.Find (sOld,0)) 
			sSrc += sNew;
		else
			sSrc.Replace (sOld, sNew);
	}

	static BOOL	fRead (const CString& fName, CString & sRes)
	{
		CFile fl;
		if (!fl.Open (fName, CFile::modeRead | CFile::shareDenyWrite))
			return FALSE;

		sRes.Empty ();

		const size_t __MAX_BUF_SIZE_FREAD__(static_cast<size_t>(fl.GetLength()));
#if _MSC_VER > 1200
		sRes.Preallocate(__MAX_BUF_SIZE_FREAD__);
#endif
		std::vector<char> sBuf(__MAX_BUF_SIZE_FREAD__ + 1);

		UINT nBytesRead;
		while(0 != (nBytesRead = fl.Read (&*sBuf.begin(), __MAX_BUF_SIZE_FREAD__)))
		{
			sBuf[nBytesRead] = '\0';
			sRes+=(&*sBuf.begin());
		}

		fl.Close ();
		return TRUE;
	};

	static BOOL	fWrite (const CString& sFName, const CString& sText) 
	{
		CFile fl;
		if (!fl.Open (sFName, CFile::modeWrite | CFile::modeCreate))
			return FALSE;

		fl.Write ((LPCSTR)sText, sText.GetLength());
		fl.Close ();
		
		return TRUE;
	};

	static void AddLine (CString& sSource, const CString sAdd)
	{
		if (sAdd.IsEmpty ())		return ;
		if (!sSource.IsEmpty ())		sSource += '\n';
		sSource += sAdd;
	};	

	static void SetStrForTag (CString& sSource, CString sTag, CString sContent)
	{
		CStringProc::SetStrBtw (sSource, 
			(CString)'<' + sTag + '>', (CString)"</" + sTag + '>', sContent);
	};

	static CString GetStrForTag (const CString& sSource, CString sTag)
	{
		return CStringProc::GetStrBtw (sSource, 
			(CString)'<' + sTag + '>', (CString)"</" + sTag + '>');
	};

	static CString GetStrBefore (const CString& sSource, CString sSeparator)
	{
		int nFind = sSource.Find (sSeparator, 0);
		return sSource.Left (nFind);
	};

	static CString GetStrBefore (const CString& sSource, char chSeparator)
	{
		int nPos = sSource.Find (chSeparator);
		if (nPos == -1)
			return "";
		return sSource.Left (nPos);
	};

	static CString GetStrAfter (const CString& sSource, char chSeparator)
	{
		int nPos = sSource.Find (chSeparator);
		if (nPos == -1)
			return "";
		return (CString)((LPCSTR)sSource + nPos + 1);
	};

	static CString GetStrBtw (const CString& sSource, char chBefore, char chAfter)
	{
		return GetStrBefore (GetStrAfter (sSource, chBefore), chAfter);
	}

	static CString GetStrAfter (const CString& sSource, CString sSeparator)
	{
		CString sBefore = GetStrBefore (sSource, sSeparator);
		if (sBefore.IsEmpty () && !CStringProc::HavePrefix (sSource, sSeparator))
			return "";

		CString sRet (sSource);
		sRet.Delete (0, sBefore.GetLength () + sSeparator.GetLength ());
		return sRet;
	};

	static	CString	GetStrDateTimeCur	() 
	{	return GetStrDateTimeCur	(CTime::GetCurrentTime ());	};

	static	CString	GetStrDateTimeCur	(CTime time, BOOL bUsualyFmt = FALSE)
	{	return time.Format(bUsualyFmt ? "%d.%m.%Y %H:%M" : "%b%d_%y %H:%M");		};

	// Semenov : Текущее время в виде расширения для файла
	static	CString	GetStrFileExtDateTimeCur()
	{	return CTime::GetCurrentTime().Format( ".%d_%m_%Y_%H_%M_%S");};

	static	CString	GetStrDateCur	() 
	{	return GetStrDate		(CTime::GetCurrentTime ());	};
	
	static	CString	GetStrDate		(CTime time, BOOL bUsualyFmt = FALSE)
	{	return time.Format(bUsualyFmt ? "%d.%m.%Y" : "%b%d_%y");		};


	static	void		FillByFullMonthName (CStringArray& saMonthNameRet, BOOL bRusName)
	{
		saMonthNameRet.SetSize (12);
		saMonthNameRet[0] = bRusName ? "Январь" :	"January";
		saMonthNameRet[1] = bRusName ? "Февраль":	"February";
		saMonthNameRet[2] = bRusName ? "Март"	 :	"March";
		saMonthNameRet[3] = bRusName ? "Апрель" :	"April";
		saMonthNameRet[4] = bRusName ? "Май"	 :	"May";
		saMonthNameRet[5] = bRusName ? "Июнь"	 :	"June";
		saMonthNameRet[6] = bRusName ? "Июль"	 :	"July";
		saMonthNameRet[7] = bRusName ? "Август" : "August";
		saMonthNameRet[8] = bRusName ? "Сентябрь" : "September";
		saMonthNameRet[9] = bRusName ? "Октябрь": "October";
		saMonthNameRet[10] = bRusName ? "Ноябрь" : "November";
		saMonthNameRet[11] = bRusName ? "Декабрь": "December";
	};
	
	static	void		ConvertFullMonthNameToShort (CStringArray& saMonthName)
	{
		for (int i = 0; i < saMonthName.GetSize (); i++)
			if (saMonthName[i].GetLength () > 3) 
				saMonthName[i] = saMonthName[i].Left (3);
	}

	static	void		ConvertShortMonthToRus (CString& sDate)
	{
		sDate.Replace ("Jan", "Янв");
		sDate.Replace ("Feb", "Фев");
		sDate.Replace ("Mar", "Мар");
		sDate.Replace ("Apr", "Апр");
		sDate.Replace ("May", "Май");
		sDate.Replace ("Jun", "Июн");
		sDate.Replace ("Jul", "Июл");
		sDate.Replace ("Aug", "Авг");
		sDate.Replace ("Sep", "Сен");
		sDate.Replace ("Oct", "Окт");
		sDate.Replace ("Nov", "Ноя");
		sDate.Replace ("Dec", "Дек");
	};

	static	void		ConvertRusShortMonthToFull (CString& sDate)
	{
		sDate.Replace ("Янв","Январь");
		sDate.Replace ("Фев","Февраль");
		sDate.Replace ("Мар","Март");
		sDate.Replace ("Апр","Апрель");
		sDate.Replace ("Май","Май");
		sDate.Replace ("Июн","Июнь");
		sDate.Replace ("Июл","Июль");
		sDate.Replace ("Авг","Август");
		sDate.Replace ("Сен","Сентябрь");
		sDate.Replace ("Окт","Октябрь");
		sDate.Replace ("Ноя","Ноябрь");
		sDate.Replace ("Дек","Декабрь");
	};

	static	void		ConvertRusMonthToNum (CString& sDate)
	{
		sDate.Replace ("Янв", "01");
		sDate.Replace ("Фев", "02");
		sDate.Replace ("Мар", "03");
		sDate.Replace ("Апр", "04");
		sDate.Replace ("Май", "05");
		sDate.Replace ("Июн", "06");
		sDate.Replace ("Июл", "07");
		sDate.Replace ("Авг", "08");
		sDate.Replace ("Сен", "09");
		sDate.Replace ("Окт", "10");
		sDate.Replace ("Ноя", "11");
		sDate.Replace ("Дек", "12");
	};

	// AKV: Пусть будут и английские
	static	void		ConvertShortMonthToNum (CString& sDate)
	{
		sDate.Replace (_T("Jan"), _T("01"));
		sDate.Replace (_T("Feb"), _T("02"));
		sDate.Replace (_T("Mar"), _T("03"));
		sDate.Replace (_T("Apr"), _T("04"));
		sDate.Replace (_T("May"), _T("05"));
		sDate.Replace (_T("Jun"), _T("06"));
		sDate.Replace (_T("Jul"), _T("07"));
		sDate.Replace (_T("Aug"), _T("08"));
		sDate.Replace (_T("Sep"), _T("09"));
		sDate.Replace (_T("Oct"), _T("10"));
		sDate.Replace (_T("Nov"), _T("11"));
		sDate.Replace (_T("Dec"), _T("12"));
	};

	static	BOOL		IsCorrectForMask (const CString& sSrc, CString sMask)
	{
		int nPosStar = sMask.Find ('*', 0);
		if (nPosStar == -1) 
			return CStringProc::HavePrefix (sSrc, sMask);

		const CString sPrefix	=	sMask.Left (nPosStar);
		const CString sPostfix	=	sMask.Right (sMask.GetLength () - nPosStar - 1);

		return CStringProc::HavePrefix (sSrc, sPrefix) &&
				CStringProc::HavePostfix (sSrc, sPostfix);
	};

	static BOOL IsCorrectForExtMask (CString sSrc, CString sMask, BOOL bCaseSense = FALSE)
	{	//bool PatternMatch(const char* s, const char* mask)
		if (!bCaseSense) 
		{
			sSrc.MakeLower ();
			sMask.MakeLower ();
		}
		LPCSTR pSrc = (LPCSTR)sSrc, pMask = (LPCSTR)sMask;
		LPCSTR pCharSrc = 0, pCharMask = 0;
		for (; *pSrc && *pMask != '*'; pMask++,pSrc++)
			if (*pMask != *pSrc && *pMask != '?') 
				return FALSE;

	  for (;;) 
	  {
		 if (!*pSrc)
		 { 
			 while (*pMask == '*') 
				 pMask++; 
			 return !*pMask; 
		 }
    
		 if (*pMask == '*') 
		 { 
			 if (!*++pMask) 
				 return TRUE;
			 pCharMask = pMask;
			 pCharSrc = pSrc + 1; 
			 continue; 
		 }
    
		 if (*pMask == *pSrc || *pMask == '?') 
		 { 
			 pMask++, pSrc++;
			 continue; 
		 }
    
		 pMask = pCharMask; 
		 pSrc = pCharSrc++;
	  }
	  return FALSE;
	}
		//NMS :  Format
	static CString Format(LPCTSTR lpszFormat,...)
	{
		ASSERT(lpszFormat!=NULL);
		CString strResult;
		try
		{		
			if (lpszFormat!=NULL)
			{
				va_list pArgList=NULL;
				va_start(pArgList,lpszFormat);
				strResult.FormatV(lpszFormat,pArgList);
				va_end(pArgList);
			}
		}
		catch(...)
		{
			strResult.Empty();			
			ASSERT(FALSE);
		}
		return strResult;
	}

	//NMS : Возвращает описание системной ошибки по коду
	static CString GetSystemError(const DWORD dwErrorCode=::GetLastError())
	{
		CString strResult;
		LPVOID lpMsgBuf=NULL;
		::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
						FORMAT_MESSAGE_FROM_SYSTEM,
						NULL,
						dwErrorCode,
						MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
						(LPTSTR) &lpMsgBuf,
						0,
						NULL);
		strResult=(LPCTSTR)lpMsgBuf;
		strResult.TrimRight("\n");
		strResult.TrimRight("\r");
// SMU: add number of error code
		CString sCode;
		sCode.Format ("0x%.8x", dwErrorCode);
		strResult += (CString)" (Код ошибки = " + sCode + ')';
		::LocalFree(lpMsgBuf);
		return strResult;
	}

	// AKV : Из Multibyte в TString
	static CString MultiByteToStringT(LPCSTR cszIn, UINT uiCodePage = CP_ACP)
	{
		ASSERT(cszIn);
#ifdef _UNICODE
		int iBufSize = ::MultiByteToWideChar(uiCodePage, MB_ERR_INVALID_CHARS, cszIn, -1, NULL, 0);
		if (iBufSize == 0)
			return CStringProc::GetSystemError();
		CString strRes;
		LPWSTR wszRes = strRes.GetBuffer(iBufSize + 1);
		iBufSize = ::MultiByteToWideChar(uiCodePage, MB_ERR_INVALID_CHARS, cszIn, -1, wszRes, iBufSize + 1);
		strRes.ReleaseBuffer();
		if (iBufSize == 0)
			return CStringProc::GetSystemError();
		return strRes;
#else
		return cszIn;
#endif
	}

	// AKV : Из WideChar в TString
	static CString WideCharToStringT(LPCWSTR cwszIn, UINT uiCodePage = CP_ACP)
	{
		ASSERT(cwszIn);
#ifndef _UNICODE
		int iBufSize = ::WideCharToMultiByte(uiCodePage, 0, cwszIn, -1,
											NULL, 0, NULL, NULL);
		if (iBufSize == 0)
			return CStringProc::GetSystemError();
		CString strRes;
		LPSTR szRes = strRes.GetBuffer(iBufSize + 1);
		iBufSize = ::WideCharToMultiByte(uiCodePage, MB_ERR_INVALID_CHARS, cwszIn, -1,
											szRes, iBufSize + 1, NULL, NULL);
		strRes.ReleaseBuffer();
		if (iBufSize == 0)
			return CStringProc::GetSystemError();
		return strRes;
#else
		return cwszIn;
#endif
	}
};

class CStringArrayEx : public CStringArray
{
public:
	CStringArrayEx	()	{};
	CStringArrayEx	(const CStringArrayEx& saList)	{ this->Copy (saList); };
	CStringArrayEx	(const CStringArray& saList)		{ this->Copy (saList); };
	CStringArrayEx	(const CString sString, const char chSeparator)		
		{ this->FillFromString (sString, chSeparator); };
	
	CStringArrayEx& operator = (const CStringArrayEx& saSrc) {	this->Copy (saSrc); return *this; }

	~CStringArrayEx	()	{};
	
	CString*	Begin	()
		{	return GetData ();	};
	
	const CString*	Begin	()	const
		{	return GetData ();	};

	CString*	End		()
		{	return GetData () + this->GetSize ();	};
	
	const CString*	End		()	const
		{	return GetData () + this->GetSize ();	};

	void	RemoveDuplicate ()
	{
		for (int i = 0; i < this->GetSize (); i++)
			for (int j = i+1; j < this->GetSize (); )
				if (CStringProc::IsIdent ((*this)[i], (*this)[j]))
				{
					this->RemoveAt (j);
				}	else j++;
	};

	void		ForEach	(void	Func (CString & str))
		{
			CString * pStr = Begin (), * pEnd = End ();
			while (pStr != pEnd)
				Func (*pStr++);
		};
		
	void		ForEach	(void	Func (const CString & str)) const
		{
			const CString * pStr = Begin ();
			const CString * pEnd = End ();
			while (pStr != pEnd)
				Func (*pStr++);
		};

	int 		Find	(const CString& str, BOOL bCaseSens = FALSE) const
		{
			if (str.IsEmpty ())
				return -1;

			if (bCaseSens)
			{
				for (int nIndex = 0; nIndex < this->GetSize (); nIndex++)
					if (*(LPCSTR)(*this)[nIndex] == *(LPCSTR)(LPCSTR)str &&
							(*this)[nIndex] == (LPCSTR)str)
						return nIndex;
			}	else	{
				for (int nIndex = 0; nIndex < this->GetSize (); nIndex++)
					if (CStringProc::IsIdent ((LPCSTR)(*this)[nIndex], str))
						return nIndex;
			}
			return -1;
		};

	void		FillFromString (const CString& sSrc, char chSep)
	{
			this->RemoveAll ();
			int nPosPrev = 0, nPosCur;
			while (*((LPCSTR)sSrc + nPosPrev) != '\0' && sSrc[nPosPrev] == chSep) 
				nPosPrev++;

//			TRACE("\n\nFill From String\n");
			while (TRUE)
			{
				if (-1 == (nPosCur = sSrc.Find (chSep, nPosPrev)))
					nPosCur = sSrc.GetLength ();

				this->Add(sSrc.Mid(nPosPrev, nPosCur - nPosPrev));
				if (*((LPCSTR)sSrc + nPosCur) == '\0')
					break;

				nPosPrev = nPosCur + 1;
			}			
		
	};
	
	//NMS : Добавил параметр bAddEmptyLine - если TRUE, тогда добавляет пустые строки
	void		FillFromString (CString sSrc, CString sSeparator,const BOOL bAddEmptyLine=FALSE)
		{
			this->RemoveAll ();
			if (sSeparator.IsEmpty ()) 
				return ;

			int nPos = 0;
			const int nLenSrc = sSrc.GetLength ();
			const int nLenSeparator = sSeparator.GetLength ();
			if (nLenSeparator == 1) 
			{
				this->FillFromString (sSrc, (char)*(LPCSTR)sSeparator);
				return ;
			}
			while (TRUE)
			{
				if (-1 == (nPos = sSrc.Find (sSeparator, 0)))
					nPos = nLenSrc;

				const CString sItem = sSrc.Left (nPos);
				if (bAddEmptyLine!=FALSE)
				{
					this->Add (sItem);
				}
				else
				{				
					if (!sItem.IsEmpty ())
					{
						this->Add (sItem);
					}
				}
				
				if (nPos + nLenSeparator >= nLenSrc)
					break;

				sSrc.Delete (0, nPos + nLenSeparator);
			}			
		};

		void FillByLinesWithStrFragment (const CString& sAllText, 
													const CString& sFragment)
		{
			this->RemoveAll ();
			int nPos = -1;
			while ((nPos = sAllText.Find (sFragment, ++nPos)) != -1)
			{
				LPCSTR pStart = (LPCSTR)sAllText + nPos;
				while (*pStart != '\n' && pStart != (LPCSTR)sAllText)
					pStart--;

				int nPosStart = (pStart - (LPCSTR)sAllText);

				LPCSTR pEnd = (LPCSTR)sAllText + nPos;
				while (*pEnd != '\n' && *pEnd != '\0')
					pEnd++;

				this->Add ("");
#if _MFC_VER >= 0x0700
				strncpy_s ((*this)[this->GetSize () - 1].GetBufferSetLength (
					(int)(pEnd - /*(int)*/pStart)), (int)(pEnd - /*(int)*/pStart), pStart, (int)(pEnd - /*(int)*/pStart));
#else
				strncpy((*this)[this->GetSize () - 1].GetBufferSetLength (
					(int)(pEnd - /*(int)*/pStart)), pStart, (int)(pEnd - /*(int)*/pStart));
#endif
			}
		};


	CString		GetAsString (const CString sSeparator = "\n", const BOOL bAddLastSeparator = TRUE) const
		{
			const CString* pStr = Begin ();
			const CString* pEnd = End ();
			CString sRet;
			while (pStr != pEnd)
			{
				sRet += *pStr++;
				sRet += sSeparator;
			}
			if (!bAddLastSeparator && sRet.GetLength () > 0 && !sSeparator.IsEmpty ())
				sRet.Delete (sRet.GetLength () - sSeparator.GetLength (), sSeparator.GetLength ());

			return sRet;
		}

	void		RemoveEmptyString () // and TrimAll
		{
			for (int i = 0; i < GetSize (); )
			{
				(*this)[i].TrimLeft ();
				(*this)[i].TrimRight ();
				if ((*this)[i].IsEmpty ())
					RemoveAt (i);
				else
					i++;
			}
		}

	void		ProcWithHeader (const CString & sHead, DWORD dwStyle = 0)
		{
			int nPosStar = sHead.Find ('*', 0);
			if (nPosStar == -1) 
				nPosStar = sHead.GetLength ();

			const CString sPrefix	=	sHead.Left (nPosStar);
			const CString sPostfix	=	sHead.Right (sHead.GetLength () - nPosStar - 1);

			for (int i = 0; i < GetSize ();)
			{
				BOOL  bIdent = 
					(dwStyle & SARRST_EXT_MASK) ?
					CStringProc::IsCorrectForExtMask ((*this)[i], sHead, !(dwStyle & SARRST_NOCASESENS)) :
					CStringProc::HavePrefix ((*this)[i], sPrefix, !(dwStyle & SARRST_NOCASESENS)) &&
					CStringProc::HavePostfix ((*this)[i], sPostfix, !(dwStyle & SARRST_NOCASESENS));

				if (bIdent && (dwStyle & SARRST_REMOVE))
				{
					this->RemoveAt (i);
					continue;
				}
				if (!bIdent && (dwStyle & SARRST_STAY))
				{
					this->RemoveAt (i);
					continue;
				}
				i++;
			}
		};

	void		CopyItemsCorrectForMasks (
		const CStringArrayEx& saSrc, CString sMask, BOOL bCaseSens = FALSE)
	{
		CStringArrayEx saMasks;
		saMasks.Add (sMask);
		CopyItemsCorrectForMasks (saSrc, saMasks, bCaseSens);
	};

	void		CopyItemsCorrectForMasks (
			const CStringArrayEx& saSrc, const CStringArrayEx& saMasks, BOOL bCaseSens = FALSE)
		{
			this->RemoveAll ();
			FOR_ALL_CONST_STR (pStrMask, saMasks)
			{
				CStringArrayEx saList;
				saList.Copy (saSrc);
				saList.ProcWithHeader (*pStrMask, bCaseSens ? SARRST_STAY : SARR_NCST);
				this->Append (saList);
			}
		};

	void		ClearWhiteSpaces ()
		{
			FOR_ALL_STR (pStr, (*this)) { CStringProc::ClearWhiteSpaces (*pStr); }
		};

	void		ToDoSort (BOOL bAscending = TRUE)
		{
			std::vector<CString> sVec;
			FOR_ALL_STR (pStr, (*this))
				sVec.push_back ((*pStr));
			std::make_heap (sVec.begin (), sVec.end());
			std::sort_heap (sVec.begin (), sVec.end());
			(*this).RemoveAll ();

			if (bAscending) 
				for (std::vector<CString>::iterator it = sVec.begin(); it!=sVec.end(); it++)
					(*this).Add (*it);
			else
				for (std::vector<CString>::iterator it = sVec.begin(); it!=sVec.end(); it++)
					(*this).InsertAt (0, *it);			
		}
		
#define MEMBFUN(funcName) void ForAll##_##funcName (){ CString * pStr = Begin (), * pEnd = End (); while (pStr != pEnd) (pStr++)->funcName();	};
	
	MEMBFUN (TrimLeft);
	MEMBFUN (TrimRight);
	MEMBFUN (MakeLower);
	MEMBFUN (MakeUpper);
};

#endif //__STRING_ARRAY_EX__
