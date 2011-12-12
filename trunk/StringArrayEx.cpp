#include "stdafx.h"
#include "StringArrayEx.h"
#include <objbase.h>
#include "CBase64Utils.h"
#include "IniMng.h"
#include <ATLComTime.h>

CString CStringProc::GetMID (const CString& sPostfix, int nMaxLen /*= 0*/)
{
	// AKV: Формируем в виде чистого GUID
	CBinData bnGUID(sizeof(GUID));

	CoCreateGuid ((GUID*)bnGUID.BufUC());

	CString sMID;

	bnGUID.Encode2Hex (sMID);
	sMID += '@' + sPostfix;
	const int nLen = sMID.GetLength ();
	if (0 < nMaxLen && nLen > nMaxLen)
		sMID.Delete (nMaxLen - 1, nLen - nMaxLen);

	sMID.MakeUpper();
	return sMID;
}

BOOL CStringProc::IsINN(const CString& strIn)
{
	int iLen = strIn.GetLength();
	if ((iLen != 10) && (iLen != 12))
			 return FALSE;
	for (int i = 0; i < iLen; ++i)
	{
		if (!_istdigit(strIn[i]))
				return FALSE;
	}
	return TRUE;
}

// GAV : Конвертирует дату из формата DD.MM.YYY в YYYY.MM.DD ()
/*static*/ BOOL CStringProc::GetDateString4Compare(const CString &sDate, CString &sResult)
{	
	BOOL bConvert=FALSE;
	CStringArrayEx saDateArr;
	char sep='z';
	
	if (sDate.Find('.')>0)
		sep='.';
	else if (sDate.Find('_')>0)
		sep='_';
	else if (sDate.Find('/')>0)
		sep='/';
	else if (sDate.Find('\\')>0)
		sep='\\';

	if (sep!='z')
	{		
		saDateArr.FillFromString(sDate,sep);			

		if (saDateArr.GetSize()==3 
			&& 
			(saDateArr[0].GetLength()==4 
			|| saDateArr[2].GetLength()==4))
		{
			if (saDateArr[0].GetLength()!=4)		
			{// GAV : DD.MM.YYYY				
				CString sTemp;

				// GAV : меняем местами				
				sTemp = saDateArr[2];
				saDateArr[2] = saDateArr[0];
				saDateArr[0] = sTemp;	
			}
			sResult = saDateArr.GetAsString(CString(sep),FALSE);
			bConvert = TRUE;
		}
	
	}	

	return bConvert;
}

BOOL CStringProc::IsKPP(const CString& strIn)
{
	int iLen = strIn.GetLength();
	if (iLen != 9)
			 return FALSE;
	for (int i = 0; i < iLen; ++i)
	{
		if (!_istdigit(strIn[i]))
				return FALSE;
	}
	return TRUE;
}

BOOL CStringProc::IsThumb(const CString& strIn)
{
	CString strVal = strIn;
	strVal.Remove(_T(' '));
	strVal.Remove(_T('\t'));
	strVal.MakeUpper();
	int iLen = strVal.GetLength();
	if (iLen != 40)
			 return FALSE;
	for (int i = 0; i < iLen; ++i)
	{
		if (!((strVal[i] >= _T('0')) && (strVal[i] <= _T('9'))) &&
				!((strVal[i] >= _T('A')) && (strVal[i] <= _T('F'))))
				return FALSE;
	}
	return TRUE;
}

BOOL	CStringProc::IsCodeIFNS (LPCSTR lpCode)
{
	int nLen = 0;
	while (*lpCode != '\0')
		if (!isdigit ((UCHAR)*lpCode++) || ++nLen > 4)
			return FALSE;
	return nLen == 4;
}

BOOL	CStringProc::IsEMail (CString sEMail)
{
	int nPosDog = sEMail.Find ('@');
	if (!isalnum((UCHAR)*(LPCSTR)sEMail) || // first symbol of EMail must be alphanum
			nPosDog == -1 ||// AKV: Точки может и не быть sEMail.Find ('.', nPosDog) == -1 || // dot must present after dog
			sEMail.Replace ('@', '.') != 1 || // replace only one '@' on '.' for check of present only alpha, numbers, '.' or '_'
			sEMail.Find ("..") >= 0) // not present double dot
		return FALSE;
    LPCSTR lpCur;
	for (lpCur = (LPCSTR)sEMail; *lpCur != '\0'; lpCur++)
		if (!isalnum ((UCHAR)*lpCur) && *lpCur != '_' && *lpCur != '-' && *lpCur != '.')
			return FALSE;

	return isalnum (*(--lpCur)); // last symbol of EMail must be alphanum
}

BOOL CStringProc::ConvertStr2CTime (const CString& sTime, CTime& tmRet)
{
#define	_N_PLACE_T_XML_TIME			10
#define	_N_LEN_XML_TIME				19
#define	_N_LEN_DDMMYYYY				10
// AKV: Для преобразования только времени
#define	_N_LEN_HHMMSS				8
#define	_N_LEN_FILEEXT_TIME			20

	int nSec = 0, nMin = 0, nHour = 0, nDay = 1, nMonth = 1, nYear = 1970;

	// AKV: Возможен формат, который возвращает GetStrDate().
	ASSERT(!sTime.IsEmpty());
	if (!_istdigit(sTime[0]) && sTime[0] != '.')
	{
		CString strDT = sTime;
		if (_istalpha(strDT[0]))
			ConvertShortMonthToNum(strDT);
		else
			ConvertRusMonthToNum(strDT);
		strDT.Insert(2, _T(' '));
		if (!sscanf ((LPCSTR)strDT, "%d", &nMonth) ||
			!sscanf ((LPCSTR)strDT + 3, "%d", &nDay) ||
			!sscanf ((LPCSTR)strDT + 6, "%d", &nYear)) 
			return FALSE;

		if ( strDT.GetLength() >= 11 )
			sscanf((LPCSTR)strDT + 9, "%d", &nHour);
		if ( strDT.GetLength() >= 14 )
			sscanf((LPCSTR)strDT + 12, "%d", &nMin);
		if ( strDT.GetLength() >= 17 )
			sscanf((LPCSTR)strDT + 15, "%d", &nSec);

		nYear += 2000;
		tmRet = CTime (nYear, nMonth, nDay, nHour, nMin, nSec);
		return TRUE;
	}
	// AKV End

	switch (sTime.GetLength ())
	{
	case _N_LEN_XML_TIME: // "2005-09-15T13:14:00"
		{
			char chTime = sTime[_N_PLACE_T_XML_TIME];
			if (chTime != 'T' && chTime != 't') 
				return FALSE;

			CStringArrayEx saYearMonDay (
				sTime.Left (_N_PLACE_T_XML_TIME), '-');
			saYearMonDay.GetAsString ();
			if (saYearMonDay.GetSize () != 3 ||
					!sscanf ((LPCSTR)saYearMonDay[0], "%d", &nYear) ||
					!sscanf ((LPCSTR)saYearMonDay[1], "%d", &nMonth) ||
					!sscanf ((LPCSTR)saYearMonDay[2], "%d", &nDay))
				return FALSE;

			CStringArrayEx saHourMinSec ((LPCSTR)sTime + 
				_N_PLACE_T_XML_TIME + 1, ':'); // start of HH:MM:SS
			saHourMinSec.GetAsString ();
			if (saHourMinSec.GetSize () != 3 ||
					!sscanf ((LPCSTR)saHourMinSec[0], "%d", &nHour) ||
					!sscanf ((LPCSTR)saHourMinSec[1], "%d", &nMin) ||
					!sscanf ((LPCSTR)saHourMinSec[2], "%d", &nSec))
				return FALSE;
			break;
		}
	case _N_LEN_DDMMYYYY: // 28 09 2007 or 17.08.2007
		{
			if (!sscanf ((LPCSTR)sTime, "%d", &nDay) ||
					!sscanf ((LPCSTR)sTime + 3, "%d", &nMonth) ||
					!sscanf ((LPCSTR)sTime + 6, "%d", &nYear)) 
				return FALSE;
			break;
		}
	// AKV: Расшифровка времени
	case _N_LEN_HHMMSS: // HH:MM:SS
		{
			if (!sscanf ((LPCSTR)sTime, "%d", &nHour) ||
				!sscanf ((LPCSTR)sTime + 3, "%d", &nMin) ||
				!sscanf ((LPCSTR)sTime + 6, "%d", &nSec)) 
				return FALSE;
			break;
		}
	case _N_LEN_FILEEXT_TIME: // .28_04_2010_16_44_35
		{
			if (!sscanf((LPCSTR)sTime+1, "%d", &nDay) ||
				!sscanf((LPCSTR)sTime+4, "%d", &nMonth) ||
				!sscanf((LPCSTR)sTime+7, "%d", &nYear) ||
				!sscanf((LPCSTR)sTime+12, "%d", &nHour) ||
				!sscanf((LPCSTR)sTime+15, "%d", &nMin) ||
				!sscanf((LPCSTR)sTime+18, "%d", &nSec)) 
				return FALSE;
			break;
		}
		// AKV End
	default:
		return FALSE;
	}

	tmRet = CTime (nYear, nMonth, nDay, nHour, nMin, nSec);
	return TRUE;
}

void	CStringProc::GetTagList (const CString & sSrc, CStringArray& saTagListRet)
{
	CStringArrayEx saListString (sSrc, '<');
	FOR_ALL_STR (pStrTag, saListString)
		*pStrTag = CStringProc::GetStrBefore (*pStrTag, '>');

	saTagListRet.RemoveAll ();
	for (int i = 0; i < saListString.GetSize (); i++)
	{
		if (saListString[i].IsEmpty () || *(saListString[i]) == '/') 
			continue;

		CString sFindTag = (CString)'/' + saListString[i];
		for (int j = i+1; j < saListString.GetSize (); j++)
			if (sFindTag == saListString[j])
			{			
				if (((CStringArrayEx*)&saTagListRet)->Find (saListString[i]) == -1)
					saTagListRet.Add (saListString[i]);
				break;
			}
	}
}

BOOL CStringProc::ConvertCStringToCTime(const CString& sTime, CTime& tmRet) //КПМ: Для конвертации DD.MM.YYYY HH:MM:SS
{
	COleDateTime myDtTime;
	if(myDtTime.ParseDateTime(sTime))
	{
		SYSTEMTIME st;
		if(myDtTime.GetAsSystemTime(st))
		{
			tmRet = st;
			return true;
		}
	}
	else
		return false;
	return false;
}
