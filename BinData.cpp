// Use Settings : Preprocessor : Add include path = <path to project>
#include "stdafx.h"
#include "BinData.h"

#define		__MAX_BUF_SIZE__		64*1024

CBinData::CBinData () : doNotFreeGlobal(false)
{
	nBytes_ = 0;
	pData_ = NULL;
	m_hGlobal=NULL;
};

CBinData::CBinData (const UINT nBytes) : doNotFreeGlobal(false)
{
	pData_ = NULL;
	m_hGlobal=NULL;
	AllocMem (nBytes);
}

void	CBinData::FreeMem ()
{
	//NMS : Если работали с HGLOBAL
	if(!doNotFreeGlobal)
		GlobalFree();

	if (NULL == pData_) 
		return ;
	free (pData_);
	pData_ = NULL;
	nBytes_ = 0;
};

BOOL	CBinData::AllocMem (const UINT nBytes)
{
	if (nBytes==0)		return TRUE;
	FreeMem ();
	nBytes_ = nBytes;
	pData_ = malloc (nBytes_);
	return pData_ != NULL;						
};

BOOL	CBinData::AppendMem (unsigned char * pBuf, const UINT nBytes)
{
	//NMS : Если работали с HGLOBAL
	GlobalFree();
	
	if (NULL == pBuf)
		return FALSE;
		
	if (pData_) 
	{
		nBytes_ += nBytes;
		if (NULL == (pData_ = realloc (pData_, nBytes_)))
			return FALSE;
	}	else	{
		AllocMem (nBytes);
	}
	
	BOOL retVal = NULL != memcpy ((unsigned char * )pData_ + nBytes_ - nBytes, pBuf, nBytes);
	return retVal;
};

/*
BOOL	CBinData::CutLastBytes (const UINT nBytes)
{
	if (nBytes > nBytes_)
		return FALSE;

	nBytes_ -= nBytes;
	return TRUE;
}
*/

BOOL	LoadStruct (const CString & sFName, void * pMem, const UINT nBytes)
{
	CBinData bData;
	if (!bData.fRead (sFName))
		return FALSE;
	
	if (bData.Size ()!=nBytes)
		return FALSE;
	
	if (!memcpy (pMem, bData.Buf (), nBytes))
		return FALSE;
		
	return TRUE;
}

BOOL	SaveStruct (const CString & sFName, const void * pMem, const UINT nBytes)
{
	CFile fl;
	if (pMem == NULL || !fl.Open (sFName, CFile::typeBinary | CFile::modeWrite | CFile::modeCreate))
		return FALSE;
	
	fl.Write (pMem, nBytes);
	fl.Close ();	
	return TRUE;
}

BOOL	CBinData::fRead (const CString& fName)
{
	FreeMem ();
	
	CFile fl;
	if (!fl.Open (fName, CFile::typeBinary | CFile::modeRead))
		return FALSE;
	
	unsigned char sBuf[__MAX_BUF_SIZE__];
	UINT nBytesRead;
	do {
		nBytesRead = fl.Read (sBuf, __MAX_BUF_SIZE__);
		if (!this->AppendMem (sBuf, nBytesRead))
			return FALSE;
	} while (nBytesRead == __MAX_BUF_SIZE__);

	fl.Close ();	
	return TRUE;
}

BOOL	CBinData::fWrite (const CString& sFName) const
{
	CFile fl;
	if (!fl.Open (sFName, CFile::typeBinary | CFile::modeWrite | CFile::modeCreate))
		return FALSE;
#if 0
	const UCHAR* pStrCur = (const UCHAR*)BufUC ();
	const UCHAR* pStrEnd = pStrCur + Size ();
	
	do {
		fl.Write ((const void *)pStrCur, 
			pStrEnd > pStrCur + __MAX_BUF_SIZE__ ? __MAX_BUF_SIZE__ : (UINT)(pStrEnd - pStrCur));
		pStrCur += __MAX_BUF_SIZE__;
	} while (pStrEnd > pStrCur);
#else
	fl.Write (Buf (), Size ());
#endif
	
	fl.Close ();
	
	return TRUE;
}

void	CBinData::operator = (const CBinData& bnData)
{
	FreeMem ();
	AppendMem ((UCHAR*)bnData.Buf (), bnData.Size ());
}

int		CBinData::Find (LPCSTR pStr, UINT nPos /*= 0*/) const
{
	UINT nLen = 0;
	if (NULL == pData_ || nPos >= this->nBytes_ || *pStr == '\0' ||
			(nLen = strlen (pStr)) > this->nBytes_ - nPos)
		return -1;
	CBinData bnStr ((UCHAR*)pStr, nLen);
	return Find (bnStr, nPos);
/*

	LPCSTR pCur = (const char * )pData_ + nPos;
	LPCSTR pEnd = (const char * )pData_ + this->nBytes_ - nLen;

	while (pCur != pEnd)
	{
		if (*pCur++ == *pStr)
		{
			for (LPCSTR pTemp = pCur; pTemp < pEnd)
			return (UINT)pData_ - (UINT)pCur;
		pCur++;
	}
// ****
	if (NULL == pData_ || nPos >= this->nBytes_ || *pStr == '\0')
		return -1;
	
	const char * ptr;
	if (NULL == (ptr = strstr ((const char * )pData_ + nPos, pStr)))
		return -1;
	return (int)ptr - (int)pData_;
*/

//	CString sTemp ((UCHAR*)pData_), sTempSrc (str);
//	sTempSrc.MakeLower ();
//	sTemp.MakeLower ();
//	return sTemp.Find (sTempSrc, nPos);
}

CString		CBinData::GetStrBetween (LPCSTR psBefore, LPCSTR psAfter) const 
{
//	TRACE("CBinData::GetStrBetween : %s => %s\n %s", sBefore, sAfter, (UCHAR*)pData_);
	int nPosStart, nPosEnd;
	CString sRet;
	if (-1 != (nPosStart = Find (psBefore)))
	{
		nPosStart += strlen (psBefore);
		if (-1 != (nPosEnd = Find (psAfter, nPosStart)) && nPosEnd != nPosStart)
			strncpy (sRet.GetBufferSetLength (nPosEnd - nPosStart/* - 1 NMS : -1 делать не нужно, так как размер буфера определяется не с 0*/), 
					 (LPCSTR)Buf () + nPosStart, nPosEnd - nPosStart);
	}
	return sRet;
}

void		CBinData::OemToAnsi ()
{
	CString sTemp;
	strncpy (sTemp.GetBufferSetLength (nBytes_),(LPCSTR)pData_, nBytes_);
	sTemp.OemToAnsi ();
	TRACE("CBinData::OemToAnsi:: sTempLen = %d\n", sTemp.GetLength ());
	ASSERT (nBytes_ >= (UINT)sTemp.GetLength ());
	memcpy (pData_, (LPCSTR)sTemp, nBytes_);
}

void		CBinData::AnsiToOem ()
{
	CString sTemp;
	strncpy (sTemp.GetBufferSetLength (nBytes_),(LPCSTR)pData_, nBytes_);
	sTemp.AnsiToOem ();
	TRACE("CBinData::AnsiToOem:: sTempLen = %d\n", sTemp.GetLength ());
	ASSERT (nBytes_ >= (UINT)sTemp.GetLength ());
	memcpy (pData_, (LPCSTR)sTemp, nBytes_);
}

int		CBinData::Find (const CBinData& bn, UINT nPos/* = 0*/) const
{
	if (bn.Size () == 0 || this->Size () == 0) 
		return -1;

	for (UINT n = nPos; n < (*this).Size () - bn.Size () + 1; n++)
	{
		if ((*this)[n] != bn[0]) 
			continue;
		
		if (0 == memcmp (bn.Buf (), (void*)((UCHAR*)(this->Buf ()) + n), bn.Size ()))
			return n;
	}
	return -1;
}

int	CBinData::FindBack (const CString & str, UINT nPosFromEnd /*= 0*/) const
{	// nPos == 0 find from end
	const int nLen = str.GetLength ();
	CBinData bn ((UCHAR*)(LPCSTR)str, nLen);
	return FindBack (bn, nPosFromEnd);
}

int	CBinData::FindBack (const CBinData& bn, UINT nPosFromEnd /*= 0*/) const 
{
	if (bn.Size () >= this->Size () || this->Size () <= nPosFromEnd) 
		return -1;

	if (nPosFromEnd < bn.Size () - 1)
		nPosFromEnd = bn.Size () - 1;

	UCHAR* ptr = this->BufUC () + this->Size () - 1 - nPosFromEnd;
	do {
		if (*ptr != *bn.BufUC ()) 
			continue;
		
		if (0 == memcmp (ptr, bn.Buf (), bn.Size ()))
			return ptr - this->BufUC ();

	} while (ptr-- != this->BufUC ());

	return -1;
}

void	CBinData::XORByWord (const CBinData& bnWord)
{
	if (!pData_ || !nBytes_ || !bnWord.nBytes_)
		return ;

	for (unsigned int i = 0; i < nBytes_; i++)
		(*this)[i] ^= bnWord[(nBytes_ - i + bnWord.nBytes_)%bnWord.nBytes_];
}

/************************************************************************\
	Hex transformation
\************************************************************************/
#define Hex2Int(ch, n){  if (ch >= '0' && ch <= '9') n = ch - '0';\
  else if (ch >= 'a' && ch <= 'f') n = ch - 'a' + 0xA;\
  else if (ch >= 'A' && ch <= 'F') n = ch - 'A' + 0xA;\
  else throw 1;}

BOOL CBinData::FillFromHex (const CString& sHexValue)
{
	int nLen = sHexValue.GetLength ();
	if (nLen%2 != 0) 
		return FALSE;
//		throw CString ("Некорректная hex-строка для заполнения бинарного массива.");
	(*this).SetSize (nLen/2);
	const char* pHexSign = (LPCSTR)sHexValue;
	UCHAR* pChar = (*this).BufUC ();
	try{
		int nLeftPart, nRightPart;
		while (*pHexSign)
		{
			ASSERT ((UINT)pChar - (UINT)(*this).BufUC () < (*this).Size ());
			Hex2Int (*pHexSign, nLeftPart);
			pHexSign++;
			Hex2Int (*pHexSign, nRightPart);
			pHexSign++;
			*pChar++ = (UCHAR)(nLeftPart << 4 | nRightPart); 
		}
		ASSERT ((UINT)pChar - (UINT)(*this).BufUC () == (*this).Size ());
	}
	catch(...) {
//		throw CString ("Некорректная hex-строка для заполнения бинарного массива.");
		return FALSE;
	}
	return TRUE;
}

void	CBinData::Encode2Hex (CString& sHexRet) const
{
	UCHAR* pStr = (UCHAR*)sHexRet.GetBufferSetLength ((*this).Size ()*2);
	UCHAR *pBinCur = (*this).BufUC (), *pBinEnd = (*this).BufUC () + (*this).Size ();
	char const hex[] = "0123456789abcdef";
	while (pBinCur < pBinEnd)
	{
     *pStr++ = hex[*pBinCur >> 4];
     *pStr++ = hex[*pBinCur++ & 0xf];
	}
}

/************************************************************************\
	Memory hex conversation
Sample: // m_cmn.m_iniConfig - is CIniMng variable
	const CString sHexAddress = CBinData::MemAddress2Hex ((UCHAR*)&(m_cmn.m_iniConfig));
	CIniMng* pIniDst = NULL;
	if (!CBinData::Hex2MemAddress (sHexAddress, (UCHAR**)&pIniDst))
		AfxMessageBox ("Bad!");
// pIniDst - now pointer to m_cmn.m_iniConfig
\************************************************************************/
CString	CBinData::MemAddress2Hex (const UCHAR* pAddress)
{
	CBinData bnPtr ((UCHAR*)&pAddress, sizeof (CBinData*));
	CString sHexData;
	bnPtr.Encode2Hex (sHexData);
	return sHexData;
}

BOOL		CBinData::Hex2MemAddress (const CString& sHexAddress, UCHAR** ppAddress)
{
	CBinData bnPtr;
	if (sHexAddress.IsEmpty () || sHexAddress.GetLength () != 2*sizeof (CBinData*) ||
			!bnPtr.FillFromHex (sHexAddress))
		return FALSE;

	bnPtr.FillFromHex (sHexAddress);
	*ppAddress = *(UCHAR**)bnPtr.Buf ();
	return TRUE;
}

// Use this func if (*this) is CString garanty!!!
BOOL		CBinData::CopyDataToString (CString& sRet)
{
	UCHAR* pStr = (UCHAR*)sRet.GetBufferSetLength ((*this).Size ());
	UCHAR *pBinCur = (*this).BufUC (), *pBinEnd = (*this).BufUC () + (*this).Size ();

	while (pBinCur < pBinEnd)
     *pStr++ = *pBinCur++;
	sRet.ReleaseBuffer ();
	return sRet.GetLength () == (*this).Size ();
}

//NMS : Позволяет работать с описателем HGLOBAL	

//NMS : Выделяет память
HGLOBAL CBinData::GlobalAlloc(const UINT uFlags/*=GMEM_MOVEABLE*/)
{
	//NMS : Освободим старую память
	GlobalFree();
	//NMS : Выделим новую
	m_hGlobal=::GlobalAlloc(uFlags,Size());
	ASSERT(m_hGlobal!=NULL);
	if (m_hGlobal!=NULL)
	{
		LPVOID pVoid=::GlobalLock(m_hGlobal);
		ASSERT(pVoid!=NULL);
		::CopyMemory(pVoid,Buf(),Size());
		::GlobalUnlock(m_hGlobal);	
	}
	return m_hGlobal;
}

//NMS : Освобождает память
BOOL CBinData::GlobalFree(void)
{
	BOOL bResult=FALSE;
	if (m_hGlobal!=NULL)
	{
		::GlobalFree(m_hGlobal);
		bResult=TRUE;
	}
	return bResult;
}

//NMS : Подсчитывает размер
DWORD CBinData::GlobalSize(void) const
{
	DWORD dwResult=0x00;
	if (m_hGlobal!=NULL)
	{
		dwResult=::GlobalSize(m_hGlobal);
	}
	return dwResult;
}

BOOL	CBinData4PFR::fWrite (const CString& sFName) const
{
	CFile fl;
	CFileException Error;	
	
	CString sTmp = CString("\\\\?\\") + sFName;
	int nSize = ::MultiByteToWideChar(CP_ACP, 0, sTmp, sTmp.GetLength(), 0, 0);
	CByteArray wStr;
	nSize*=2;
	nSize+=2;
	wStr.SetSize(nSize);
	
	::MultiByteToWideChar(CP_ACP, 0, sTmp, sTmp.GetLength(), (LPWSTR) wStr.GetData(), nSize);
	HANDLE hFile = ::CreateFileW((LPWSTR) wStr.GetData(), GENERIC_WRITE | FILE_ALL_ACCESS | FILE_WRITE_DATA, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwBuf=0;
	
	if(!::WriteFile(hFile, Buf(), Size(), &dwBuf, 0))
	{
		::CloseHandle(hFile);
		return FALSE;

	}

	::CloseHandle(hFile);	
	return TRUE;
//	if (!fl.Open (sFName, CFile::typeBinary | CFile::modeWrite | CFile::modeCreate,&Error))
//		return FALSE;
#if 0
	const UCHAR* pStrCur = (const UCHAR*)BufUC ();
	const UCHAR* pStrEnd = pStrCur + Size ();
	
	do {
		fl.Write ((const void *)pStrCur, 
			pStrEnd > pStrCur + __MAX_BUF_SIZE__ ? __MAX_BUF_SIZE__ : (UINT)(pStrEnd - pStrCur));
		pStrCur += __MAX_BUF_SIZE__;
	} while (pStrEnd > pStrCur);
#else
	fl.Write (Buf (), Size ());
#endif
	
	fl.Close ();
	
	return TRUE;
}

void Invert (CBinData& bnSerial)
{
	for (int i = 0; i < bnSerial.Size () / 2; i++)
	{
		UCHAR ucSwap = *(bnSerial.BufUC () + i);
		*(bnSerial.BufUC () + i) = *(bnSerial.BufUC () + bnSerial.Size () - i - 1);
		*(bnSerial.BufUC () + bnSerial.Size () - i - 1) = ucSwap;
	}
}