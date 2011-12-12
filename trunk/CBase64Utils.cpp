 #include "stdAfx.h"
#include "CBase64Utils.h"
#include <vector>
#include "StringArrayEx.h"
#include <objbase.h>

#define	_N_SIZE_			(ULONG((double(nSize)*1.5)+10))
#define	_N_STEP_			2*30
#define	_LINE_LIMIT_	76
#define	_USHORT_MAX_	4096
#define	_CONVERT_ 		*(pOutBuf++) =	alphabet[pInCur[0] >> 2];		\
	*(pOutBuf++) = alphabet[((pInCur[0] << 4) | (pInCur[1] >> 4))& 63];	\
	*(pOutBuf++) = alphabet[((pInCur[1] << 2) | (pInCur[2] >> 6))& 63];\
	*(pOutBuf++) = alphabet[(pInCur[2] << 0) & 63];

#define	_CONVERT_TABLE_ *(pOutBuf++) =	alphabet[pInCur[0] >> 2];		\
	*(pOutBuf++) = alphabet[((pInCur[0] << 4) | (pInCur[1] >> 4))& 63];

const CHAR* alphabet =
    "ABCDEFGH"
    "IJKLMNOP"
    "QRSTUVWX"
    "YZabcdef"
    "ghijklmn"
    "opqrstuv"
    "wxyz0123"
    "456789+/";

CString	CBase64Utils::GetUnicB64Name ()
{
	GUID guid;
	CoCreateGuid (&guid);
	CBinData bnData ((UCHAR*)&guid, sizeof (GUID) - 1);
	return EncodeToB64 (bnData);	
}

void	CBase64Utils::BuildBase64Table ()
{
	if (m_bUseTableBase64)
		return ;
	
	m_usTableBase64 = new USHORT[_USHORT_MAX_];
	if (!m_usTableBase64) return ;

	for (USHORT u = 0; u < _USHORT_MAX_; u++)
	{
		CHAR* ptrOut = (CHAR*)(m_usTableBase64 + u);
		UCHAR* ptrIn = (UCHAR*)&u;
	
		*(ptrOut+1) = alphabet[ptrIn[0] & 63];
		*(ptrOut) = alphabet[((ptrIn[1] << 2) | (ptrIn[0] >> 6))& 63];

//		*(pOutBuf++) = alphabet[((pInCur[1] << 2) | (pInCur[2] >> 6))& 63];\
//		*(pOutBuf++) = alphabet[(pInCur[2] << 0) & 63];
	}
	CBinData bn ((UCHAR*)m_usTableBase64, _USHORT_MAX_* sizeof (USHORT));
	bn.fWrite ("C:\\table.bin");
}

CString		CBase64Utils::EncodeTable (LPCTSTR bnEncoding, const int nSize)
{
	if (!m_bUseTableBase64)
		BuildBase64Table ();

	UCHAR* pInCur	= (UCHAR*)bnEncoding;
	UCHAR* pInEnd	= pInCur + nSize;
	CHAR*  chOutBuf= new CHAR [size_t(_N_SIZE_)];
	
	USHORT*  pOutBufShort = (USHORT*)chOutBuf;
	if (nSize > 3) 
	{
		pInEnd -= 3;
		while (pInCur <= pInEnd)
		{
//			UCHAR ucTemp1 = *(pInCur+1);
			*(pInCur+1) = (*(pInCur+1) << 4) | (*(pInCur+1) >> 4);
//			UCHAR ucTemp2 = *(pInCur+1);
			USHORT*  pInCurShort1 = (USHORT*)(pInCur);
			*(pOutBufShort++) = m_usTableBase64 [(*pInCurShort1) >> 4];
//			*(pOutBufShort++) = m_usTableBase64 [(*pInCurShort1) & (_USHORT_MAX_ - 1)];

			USHORT*  pInCurShort2 = (USHORT*)(pInCur+1);
//			*(pOutBufShort++) = m_usTableBase64 [(*pInCurShort2) >> 4];
			*(pOutBufShort++) = m_usTableBase64 [(*pInCurShort2) & (_USHORT_MAX_ - 1)];

			pInCur += 3;
		}
		pInEnd += 3;
	}

	WriteEnd (pInCur, pInEnd, (CHAR*)pOutBufShort);
	CString sRet(chOutBuf);
	delete[] chOutBuf;

	CBinData bnDst;
	ASSERT (Decode (sRet, bnDst) && nSize == bnDst.Size () && 0 == memcmp (bnDst.Buf (), bnEncoding, nSize));
	bnDst.fWrite ("C:\\bnDst.txt");
	return sRet;
}

CString		CBase64Utils::Encode (LPCTSTR bnEncoding, const int nSize)
{
//	if (m_bUseTableBase64 || nSize > _USHORT_MAX_*10) 
//		return EncodeTable (bnEncoding, nSize);
	if (nSize == 0) 
		return "";

	BOOL bBreakLine = FALSE;
	UCHAR* pInCur = (UCHAR*)bnEncoding;
	UCHAR* pInEnd = pInCur + nSize;
	CHAR* chOutBuf = new CHAR [_N_SIZE_];
	CHAR* pOutBuf = chOutBuf;
	
	if (nSize > _N_STEP_) 
	{
		pInEnd -= _N_STEP_;
		while (pInCur <= pInEnd)
		{
// first 10
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
// last 10
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;
			_CONVERT_	pInCur += 3;

			*(pOutBuf++) = '\r';
			*(pOutBuf++) = '\n';
		}
		pInEnd += _N_STEP_;
	}

	while (pInCur+3 <= pInEnd)
	{
		_CONVERT_		pInCur += 3;
	}
	WriteEnd (pInCur, pInEnd, pOutBuf);

	CString sRet(chOutBuf);
	delete[] chOutBuf;

	CBinData bnDst;
	ASSERT (Decode (sRet, bnDst) && nSize == bnDst.Size () && 0 == memcmp (bnDst.Buf (), bnEncoding, nSize));

	return sRet;
}


/************************************************************************\
	Base64Utils functions
\************************************************************************/
CBase64Utils::CBase64Utils()
{
	m_sBase64Alphabet = _T( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" );
	m_nMask = new int [9];
	*(m_nMask) = 0;
	*(m_nMask + 1) = 1;
	*(m_nMask + 2) = 3;
	*(m_nMask + 3) = 7;
	*(m_nMask + 4) = 15;
	*(m_nMask + 5) = 31;
	*(m_nMask + 6) = 63;
	*(m_nMask + 7) = 127;
	*(m_nMask + 8) = 255;
	m_bUseTableBase64 = FALSE;
	m_usTableBase64 = NULL;
}

CBase64Utils::~CBase64Utils()
{
	if (m_nMask)
		delete[] m_nMask;
	
	if (m_bUseTableBase64 && m_usTableBase64)
		delete[] m_usTableBase64;
}

/************************************************************************\
	The size of the output buffer must not be less than
	3/4 the size of the input buffer. For simplicity,
	make them the same size.	
\************************************************************************/
BOOL	CBase64Utils::Decode (LPCSTR psInput, CBinData& bnOut)
{
	std::vector <int> nDecode (256, -2);	// Build Decode Table
	for (int i = 0; i < 64; i++)
	{
		nDecode[ m_sBase64Alphabet[ i ] ] = i;
		nDecode[ m_sBase64Alphabet[ i ] | 0x80 ] = i; // Ignore 8th bit
		nDecode[ '=' ] = -1; 
		nDecode[ '=' | 0x80 ] = -1; // Ignore MIME padding char
    }

	if (psInput == NULL || *psInput == '\0')
		return FALSE;
	
// Clear the output buffer
	const int nLenStr = strlen (psInput);
	bnOut.AllocMem (nLenStr);
	memset (bnOut.Buf (), 0, bnOut.Size ());

	m_nBitsRemaining = 0;

// Decode the Input
	int nCount = 0;
	for (int lp = 0; lp < nLenStr; lp++)
	{
		int nDigit;
		if( (nDigit = nDecode [psInput [lp] & 0x7F]) <= -1)
			continue;

// i (index into output) is incremented by write_bits()
//		write_bits (nDigit & 0x3F, 6, bnOut, i);
		m_lBitStorage = (m_lBitStorage << 6) | nDigit & 0x3F;
		m_nBitsRemaining += 6;
		while( m_nBitsRemaining > 7 ) 
		{
			ULONG lScratch = m_lBitStorage >> (m_nBitsRemaining - 8);
			bnOut [nCount++] = UCHAR(lScratch & 0xFF);
			m_nBitsRemaining -= 8;
		}
    }	
	
	bnOut.SetSize (nCount);
	return TRUE;
}

void	CBase64Utils::WriteEnd (UCHAR* pInCur, UCHAR* pInEnd, CHAR* pOutBuf)
{
	switch (pInEnd - pInCur) 
	{
	case 1:
		*(pOutBuf++) =	alphabet[pInCur[0] >> 2];
		*(pOutBuf++) = alphabet[(pInCur[0] << 4)& 63];
		*(pOutBuf++) = '=';
		*(pOutBuf++) = '=';
		break;
	case 2:
		*(pOutBuf++) =	alphabet[pInCur[0] >> 2];
		*(pOutBuf++) = alphabet[((pInCur[0] << 4) | (pInCur[1] >> 4))& 63];
		*(pOutBuf++) = alphabet[(pInCur[1] << 2)& 63];
		*(pOutBuf++) = '=';
		break;
	default:
		break;
	}

	*(pOutBuf++) = '\0';
}