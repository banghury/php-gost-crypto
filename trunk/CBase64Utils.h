// class for converting file to Base64

// nov16_07 ADD EncodeToB64 (const CString& str, const BOOL bDelNewLine = TRUE)
// apr28_05 ADD CString GetUnicB64Name (). Don't use for create FILE NAMES!!!!
// oct20_04 MODUF BOOL	Decode (LPCSTR psInput, CBinData& bnOut)

// ADD : static function EncodeToB64 DecodeFromB64
// ADD : Modified class CBase64Utils

#pragma once
#include "BinData.h"

//class to handle all base64 stuff...
class CBase64Utils
{
public:
	CBase64Utils();
	~CBase64Utils();

	BOOL			Decode (LPCSTR psInput, CBinData& bnOut);
	CString		Encode (LPCTSTR szEncoding, const int nSize);
	CString		Encode (const CBinData& bnIn) 
	{ 
		return Encode ((LPCTSTR)bnIn.Buf (), bnIn.Size ()); 
	};

	CString		EncodeTable (LPCTSTR bnEncoding, const int nSize);

	static		CString	GetUnicB64Name (); // Don't use for create FILE NAMES!!!!
	static		CString	EncodeToB64 (const CString& str, const BOOL bDelNewLine = TRUE)
	{
		CBase64Utils b64;
		CString sRet = b64.Encode ((LPCTSTR)str, str.GetLength ()); 
		if (bDelNewLine)
			sRet.Replace ("\r\n", "");
		return sRet;
	};

	static		CString	EncodeToB64 (const CBinData& bnIn, const BOOL bDelNewLine = TRUE) 
	{ 
		CBase64Utils b64;
		CString sRet = b64.Encode ((LPCTSTR)bnIn.Buf (), bnIn.Size ()); 
		if (bDelNewLine)
			sRet.Replace ("\r\n", "");
		return sRet;
	};

	static		BOOL	DecodeFromB64 (LPCSTR psInput, CBinData& bnOut) 
	{ 
		CBase64Utils b64;
		return b64.Decode (psInput, bnOut); 
	};

private:
	UINT			read_bits (int nNumBits, int * pBitsRead, int& lp);
	void			BuildBase64Table ();
	void			WriteEnd (UCHAR* pInCur, UCHAR* pInEnd, CHAR* pOutBuf);
	
// for encoding
	int m_nInputSize;
	int m_nBitsRemaining;
	ULONG m_lBitStorage;
	LPCTSTR m_szInput;
	int* m_nMask;
	CString m_sBase64Alphabet;

	BOOL		m_bUseTableBase64;
	USHORT*	m_usTableBase64;
};
