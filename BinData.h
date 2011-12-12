// class for work at binary data
// 16.04.2004
/************************************************************************\
	19.11.2007		ADD BOOL		CopyDataToString (CString& sRet)
	09.02.2006		ADD static	CString	MemAddress2Hex (UCHAR* pAddress);
	09.02.2006		ADD static	BOOL		Hex2MemAddress (const CString& sHex, UCHAR** pAddress);
   01.11.2005		ADD Hex transformation
	07.12.2004		ADD XORByWord (const CBinData& bnWord);
	07.12.2004		ADD CBinData (const CString& str);
	27.10.2004		ADD typedef std::multimap<CString, CBinData> CMapFiles; // file name and binary data
	20.10.2004		MODIF void	SetSize (const UINT nBytesSet) // if nBytesSet > nBytes_ MEMORY WAS MISSED !!!
   19.10.2004		Add int FindBack (const CString & str, UINT nPos = 0)
	19.10.2004		Add UCHAR* BufUC ()
	19.10.2004		Modif void SetSize (const UINT nBytesSet)
	16.04.2004		Add BOOL	operator == (const CBinData& bnData)
   20.11.2003		Add Find for CBinData
	28.02.2003		Add constructor CBinData (unsigned char * pBuf, const UINT nBytes)
	27.05.2002		Add find func
	23.05.2002		Bug in FreeMem

\************************************************************************/

#ifndef __BINDATA_H__
#define __BINDATA_H__

#pragma once
#include <stdlib.h>
#include <map>
#include <afx.h>
#include <afxdisp.h>

class CBinData;
typedef std::multimap<CString, CBinData> CMapFiles; // file name and binary data

extern BOOL	LoadStruct (const CString & sFName, void * pMem, const UINT nBytes);
extern BOOL	SaveStruct (const CString & sFName, const void * pMem, const UINT nBytes);

class CBinData
{
public:
	CBinData ();
	CBinData (const UINT nBytes);
	CBinData (const CBinData& bnData) : doNotFreeGlobal(false)
		{		nBytes_ = 0;	pData_ = NULL; m_hGlobal=NULL;	(*this) = bnData;	};
	CBinData (UCHAR* pBuf, const UINT nBytes) : doNotFreeGlobal(false)
		{		nBytes_ = 0;	pData_ = NULL; m_hGlobal=NULL;	AppendMem (pBuf, nBytes);	}
	CBinData (const CString& str) : doNotFreeGlobal(false)
		{		nBytes_ = str.GetLength ();	
				pData_ = NULL;
				m_hGlobal=NULL;
				AppendMem ((UCHAR*)(LPCSTR)str, nBytes_);	
		};
	
	~CBinData () 
		{	FreeMem ();	};
	
	void	FreeMem ();
	BOOL	AllocMem (const UINT nBytes);
	BOOL	AppendMem (unsigned char * pBuf, const UINT nBytes);
	BOOL	fRead  (const CString & sFName);
	BOOL	fWrite (const CString & sFName) const;
	void	operator = (const CBinData& bnData);
	unsigned char&	operator [] (const UINT n)
		{
			if (n >= nBytes_)
				throw CString ("CBinData::operator []::Bad index!");
			return *((unsigned char *)pData_ + n);
		};
	unsigned char	operator [] (const UINT n) const
		{
			if (n >= nBytes_)
				throw CString ("CBinData::operator []::Bad index!");
			return *((unsigned char *)pData_ + n);
		};
		
	int		Find (LPCSTR pStr, UINT nPos = 0) const;
	int		Find (const CBinData& bn, UINT nPos = 0) const;
	int		FindBack (const CString & str, UINT nPosFromEnd = 0) const; // nPos == 0 find from end
	int		FindBack (const CBinData& bn, UINT nPosFromEnd = 0) const;

	CString	GetStrBetween (LPCSTR psBefore, LPCSTR psAfter) const;
	
	void *	Buf () const 
		{
			return pData_;
		};

	UCHAR*	BufUC () const // return ptr to Buf as UCHAR *
		{
			return (UCHAR*)pData_;
		};

	UINT	Size () const
		{
			return nBytes_;
		};
		
	void	SetSize (const UINT nBytesSet) // if nBytesSet > nBytes_ MEMORY WAS MISSED !!!
		{
			if (nBytesSet > nBytes_)
				AllocMem (nBytesSet);
//				throw CString ("CBinData::SetSize::Bad number of bytes!");
			nBytes_ = nBytesSet;
		};
	
	void	OemToAnsi ();
	void	AnsiToOem ();
	BOOL	operator == (const CBinData& bnData)
	{
		return nBytes_ == bnData.Size () && 0 == memcmp (bnData.Buf (), this->Buf (), nBytes_);
	}
	BOOL	operator != (const CBinData& bnData)
	{
		return !(*this == bnData);
	}

	void		XORByWord (const CBinData& bnWord);

	BOOL		CopyDataToString (CString& sRet);

// hex transformation
	BOOL		FillFromHex (const CString& sHexValue);
	void		Encode2Hex (CString& sHexRet) const;

	static	CString	MemAddress2Hex (const UCHAR* pAddress);
	static	BOOL		Hex2MemAddress (const CString& sHex, UCHAR** ppAddress);


	//NMS : Позволяет работать с описателем HGLOBAL	(необходимо для работы с БД)
	HGLOBAL GlobalAlloc(const UINT uFlags=GMEM_MOVEABLE);
	BOOL GlobalFree(void);
	DWORD GlobalSize(void) const;
	//NMS : Сам описатель m_hGlobal, в деструкторе уничтожается
	HGLOBAL m_hGlobal;
	
	bool	doNotFreeGlobal;

private:
	UINT	nBytes_;
	void*	pData_;
};

// GAV : класс от CBinData с переопределенной функцией записи  
// для файлов с длиной имени более 255 символов
class CBinData4PFR : public CBinData
{
public:
	BOOL	fWrite (const CString & sFName) const;
};


#endif // __BINDATA_H__
