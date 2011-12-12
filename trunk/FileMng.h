// class for work witn file name? file path and others operation on files


// 22 aug 2007 ADD GetCountFilesInDir
// 15 jun 2005 ADD static	BOOL	GetDirWin	(CString & sDirWin)
// 01 oct 2004 ADD template<class T> BOOL	_List_GetListFiles
// 24 jun 2003

#ifndef __FILEMNG_H__
#define __FILEMNG_H__

#pragma once

#include "StringArrayEx.h"
#include <vector>
#include <list>
#include <string>
#include <iostream>

#include <windows.h>
#include <conio.h>


#define		FMNG_RECURS		0x0001
#define		FMNG_ADDPATH	0x0002
#define		FMNG_PROCDIR	0x0004

class CFileMng
{
public:
	CFileMng	()	{};
	~CFileMng	()	{};
	
	static	void			MovingFile		(CString sPFSrc, CString sPFDst);
	static	CString		GetFileName		(const CString& sFullFileName);
	static	CString		GetExtFileName	(const CString& sFullFileName); // Get extension of file
	static	CString		GetExt			(const CString& sFullFileName)
				{	return GetExtFileName (sFullFileName);	}; // Get extension of file

	static	CString		GetOnlyName (const CString& sPFN) // Get file name without ext and path
				{	return GetPathFileWOExt (GetFileName (sPFN));	};
	
	static	CString		GetPathFileWOExt(const CString& sFullFileName); // Get PathFile without extension
	static	CString		GetPath			(CString sPathFile);
	static	BOOL			IsFileExist		(const CString& sFName);
	static	BOOL			IsDirExist		(CString sPath);
	static	CString		GetUnicName		(const CString sExtension = "");
	static	void		GetListFileName (CString sPath,		// before calling saRet.RemoveAll !
		CStringArrayEx& saRet, const CString & sMask = "*.*", const DWORD dwStyle = 0);
	static	BOOL		DeleteAllFiles	(const CString& sPath, const DWORD dwStyle = 0, CString sMask = "*.*");
	static	BOOL		CreatePaper		(CString sFullPath);
	//NMS : � ������� �� ������� CreatePaper �� ������������ ����,
	//		� ��� �� ��������� FALSE, ���� �� ������� �������
	//		���� �� ��������� � ����.
	static BOOL			CreateDirTree(LPCTSTR lpszPath);
	static	BOOL		GetDirExe		(CString & sDirExe);
	static	void		GetDirWin		(CString & sDirWin);
	static	CString	GetSysVar		(CString sVarName);
	static LONG GetCountFilesInDir(LPCTSTR lpszDirPath,LPCTSTR lpszMask=_T("*.*"));	
	static BOOL DeleteFile(LPCTSTR lpszFilePath);
	//DIP : �������� ����������� ������ � �����
	static BOOL			IsFolderWriteable( LPCTSTR strFolder );
	//DIP : ��������� ������ ���������� �� ����������� ������ ( -1 ���� ��� ������� ��� ������ )
	static int			IsFolderListWriteable( CStringArray &ar );
	
// dwFlags : 
//	CSIDL_APPDATA | CSIDL_FLAG_CREATE - Application Data folder
//	CSIDL_PERSONAL | CSIDL_FLAG_CREATE - Personal folder
	static	CString	GetFolderPath	(DWORD dwFlags);
	// AKV: ����� TEMP
	static	CString		GetDirTemp(void);
	static  BOOL GetFileVersion(LPCTSTR pszFileName,CString &Version);
	//AKV: ��������� �������� � EXE ���������� �������
	static BOOL GetDirExeEx(CString& strDirExe);
	//AKV: ��������� ���� � ������ '..'
	static BOOL CanonicalizePath(CString strDirIn, CString& strDirOut);
	//���: ������� ������� ���������� ������ � �������� � �������������� ������������ � ����������
	static int CountFiles(const std::string &refcstrRootDirectory,
		const std::string &refcstrExtension,
		bool bSubdirectories = false);
	//���: ��� ������ ������ ����������� � �������� 
	static std::string GetLastCreatedDir(const std::string &refcstrRootDirectory);

protected:
};

template<class T> BOOL	_Vec_GetListFiles(
	const CString& sPath, 
	std::vector<T>& vec,
	const CString & sMask = "*.*",
	bool bLookInSubfolders = false)
{
	if ( !bLookInSubfolders )
		vec.clear();

	CFileFind finder;
	BOOL bWorking = finder.FindFile (sPath + "\\" + sMask);

	while (bWorking)
	{
		bWorking = finder.FindNextFile();
		
		if (finder.IsDots ())
		{
			continue;
		}
		else if ( finder.IsDirectory() && bLookInSubfolders )
		{
			if ( bLookInSubfolders )
			{
				_Vec_GetListFiles( finder.GetFilePath(), vec, sMask, bLookInSubfolders );
			}
			continue;
		}
		else
		{
			vec.push_back( T(finder.GetFilePath()) );
		}
	}
	return TRUE;
}

template<class T> BOOL	_List_GetListFiles (const CString & sPath, std::list<T>& lst, const CString & sMask = "*.*")
{
	lst.clear ();

	CFileFind finder;
	BOOL bWorking = finder.FindFile (sPath + "\\" + sMask);

	while (bWorking)
	{
		bWorking = finder.FindNextFile();
		if (finder.IsDots ())
			continue;

		if (finder.IsDirectory() || 
			!CFileMng::IsFileExist (finder.GetFilePath ()))
			continue;

		lst.push_back (T(finder.GetFilePath ()));
	}
	return TRUE;
}

#endif // __FILEMNG_H__
