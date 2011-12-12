// Use Settings : Preprocessor : Add include path = <path to project>

// 2007 nov 20 - ADD   DeleteFile
// 2006 may 20 - MODIF DeleteAllFiles for empty sPath
// 2004 nov 11 - MODIF and test GetDirExe 
// 2004 nov 11 - MODIF CreatePaper for work at network
// 2004 nov 05 - MODIF BOOL CreatePaper if (CFileMng::IsDirExist (sFullPath)) return TRUE;
// 2004 nov 05 - MODIF BOOL GetDirExe (CString & sDirExe) for UNS file name
// 2004 jan 04 - MODIF CreatePaper.
// 2003 dec 02 - MODIF GetDirExe. Bug with FAR

#include "stdafx.h"

#include "FileMng.h"
#include <objbase.h>
#include "StringArrayEx.h"
#include <shlwapi.h>
#pragma comment (lib,"version.lib")
#pragma comment (lib,"shlwapi.lib")

/************************************************************************\
	File already exist?
\************************************************************************/
BOOL		CFileMng::IsFileExist (const CString& sFName)
{
	if (sFName.IsEmpty ())
		return FALSE;
#if 0
	//NMS : Очень долго
	FILE * stream = fopen ((LPCSTR)sFName, "r");
	if (!stream)
		return FALSE;	
	fclose (stream);
#endif
	const DWORD dwAttr=GetFileAttributes(sFName);
	return (dwAttr!=DWORD(-1) && (!(dwAttr&FILE_ATTRIBUTE_DIRECTORY)));
}

/************************************************************************\
	Get ONLY filename.extension without path 
\************************************************************************/
CString		CFileMng::GetFileName (const CString & sFullFileName)
{
	LPCTSTR lpFirst = (LPCSTR)sFullFileName;
	LPCTSTR lpsz =  _tcsrchr(lpFirst, (_TUCHAR) '\\');
	return (lpsz == NULL) ? sFullFileName : lpsz+1;
#if 0
	//KAA : Какие-то извраты
	int nPos = sFullFileName.GetLength ();
	while (nPos != 0 && sFullFileName[--nPos] != (CString)"\\");
	if (nPos == 0)
		nPos--;
	
	CString sRet;
	while (++nPos < sFullFileName.GetLength ())
		sRet += sFullFileName[nPos];
	return sRet;
#endif

}

/************************************************************************\
	Get path of file
\************************************************************************/
CString		CFileMng::GetPath	(CString sPathFile)
{

	sPathFile.Replace ('/', '\\');
	LPCTSTR lpFirst = (LPCSTR)sPathFile;
	LPCTSTR lpsz =  _tcsrchr(lpFirst, (_TUCHAR) '\\');
	return (lpsz == NULL) ? sPathFile : sPathFile.Left(lpsz - lpFirst);
#if 0
	//KAA : Какие-то извраты

	int nPos = sPathFile.GetLength ();
	while (nPos != 0 && sPathFile[--nPos] != '\\');
	sPathFile.GetBufferSetLength (nPos);
	return sPathFile;
#endif
}

/************************************************************************\
	Get extension of file
\************************************************************************/
CString		CFileMng::GetExtFileName (const CString & sFullFileName)
{
	LPCTSTR lpFirst = (LPCSTR)sFullFileName;
	LPCTSTR lpsz =  _tcsrchr(lpFirst, (_TUCHAR) '.');
	return (lpsz == NULL) ? "" : lpsz+1;
#if 0
	//KAA : Какие-то извраты
	int nPos = sFullFileName.GetLength ();
	while (nPos != 0 && sFullFileName[--nPos] != (CString)".");
	if (0 == nPos)
		return "";
		
	CString sRet;
	while (++nPos < sFullFileName.GetLength ())
		sRet += sFullFileName[nPos];
	return sRet;
#endif
}

/************************************************************************\
	Get File Name Without extension
\************************************************************************/
CString		CFileMng::GetPathFileWOExt (const CString & sFullFileName)
{
/*	int nPos = sFullFileName.GetLength ();
	while (nPos != 0 && sFullFileName[--nPos] != (CString)".");
	if (0 == nPos)
		return sFullFileName;
		
	CString sRet = sFullFileName;
	sRet.Delete (nPos, sFullFileName.GetLength () - nPos);
	return sRet;
*/	LPCTSTR lpFirst = (LPCSTR)sFullFileName;
	LPCTSTR lpsz =  _tcsrchr(lpFirst, (_TUCHAR) '.');
	return (lpsz == NULL) ? sFullFileName : sFullFileName.Left(lpsz - lpFirst);

}

/************************************************************************\
	Get unic file name based on GUID
\************************************************************************/
long log_4(long x)
{
	long xx = x*x;
	return static_cast<long>(-(x*( 1. + xx/3.) - xx/4.*(2. + xx) ));
}

CString		CFileMng::GetUnicName (const CString sExtension /*= ""*/)
{
	GUID guid;
	CString sRet;
	CoCreateGuid (&guid);
#if 1
	sRet.Format ("%04X_%04X_%04X_%04X_%04X_%04X_%08X", guid.Data2, guid.Data3, 
			*((unsigned short *)guid.Data4), *((unsigned short *)(guid.Data4+2)),
			*((unsigned short *)(guid.Data4+4)), *((unsigned short *)(guid.Data4+6)),
			guid.Data1);
	return sRet + sExtension;
#else
	timeb tbeg;
	ftime (&tbeg);

#define _MUL_	111111113
	static int nMul = _MUL_ + 1;
	if (!(--nMul))
		nMul = _MUL_;

	sRet.Format ("%04X_%04X_%04X_%04X_%04X_%04X_%X%X", guid.Data2, guid.Data3, 
			*((unsigned short *)guid.Data4), *((unsigned short *)(guid.Data4+2)),
			*((unsigned short *)(guid.Data4+4)), *((unsigned short *)(guid.Data4+6)),
			guid.Data1, (unsigned int)log_4(tbeg.time * nMul));
	return sRet + sExtension;
#endif
}

/************************************************************************\
	Get list path file name by recurive
\************************************************************************/
void	CFileMng::GetListFileName (CString sPath, CStringArrayEx& saRet, 
		const CString & sMask /*= "*.*"*/, const DWORD dwStyle /*= 0*/)
{
	CFileFind finder;
	BOOL bWorking;
	// AKV: Учитываем относительные пути
	CFileMng::CanonicalizePath(sPath, sPath);

	if (dwStyle & FMNG_RECURS)		// run recursive by directory
	{
		bWorking = finder.FindFile (sPath + "\\*.*");
		while (bWorking)
		{
			bWorking = finder.FindNextFile();
			if (finder.IsDots ())
				continue;

			if (finder.IsDirectory())
				GetListFileName (
				sPath + '\\' + finder.GetFileName (), saRet, sMask, dwStyle);
		}
	}

// scan files by mask
	bWorking = finder.FindFile (sPath + "\\" + sMask);
	while (bWorking)
	{
		bWorking = finder.FindNextFile();
		if (!finder.IsDirectory ())
		{
			if (!(dwStyle & FMNG_PROCDIR))
				saRet.Add (dwStyle & FMNG_ADDPATH ? 
					finder.GetFilePath () : finder.GetFileName ());
			continue;
		}

// proc for directory
		if (!(dwStyle & FMNG_PROCDIR) || finder.IsDots ())		// proc only with directory
			continue;

			saRet.Add (dwStyle & FMNG_ADDPATH ? 
				finder.GetFilePath () : finder.GetFileName ());
	}
}

BOOL	CFileMng::DeleteAllFiles	(const CString& sPath, 
			const DWORD dwStyle /*= 0*/, CString sMask /*= "*.*"*/)
{
	if (sPath.IsEmpty ()) 
		return TRUE;

// clear temp directory
	CStringArrayEx saDelTemp;
	CFileMng::GetListFileName (sPath, saDelTemp, sMask, FMNG_ADDPATH | dwStyle);

	BOOL bDelOK = TRUE;
	FOR_ALL_STR (pStrDel, saDelTemp)
	{
		if (!CFileMng::DeleteFile(*pStrDel))
		{
			bDelOK = FALSE;
		}
	}
	
	return bDelOK;
}

BOOL	CFileMng::CreatePaper	(CString sFullPath)
{
	if (sFullPath.IsEmpty ())
		return FALSE; // (FALSE, "Строка пуста!");
	
	if (CFileMng::IsDirExist (sFullPath)) 
		return TRUE;

// replace double spaces and slash
	sFullPath.Replace ('/', '\\');
	while (sFullPath.Replace ("  ", " "));

// process of creating
	CString sCurDir;
	int nPos;
	do {
		sFullPath.TrimLeft ();
		if (0 == (nPos = sFullPath.Find ('\\', 0)))
		{
			sCurDir += '\\';
			sFullPath.Delete (0, 1);
			continue;
		}

		if (!sCurDir.IsEmpty ())
			sCurDir += '\\';
		
		sCurDir += (nPos > 0 ? sFullPath.Left (nPos) : sFullPath);
		sCurDir.TrimRight ();
		if (sCurDir[sCurDir.GetLength () - 1] == '\\')
			sCurDir.Delete (sCurDir.GetLength () - 1);
		else
			if (!CFileMng::IsDirExist (sCurDir)) 
				CreateDirectory (sCurDir, NULL);
		sFullPath.Delete (0, nPos + 1);
	} while (nPos != -1);

	return TRUE;
} 

//NMS : В отличии от функции CreatePaper не корректирует путь,
//		а так же возращает FALSE, если не удалось создать
//		один из каталогов в пути.
/*static*/ BOOL CFileMng::CreateDirTree(LPCTSTR lpszPath)
{
	CString sFullPath(lpszPath);
	//NMS : Пустая строка
	if (sFullPath.IsEmpty ())
	{
		return FALSE; // (FALSE, "Строка пуста!");
	}
	//NMS : Путь уже существует	
	if (CFileMng::IsDirExist (sFullPath)) 
	{
		return TRUE;
	}
	BOOL bResult=TRUE;
	//NMS : Формируем массив
	CStringArrayEx saDirs;
	//NMS : Приведем все разделители к одному виду
	sFullPath.Replace(_T("/"),_T("\\"));
	//NMS : Уберем хвостовой
	sFullPath.TrimRight(_T("\\"));
	//NMS : Разберем путь на каталоги
	saDirs.FillFromString(sFullPath,_T('\\'));
	//NMS : Если это UNC
	const BOOL bIsUnc=sFullPath.Find(_T("\\\\"))==0 ? TRUE:FALSE;
	//NMS : Бежим по каталогам и собираем путь
	CString strMakePF;	
	FOR_ALL_CONST_STR(pDir,saDirs)
	{
		if (!strMakePF.IsEmpty())
		{
			strMakePF+=_T('\\');
		}
		else
		{
			if (bIsUnc!=false)
			{//NMS : Имя машины в этом случае пропустим
				strMakePF=_T("\\\\");
				strMakePF+=*pDir;
				continue;
			}
		}
		strMakePF+=*pDir;		
		//NMS : Смотрим, существует
		if (CFileMng::IsDirExist(strMakePF)==FALSE)
		{
			//NMS : Не существует, создаем
			bResult=::CreateDirectory(strMakePF,NULL);
			//NMS : Если не удалось создать выходим
			if (FALSE==bResult)
			{
				break;
			}
		}
	}
	//NMS : Вернем результат работы
	return bResult;
}

void CFileMng::GetDirWin	(CString & sDirWin)
{
	char chBuf[_MAX_PATH];
	GetWindowsDirectory (chBuf, _MAX_PATH);
	sDirWin = chBuf;
}

CString	CFileMng::GetSysVar (CString sVarName)
{
	CString sVarNamePercent = (CString)'%' + sVarName + '%';
	char chBuf[_MAX_PATH];
	ExpandEnvironmentStrings(sVarNamePercent, chBuf, _MAX_PATH);
	return chBuf;
}

CString	CFileMng::GetFolderPath	(DWORD dwFlags)
{
//	TCHAR szPath[MAX_PATH];
//	if (SUCCEEDED (SHGetFolderPath (NULL, dwFlags, NULL, 0, szPath)))
//		return szPath;
//	return "";

	CString sTempDir;
	char chBufDrive[_MAX_PATH + 1], chBufPath[_MAX_PATH + 1];
	if (ExpandEnvironmentStrings ((CString)"%HOMEDRIVE%", chBufDrive, _MAX_PATH) &&
		ExpandEnvironmentStrings ((CString)"%HOMEPATH%", chBufPath, _MAX_PATH) &&
		(CString)"%HOMEDRIVE%" != (CString)chBufDrive &&
		(CString)"%HOMEPATH%" != (CString)chBufPath)
	{
		sTempDir = (CString)chBufDrive + (CString)chBufPath;
	}	else	{
		GetTempPath(_MAX_PATH, chBufPath);
		sTempDir = chBufPath;		
	}

	if (!sTempDir.IsEmpty () && sTempDir[sTempDir.GetLength () - 1] == '\\') 
		sTempDir.Delete (sTempDir.GetLength () - 1);

//	CString sTempFile = sTempDir + "\\temp.tmp";
//	if (!CStringProc::fWrite (sTempFile, sTempFile)) 
//		throw CString ("Невозможно сделать запись во временный каталог :\n") 
//			+ sTempDir + "\nПроверьте атрибуты доступа к данному каталогу.";
//	DeleteFile (sTempFile);
	return sTempDir;
}

BOOL		CFileMng::GetDirExe		(CString & sDirExe)
{
	char chBuf[_MAX_PATH];

// define exe directory
// if it's a dll argv will be NULL and it may cause memory leak	
#ifndef _USRDLL
	CString sAllRunString, tmpFilePath;

	BOOL bAppend = TRUE;
	for (int i = 0; i < __argc; i++)
	{
		sAllRunString += __argv[i];
		sAllRunString += ' ';
		
		if (bAppend) 
		{
			tmpFilePath += __argv[i];
			tmpFilePath += ' ';
		}
		if (bAppend && CStringProc::HavePostfix (tmpFilePath, ".exe "))
			bAppend = FALSE;
	}

// may be dir have postfix ".exe"
	sAllRunString.MakeLower ();
	if (sAllRunString.Replace (".exe", "    ") > 1) 
		tmpFilePath = __argv[0];
	else
		tmpFilePath.TrimRight ();

	tmpFilePath.Replace ("/", "\\");
	GetCurrentDirectory (MAX_PATH, chBuf);
	const CString sDirExeCur = chBuf;
	const int nPlace = tmpFilePath.ReverseFind ('\\');
// in call parameters contents logical path
	do{
		if (nPlace == -1)
		{
			sDirExe = sDirExeCur;
			break;
		}	

		if ((tmpFilePath.GetLength () > 1 && tmpFilePath[1] == ':') ||
			sDirExeCur.GetLength () > 1 && CStringProc::HavePrefix (sDirExeCur, "\\\\"))
		{
			sDirExe = tmpFilePath.Left(nPlace);
			break;
		}	

		sDirExe = sDirExeCur + '\\' + tmpFilePath.Left(nPlace);
	} while (FALSE);

	TRACE("CurDir = %s TmpDir = %s ResDir = %s\n", sDirExeCur, tmpFilePath.Left(nPlace), sDirExe);
#else
	//it must be safe for dll's
	GetCurrentDirectory (MAX_PATH, chBuf);
	sDirExe = chBuf;
	TRACE("DirExe = %s\n", sDirExe);
#endif

	CStringArrayEx saFilesExe;
	CFileMng::GetListFileName (sDirExe, saFilesExe, "*.exe", FMNG_ADDPATH);
	if (saFilesExe.GetSize ()) 
		sDirExe = CFileMng::GetPath (saFilesExe[0]);

//	AfxMessageBox (sDirExeCur + " 1\n" + tmpFilePath.Left(nPlace) + " 2\n" + sDirExe);
	return TRUE;
}

/************************************************************************\
	Dir is exist
\************************************************************************/
BOOL		CFileMng::IsDirExist (CString sPath)
{
#if 0
	//NMS : Это очень долго
	CString sPFTemp = sPath + '\\' + CFileMng::GetUnicName ();
	if (!CStringProc::fWrite (sPFTemp, sPFTemp)) 
		return FALSE;
	DeleteFile (sPFTemp);
	return TRUE;
#endif
	// AKV: Проблема с относительными путями
	CString strCanonical;
	if (!CFileMng::CanonicalizePath(sPath, strCanonical))
		return FALSE;
//	const DWORD dwAttr=GetFileAttributes(sPath);
	const DWORD dwAttr=GetFileAttributes(strCanonical);
	// AKV End
	return (dwAttr!=DWORD(-1)) && (dwAttr&FILE_ATTRIBUTE_DIRECTORY);
}

void		CFileMng::MovingFile	(CString sPFSrc, CString sPFDst)
{
	if (IsFileExist (sPFDst)) 
		DeleteFile (sPFDst);
	MoveFile (sPFSrc, sPFDst);
	DeleteFile (sPFSrc);
}

//NMS : Считает кол-во файлов в директории
/*static*/ LONG CFileMng::GetCountFilesInDir(LPCTSTR lpszDirPath,LPCTSTR lpszMask/*=_T("*.*")*/)
{
	CStringArrayEx saFiles;
	CFileMng::GetListFileName(lpszDirPath,saFiles,CString(lpszMask),0x00);
	return saFiles.GetSize();
}

//NMS : Удаляет файл, даже если он ReadOnly
/*static*/ BOOL CFileMng::DeleteFile(LPCTSTR lpszFilePath)
{
	ASSERT(lpszFilePath!=NULL);	
	DWORD dwFileAttr=::GetFileAttributes(lpszFilePath);
	if (dwFileAttr==DWORD(-1))
	{
		return FALSE;
	}
	//NMS : Если он только для чтения
	if (dwFileAttr&FILE_ATTRIBUTE_READONLY)
	{
		//NMS : Снимаем
		dwFileAttr&=~FILE_ATTRIBUTE_READONLY;
		//NMS : Установим новые атрибуты
		if (!::SetFileAttributes(lpszFilePath,dwFileAttr))
		{
			return FALSE;
		}
	}
	//NMS : Удаляем
	if (!::DeleteFile(lpszFilePath))
	{
		return FALSE;
	}
	//NMS : Файл удален !
	return TRUE;
}

//DIP : проверка возможности записи в папку
/*static*/ BOOL CFileMng::IsFolderWriteable( LPCTSTR strFolder )
{
	CString folder = strFolder;
	if( folder.GetAt( folder.GetLength() - 1 ) != '\\' )
		folder += _T("\\");


	TCHAR szTempPath[_MAX_PATH]={0};	
	GetTempFileName( folder, _T("taxcom"), 0, &szTempPath[0]);

	CFile file;
	if( file.Open( szTempPath, CFile::modeCreate | CFile::modeReadWrite ) )
	{
		file.Close();
		DeleteFile( szTempPath );

		return TRUE;
	}
	else
		return FALSE;
}

//DIP : проверяет список директорий на возможность записи ( -1 если все достпны для записи )
/*static*/ int CFileMng::IsFolderListWriteable( CStringArray &ar )
{
	for(int  i = 0; i < ar.GetSize(); i++)
		if( !IsFolderWriteable( ar.GetAt( i ) ) )
			return i;
	
	return -1;
}

// AKV: Папка TEMP
/*static*/ CString CFileMng::GetDirTemp()
{
	TCHAR szBuffer[MAX_PATH];
	if (::GetTempPath(sizeof(szBuffer) / sizeof(szBuffer[0]), szBuffer) == 0)
		szBuffer[0] = 0;
	return szBuffer;
}
// Функия возвращает значение параметра из \\StringFileInfo\\
//
CString GetStringVersionParam(LPVOID lpFixedFileInf,LPCTSTR Param)
{
	
	struct 
	{
		WORD LangID, CharSet;
	} *Array;
	
	UINT uLen = 0;                   
	
	
	if (!VerQueryValue(lpFixedFileInf,"\\VarFileInfo\\Translation",(LPVOID*)(&Array),&uLen ))	return "";
	
	char QueryBlock[1024];
	
	wsprintf(QueryBlock,"\\StringFileInfo\\%04x%04x\\%s",Array->LangID,Array->CharSet,Param);
	
	LPSTR pStr;
	CString sParam;
	if (VerQueryValue(lpFixedFileInf,QueryBlock,(LPVOID*)(&pStr),&uLen ))
	{
		sParam.Format("%s",pStr);
	}
	
	return sParam;
}

// KAA: Версия файла
/*static*/ BOOL CFileMng::GetFileVersion(LPCTSTR pszFileName,CString &Version)
{
	
    Version = "Файл не найден";
	
	struct CStringVersion
	{
		CString ProductName;
		CString FileVersion;
		CString FileDescription;
		CString ProductVersion;
	} StringVersion;
	LPVOID lpFixedFileInf=NULL;
	try
	{
		
		int size = ::GetFileVersionInfoSize((char*)pszFileName,NULL);	
		if (size<1) return FALSE;
		
		lpFixedFileInf = new char[size];
		
		if (!::GetFileVersionInfo((char*)pszFileName,NULL,size,lpFixedFileInf)) 
		{
			if (lpFixedFileInf!=NULL)
				delete []lpFixedFileInf;
			return FALSE;
		}
		
		{
			StringVersion.ProductVersion = GetStringVersionParam(lpFixedFileInf,"ProductVersion");
			StringVersion.FileVersion = GetStringVersionParam(lpFixedFileInf,"FileVersion");
			StringVersion.FileDescription = GetStringVersionParam(lpFixedFileInf,"FileDescription");
			StringVersion.ProductName = GetStringVersionParam(lpFixedFileInf,"ProductName");
			
		}
		if (StringVersion.FileVersion.GetLength()==0)
		{
			
			VS_FIXEDFILEINFO *pFixedFileInfo; // указатель на структуру VS_FIXEDFILEINFO
			UINT uLen = 0;                   
			
			
			if (!VerQueryValue(lpFixedFileInf,"\\",(LPVOID*)(&pFixedFileInfo),&uLen ))
			{
				if (lpFixedFileInf!=NULL)
					delete []lpFixedFileInf;
				return FALSE;
			}
			
			wsprintf (Version.GetBufferSetLength(260), 
				"%01.1d.%01.1d.%01.1d.%01.1d",
				HIWORD (pFixedFileInfo->dwFileVersionMS),
				LOWORD(pFixedFileInfo->dwFileVersionMS),
				HIWORD (pFixedFileInfo->dwFileVersionLS),
				LOWORD(pFixedFileInfo->dwFileVersionLS));
			
			Version.ReleaseBuffer();
		}
		else
		{
			Version = StringVersion.FileDescription + ", "+ StringVersion.FileVersion;
		}
	}
	catch(...)
	{
		Version = "Файл не найден";
		if (lpFixedFileInf!=NULL)
			delete []lpFixedFileInf;
		return FALSE;
	}
	if (lpFixedFileInf!=NULL)
		delete []lpFixedFileInf;
	return TRUE;
}

//AKV: Получение каталога с EXE правильным образом
/* static */ BOOL CFileMng::GetDirExeEx(CString& strDirExe)
{
	try
	{
		TCHAR szPath[MAX_PATH];

		if (::GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
			throw ::GetLastError();
		::PathRemoveFileSpec(szPath);
		strDirExe = szPath;
	}
	catch (DWORD dwErr)
	{
		dwErr;
		TRACE("CFileMng::GetDirExeEx ERROR - 0x%X\n", dwErr);
		return FALSE;
	}

	return TRUE;
}

/* static */ BOOL CFileMng::CanonicalizePath(CString strDirIn, CString& strDirOut)
{
	if (strDirIn[0] == '.')
	{
		CString strDirExe;
		CFileMng::GetDirExeEx(strDirExe);
		strDirIn = strDirExe + '\\' + strDirIn;
	}
	TCHAR szCanonical[MAX_PATH];
	if (!::PathCanonicalize(szCanonical, strDirIn))
		return FALSE;
	strDirOut = szCanonical;
	return TRUE;
}
//КПМ: быстрый подсчет количества файлов в каталоге с использованием подкаталогов и расширения
/* static */int CFileMng::CountFiles(const std::string &refcstrRootDirectory,
			   const std::string &refcstrExtension,
			   bool bSubdirectories /*= false*/)
{
	int             iCount          = 0;
	std::string     strFilePath;          // Filepath
	std::string     strPattern;           // Pattern
	std::string     strExtension;         // Extension
	HANDLE          hFile;                // Handle to file
	WIN32_FIND_DATA FileInformation;      // File information


	strPattern = refcstrRootDirectory + "\\" + refcstrExtension;
	hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if(FileInformation.cFileName[0] != '.')
			{
				strFilePath.erase();
				strFilePath = refcstrRootDirectory +
					"\\" +
					FileInformation.cFileName;

				if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if(bSubdirectories)
					{
						// Search subdirectory
						int iRC = CountFiles(strFilePath,
							refcstrExtension,
							bSubdirectories);
						if(iRC != -1)
							iCount += iRC;
						else
							return -1;
					}
				}
				else
				{
					// Check extension
					strExtension = FileInformation.cFileName;
					strExtension = strExtension.substr(strExtension.rfind(".") + 1);

					if((refcstrExtension == "*") ||
						(strExtension == refcstrExtension))
					{
						// Increase counter
						++iCount;
					}
				}
			}
		} while(::FindNextFile(hFile, &FileInformation) == TRUE);

		// Close handle
		::FindClose(hFile);
	}

	return iCount;
}
//КПМ: имя самого нового подкаталога в каталоге 
/* static */std::string CFileMng::GetLastCreatedDir(const std::string &refcstrRootDirectory)
{
	std::string     strDirPath;          // Filepath
	std::string     strPattern;           // Pattern
	HANDLE          hFile;                // Handle to file
	WIN32_FIND_DATA FileInformation;      // File information
	FILETIME		ftDirCreate;


	strPattern = refcstrRootDirectory + "\\*";
	hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
	ftDirCreate.dwHighDateTime = 0;
	ftDirCreate.dwLowDateTime = 0;
	if(hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if(FileInformation.cFileName[0] != '.')
			{
				if(FileInformation.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
					if(CompareFileTime(&FileInformation.ftCreationTime, &ftDirCreate) == 1)
					{
						ftDirCreate = FileInformation.ftCreationTime;
						strDirPath = FileInformation.cFileName;
					}
			}
			
		} while(::FindNextFile(hFile, &FileInformation) == TRUE);

		// Close handle
		::FindClose(hFile);
	}

	return strDirPath;
}
