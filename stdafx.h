/*
#pragma once
// * PHP Extension headers 
// * include zend win32 config first 
#define ZEND_INCLUDE_FULL_WINDOWS_HEADERS
#define SIZEOF_LONG		4
#include "zend_config.w32.h"
// * include standard header 
#include "php.h"

#define _HAS_ITERATOR_DEBUGGING 0
#include <string>

#pragma warning( disable : 4018 )
#pragma warning( disable : 4006 )
*/

#ifndef STDAFX 
#define STDAFX 
#define SIZEOF_LONG		4

// #define _AFXDLL
#define PHP_COMPILER_ID "VC9" // эту опцию мы указываем для совместимости с PHP, скомпилированным Visual C++ 9.0 

// #include "zend_config.w32.h" 
// #include <php.h>
#include <string>
 #include <iostream>
#include <afx.h>
#include <afxdisp.h>
#endif