#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef _MSC_VER
#define DLLEXPORT	__declspec( dllexport ) __stdcall
#else
#define DLLEXPORT	/* Nothing */
#endif

#endif
