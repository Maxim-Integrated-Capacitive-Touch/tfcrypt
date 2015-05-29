/******************************************************************************
* Copyright (C) 2015 Maxim Integrated Products, Inc., All rights Reserved.
*
* This software is protected by copyright laws of the United States and
* of foreign countries. This material may also be protected by patent laws
* and technology transfer regulations of the United States and of foreign
* countries. This software is furnished under a license agreement and/or a
* nondisclosure agreement and may only be used or reproduced in accordance
* with the terms of those agreements. Dissemination of this information to
* any party or parties not specified in the license agreement and/or
* nondisclosure agreement is expressly prohibited.
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
* OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
*
* Except as contained in this notice, the name of Maxim Integrated
* Products, Inc. shall not be used except as stated in the Maxim Integrated
* Products, Inc. Branding Policy.
*
* The mere transfer of this software does not imply any licenses
* of trade secrets, proprietary technology, copyrights, patents,
* trademarks, maskwork rights, or any other form of intellectual
* property whatsoever. Maxim Integrated Products, Inc. retains all
* ownership rights.
******************************************************************************/

#include "CryptDLL.h"

extern "C"
{
	extern short  kfetch(unsigned short *k, unsigned short klen, unsigned char *cp);
	extern int  encode_buffer(unsigned char *inBuf, unsigned int inBufSize, unsigned char *outBuf, unsigned int outBufSize, unsigned int *outBufUsed);
	extern int  encrypt_buffer(unsigned char *key, short key_len, unsigned char *in,  unsigned int insize, unsigned char *out, unsigned int outsize, unsigned int *rsize);
	extern int  decrypt_buffer(unsigned char *key, short key_len, unsigned char *in,  unsigned int insize, unsigned char *out, unsigned int outsize, unsigned int *rsize);
	extern int  decode_buffer(unsigned char *inBuf, unsigned int inBufSize, unsigned char *outBuf, unsigned int outBufSize, unsigned int *outBufUsed);

	BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
	{
		switch (ul_reason_for_call)
		{
			case DLL_PROCESS_ATTACH:
				break;
			case DLL_THREAD_ATTACH:
				break;
			case DLL_THREAD_DETACH:
				break;
			case DLL_PROCESS_DETACH:
				break;
		}

		return TRUE;
	}

	__declspec(dllexport) short __stdcall  kfetch_a(unsigned short *k, unsigned short klen, unsigned char *cp)
	{
		return kfetch(k, klen, cp);
	}

	__declspec(dllexport) int __stdcall  encode_buffer_a(unsigned char *inBuf, unsigned int inBufSize, unsigned char *outBuf, unsigned int outBufSize, unsigned int *outBufUsed)
	{
		return encode_buffer(inBuf, inBufSize, outBuf, outBufSize, outBufUsed);
	}

	__declspec(dllexport) int __stdcall  encrypt_buffer_a(unsigned char *key, short key_len, unsigned char *in,  unsigned int insize, unsigned char *out, unsigned int outsize, unsigned int *rsize)
	{
		return encrypt_buffer(key, key_len, in,  insize, out, outsize, rsize);
	}

	__declspec(dllexport) int __stdcall  decrypt_buffer_a(unsigned char *key, short key_len, unsigned char *in,  unsigned int insize, unsigned char *out, unsigned int outsize, unsigned int *rsize)
	{
		return decrypt_buffer(key, key_len, in,  insize, out, outsize, rsize);
	}

	__declspec(dllexport) int __stdcall  decode_buffer_a(unsigned char *inBuf, unsigned int inBufSize, unsigned char *outBuf, unsigned int outBufSize, unsigned int *outBufUsed)
	{
		return decode_buffer(inBuf, inBufSize, outBuf, outBufSize, outBufUsed);
	}
}
