/* coding.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifndef __BASE64
#define __BASE64
typedef unsigned int	word32;
#include "define.h"
#ifdef __cplusplus  
extern "C" {
#endif  


	int Base64_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);

	int Base64_Encode(const byte* in, word32 inLen, byte* out, word32* outLen);
#ifdef __cplusplus  
}
#endif  


#endif

