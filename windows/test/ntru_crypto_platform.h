/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_platform.h is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
 
/******************************************************************************
 *
 * File: ntru_crypto_platform.h
 *
 * Contents: Platform-specific basic definitions.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_PLATFORM_H
#define NTRU_CRYPTO_PLATFORM_H

/* The default implementation is to use stdint.h, a part of the C99 standard.
 * Systems that don't support this are handled on a case-by-case basis.
 */

#if defined(WIN32) && (_MSC_VER < 1600)

#include <basetsd.h>
typedef unsigned char       uint8_t;
typedef signed char         int8_t;
typedef unsigned short int  uint16_t;
typedef short int           int16_t;
typedef UINT32              uint32_t;
typedef UINT64              uint64_t;

#elif defined(linux) && defined(__KERNEL__)

#include <linux/types.h>

#else

#include <stdint.h>

#endif


/* For linux kernel drivers:
 * Use kmalloc and kfree in place of malloc / free
 * Use BUG_ON in place of assert */
#if defined(linux) && defined(__KERNEL__)

#   include  <linux/kernel.h>
#   include  <linux/module.h>
#   include  <linux/slab.h>
#   include  <linux/string.h>
#   define   MALLOC(size) (kmalloc(size, GFP_KERNEL))
#   define   FREE(x) (kfree(x))

#else

#   include  <stdlib.h>
#   include  <assert.h>
#   include  <string.h>
#   define   MALLOC(size) (malloc(size))
#   define   FREE(x) (free(x))

#endif



#if !defined(HAVE_BOOL) && !defined(__cplusplus)
#define HAVE_BOOL
typedef uint8_t bool;
#endif /* HAVE_BOOL */

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif


#endif /* NTRU_CRYPTO_PLATFORM_H */
