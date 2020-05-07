/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: base64.h,v 1.3 2008/08/04 15:31:07 dembour Exp $
**
** 
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __BASE_32_H
#define __BASE_32_H

#undef MIN
#define MIN(a,b)	((a) > (b) ? (b) : (a))


/* 
  Bloc size = 4
  each bloc is 3 of real data
*/
#define BASE32_SIZE(len)  (((len)/5)*8 + ((len) % 5 ? 8 : 0))
#define DECODED_BASE32_SIZE(len)  (((len)/8)*5)


extern int base32_encode(unsigned char *plain, unsigned char *coded, int len);
extern int base32_decode(unsigned char *plain, unsigned char *coded);

#ifndef HAVE_STRCASESTR
extern char *strcasestr(const char *, const char *);
#endif

#endif

