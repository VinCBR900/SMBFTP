/*****************************************************************************
 *  __________________    _________  _____            _____  .__         ._.
 *  \______   \______ \  /   _____/ /     \          /  _  \ |__| ____   | |
 *   |    |  _/|    |  \ \_____  \ /  \ /  \        /  /_\  \|  _/ __ \  | |
 *   |    |   \|    `   \/        /    Y    \      /    |    |  \  ___/   \|
 *   |______  /_______  /_______  \____|__  / /\   \____|__  |__|\___ |   __
 *          \/        \/        \/        \/  )/           \/        \/   \/
 *
 * This file is part of liBDSM. Copyright © 2014-2015 VideoLabs SAS
 *
 * Author: Julien 'Lta' BALLET <contact@lta.io>
 *
 * liBDSM is released under LGPLv2.1 (or later) and is also available
 * under a commercial license.
 *****************************************************************************
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
# include <iconv.h>
# include <locale.h>
# if HAVE_NL_LANGINFO && !defined( __APPLE__ )
#  include <langinfo.h>
# endif
#else
# include "winmini.h"
#endif

#include "bdsm_debug.h"
#include "smb_utils.h"


/*
 * smbftp port, v0.6 (see libdsm-v0.6-fixes.diff):
 *   - both conversions return a buffer that is followed by a zero terminator
 *     (the Windows branch used to allocate the exact length; smb_trans2.c wrote
 *     name[name_len] = 0 one byte past it: heap overflow)
 *   - a character that cannot be converted becomes '?' (it used to fail the
 *     whole conversion, which ended a directory listing at that name)
 *   - iconv branch uses UTF-16LE, so characters outside the BMP (emoji) work
 *   - the returned length never includes the terminator
 */

#ifdef _WIN32

/*
 * TCC port: Windows has no iconv, so the two conversions use the Win32 API.
 * Local text is taken to be in the process's ANSI code page (CP_ACP), which is
 * also what argv, fopen() and the other *A / msvcrt functions use, so names
 * typed on the command line round-trip. Define SMB_WIN_CODEPAGE (e.g. 65001
 * for UTF-8) to use another code page. Characters the code page cannot
 * represent become '?' instead of failing the conversion.
 */
#ifndef SMB_WIN_CODEPAGE
# define SMB_WIN_CODEPAGE 0
#endif

/*
 * smb_to_utf16 - convert local-codepage text to UTF-16LE
 * Inputs : src/src_len = text and its length in bytes (a trailing NUL counts
 *          if included), dst = result pointer
 * Outputs: length in bytes of the UTF-16LE text (no terminator counted), *dst
 *          = malloc'ed buffer with a 2-byte zero terminator after the text;
 *          0 and *dst = NULL on failure
 * Clobbers: *dst
 */
size_t      smb_to_utf16(const char *src, size_t src_len, char **dst)
{
    unsigned short  *out;
    int             n;

    assert(src != NULL && dst != NULL);

    *dst = NULL;
    if (src_len == 0 || src_len > 0x7FFFFFFF)
        return 0;
    n = MultiByteToWideChar(SMB_WIN_CODEPAGE, 0, src, (int)src_len, NULL, 0);
    if (n <= 0)
        return 0;
    if ((out = malloc((size_t)n * 2 + 2)) == NULL)
        return 0;
    if (MultiByteToWideChar(SMB_WIN_CODEPAGE, 0, src, (int)src_len, out, n) != n)
    {
        free(out);
        return 0;
    }
    out[n] = 0;
    *dst = (char *)out;
    return (size_t)n * 2;
}

/*
 * smb_from_utf16 - convert UTF-16LE to local-codepage text
 * Inputs : src/src_len = UTF-16LE text (may be unaligned) and its length in
 *          bytes (must be even and non-zero), dst = result pointer
 * Outputs: length in bytes of the converted text (no terminator counted), *dst
 *          = malloc'ed buffer with a zero terminator after the text; 0 and
 *          *dst = NULL on failure
 * Clobbers: *dst
 */
size_t      smb_from_utf16(const char *src, size_t src_len, char **dst)
{
    const unsigned short  *wsrc = (const unsigned short *)src;
    unsigned short        *aligned = NULL;
    char                  *out;
    int                   n, wlen;

    assert(src != NULL && dst != NULL);

    *dst = NULL;
    if (src_len == 0 || (src_len & 1) || src_len / 2 > 0x7FFFFFFF)
        return 0;
    wlen = (int)(src_len / 2);
    if ((size_t)src & 1)    // wire data can be unaligned
    {
        if ((aligned = malloc(src_len)) == NULL)
            return 0;
        memcpy(aligned, src, src_len);
        wsrc = aligned;
    }
    n = WideCharToMultiByte(SMB_WIN_CODEPAGE, 0, wsrc, wlen, NULL, 0, NULL, NULL);
    if (n <= 0 || (out = malloc((size_t)n + 1)) == NULL)
    {
        free(aligned);
        return 0;
    }
    if (WideCharToMultiByte(SMB_WIN_CODEPAGE, 0, wsrc, wlen, out, n, NULL, NULL) != n)
    {
        free(out);
        free(aligned);
        return 0;
    }
    free(aligned);
    out[n] = '\0';
    *dst = out;
    return (size_t)n;
}

#else   /* !_WIN32: iconv */

/*
 * current_encoding - name of the locale's character set
 * Inputs : none
 * Outputs: iconv name of the encoding
 * Clobbers: process locale (setlocale(LC_ALL, "") once)
 */
static const char *current_encoding(void)
{
#if defined( __APPLE__ )
    return "UTF8";
#elif !HAVE_NL_LANGINFO
    return "UTF-8";
#else
    static int locale_set = 0;

    if (!locale_set)
    {
        setlocale(LC_ALL, "");
        locale_set = 1;
    }
    //BDSM_dbg("%s\n", nl_langinfo(CODESET));
    return nl_langinfo(CODESET);
#endif
}

/*
 * smb_iconv - convert a buffer, replacing what cannot be converted
 * Inputs : src/src_len = input; dst = result pointer; src_enc/dst_enc = iconv
 *          encoding names (the UTF-16 side first tries "UTF-16LE", then
 *          "UCS-2LE"); src_utf16 = 1 if the input is UTF-16LE (a bad unit is
 *          skipped as 2 bytes, or 4 for a surrogate pair), 0 if it is a
 *          multibyte text (a bad byte is skipped as 1); repl/repl_len = bytes
 *          written for each skipped input unit, in the output encoding
 * Outputs: bytes written (terminator not counted), *dst = malloc'ed zeroed
 *          buffer with at least 4 spare zero bytes after the text; 0 and
 *          *dst = NULL if the input is empty, iconv is unavailable or nothing
 *          was produced
 * Clobbers: *dst, errno
 */
static size_t smb_iconv(const char *src, size_t src_len, char **dst,
                        const char *src_enc, const char *dst_enc,
                        int src_utf16, const char *repl, size_t repl_len)
{
    iconv_t     ic;
    char        *out, *outp;
    const char  *inp;
    size_t      inb, outb, outlen, ret = 0;

    assert(src != NULL && dst != NULL && src_enc != NULL && dst_enc != NULL);

    *dst = NULL;
    if (!src_len)
        return 0;

    ic = iconv_open(dst_enc, src_enc);
    if (ic == (iconv_t)-1)
    {
        // some iconv implementations do not know UTF-16LE: use the older name
        ic = iconv_open(strcmp(dst_enc, "UTF-16LE") == 0 ? "UCS-2LE" : dst_enc,
                        strcmp(src_enc, "UTF-16LE") == 0 ? "UCS-2LE" : src_enc);
    }
    if (ic == (iconv_t)-1)
    {
        BDSM_dbg("Unable to open iconv to convert from %s to %s\n",
                 src_enc, dst_enc);
        return 0;
    }

    // Worst case is 4 output bytes per input byte, plus the terminator
    outlen = src_len * 4 + 4;
    if ((out = calloc(1, outlen)) == NULL)
    {
        iconv_close(ic);
        return 0;
    }
    inp  = src;
    inb  = src_len;
    outp = out;
    outb = outlen - 4;                  // keep the terminator space out of reach

    while (inb > 0)
    {
        if (iconv(ic, (char **)&inp, &inb, &outp, &outb) != (size_t)(-1))
            break;
        if (errno == EILSEQ || errno == EINVAL)
        {
            size_t skip = 1;

            if (errno == EINVAL && src_utf16)
                break;                  // odd trailing byte: nothing more to read
            if (src_utf16)
            {
                skip = 2;
                if (inb >= 4)           // surrogate pair: high unit D800-DBFF then low DC00-DFFF
                {
                    unsigned hi = (unsigned char)inp[0] | ((unsigned)(unsigned char)inp[1] << 8);
                    unsigned lo = (unsigned char)inp[2] | ((unsigned)(unsigned char)inp[3] << 8);

                    if (hi >= 0xD800 && hi <= 0xDBFF && lo >= 0xDC00 && lo <= 0xDFFF)
                        skip = 4;
                }
                if (skip > inb)
                    skip = inb;
            }
            else if (errno == EINVAL)
                skip = inb;             // incomplete multibyte sequence at the end
            if (outb < repl_len)
                break;
            memcpy(outp, repl, repl_len);
            outp += repl_len;
            outb -= repl_len;
            inp  += skip;
            inb  -= skip;
            continue;
        }
        break;                          // E2BIG cannot happen (worst-case sizing); anything else is fatal
    }
    iconv_close(ic);

    ret = (size_t)(outp - out);
    if (ret == 0)
    {
        free(out);
        return 0;
    }
    *dst = out;
    return ret;
}

/*
 * smb_to_utf16 - convert local-locale text to UTF-16LE
 * Inputs : src/src_len = text and its length in bytes (a trailing NUL counts
 *          if included), dst = result pointer
 * Outputs: length in bytes of the UTF-16LE text (no terminator counted), *dst
 *          = malloc'ed buffer with a zero terminator after the text; 0 and
 *          *dst = NULL on failure. Unconvertible bytes become '?'.
 * Clobbers: *dst
 */
size_t      smb_to_utf16(const char *src, size_t src_len, char **dst)
{
    return (smb_iconv(src, src_len, dst, current_encoding(), "UTF-16LE",
                      0, "?\0", 2));
}

/*
 * smb_from_utf16 - convert UTF-16LE to local-locale text
 * Inputs : src/src_len = UTF-16LE text and its length in bytes, dst = result
 * Outputs: length in bytes of the converted text (no terminator counted), *dst
 *          = malloc'ed buffer with a zero terminator after the text; 0 and
 *          *dst = NULL on failure. Unconvertible characters become '?'.
 * Clobbers: *dst
 */
size_t      smb_from_utf16(const char *src, size_t src_len, char **dst)
{
    return (smb_iconv(src, src_len, dst, "UTF-16LE", current_encoding(),
                      1, "?", 1));
}

#endif  /* _WIN32 */
