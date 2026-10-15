/*
 * winshim.c - Linux implementation of the two Win32 conversion calls (test harness only)
 *
 * Version : 1.0
 * Usage   : linked by build_winutils.sh; see winshim.h
 * History : 1.0  first version.
 */
#include <string.h>
#include "winshim.h"

/*
 * MultiByteToWideChar - multibyte (Latin-1 for cp 0, UTF-8 for 65001) to UTF-16
 * Inputs : cp, flags (ignored), s/slen = source (slen<0: NUL-terminated incl. NUL),
 *          w/wlen = destination (wlen==0: only count)
 * Outputs: UTF-16 units written/needed, 0 on failure
 * Clobbers: w
 */
int MultiByteToWideChar(unsigned cp, unsigned long fl, const char *s, int slen, unsigned short *w, int wlen)
{
    int i, n = 0;
    if (slen < 0) slen = (int)strlen(s) + 1;
    if (cp == 65001) {
        const unsigned char *p = (const unsigned char *)s;
        for (i = 0; i < slen;) {
            uint32_t c = p[i]; int extra = 0;
            if (c >= 0xF0) { c &= 7; extra = 3; } else if (c >= 0xE0) { c &= 15; extra = 2; }
            else if (c >= 0xC0) { c &= 31; extra = 1; }
            if (i + extra >= slen + (extra ? 0 : 1) && extra) return 0;
            for (int k = 1; k <= extra; k++) c = (c << 6) | (p[i + k] & 63);
            i += 1 + extra;
            if (c >= 0x10000) {
                if (wlen) { if (n + 2 > wlen) return 0; w[n] = 0xD800 + ((c - 0x10000) >> 10); w[n+1] = 0xDC00 + ((c - 0x10000) & 0x3FF); }
                n += 2;
            } else { if (wlen) { if (n + 1 > wlen) return 0; w[n] = (unsigned short)c; } n++; }
        }
        return n;
    }
    for (i = 0; i < slen; i++) { if (wlen) { if (n + 1 > wlen) return 0; w[n] = (unsigned char)s[i]; } n++; }
    return n;
}

/*
 * WideCharToMultiByte - UTF-16 to Latin-1 (cp 0, '?' for the unrepresentable) or UTF-8 (65001)
 * Inputs : cp, flags/defc/used (ignored), w/wlen = source, s/slen = destination (slen==0: count)
 * Outputs: bytes written/needed, 0 on failure
 * Clobbers: s
 */
int WideCharToMultiByte(unsigned cp, unsigned long fl, const unsigned short *w, int wlen, char *s, int slen,
                        const char *defc, int *used)
{
    int i, n = 0;
    for (i = 0; i < wlen; i++) {
        uint32_t c = w[i];
        char tmp[4]; int t = 0;
        if (cp == 65001) {
            if (c >= 0xD800 && c < 0xDC00 && i + 1 < wlen && w[i+1] >= 0xDC00 && w[i+1] < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (w[i+1] - 0xDC00); i++;
            }
            if (c < 0x80) tmp[t++] = (char)c;
            else if (c < 0x800) { tmp[t++] = 0xC0 | (c >> 6); tmp[t++] = 0x80 | (c & 63); }
            else if (c < 0x10000) { tmp[t++] = 0xE0 | (c >> 12); tmp[t++] = 0x80 | ((c >> 6) & 63); tmp[t++] = 0x80 | (c & 63); }
            else { tmp[t++] = 0xF0 | (c >> 18); tmp[t++] = 0x80 | ((c >> 12) & 63); tmp[t++] = 0x80 | ((c >> 6) & 63); tmp[t++] = 0x80 | (c & 63); }
        } else {
            tmp[t++] = (c < 0x100) ? (char)c : '?';
        }
        if (slen) { if (n + t > slen) return 0; memcpy(s + n, tmp, t); }
        n += t;
    }
    return n;
}
