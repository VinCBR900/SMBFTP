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

/*
 * smb_trans2.c - TRANS2 requests: directory listing (FIND_FIRST2 / FIND_NEXT2)
 *                and path query
 *
 * smbftp port, v0.6 rewrite of the receive and parse side (see libdsm-v0.6-fixes.diff):
 *   - every TRANS2 reply is validated against its real length (status, command, word
 *     count, parameter/data offsets and counts); fragments are placed by displacement
 *   - find entries are bounds-checked; a name that cannot be converted becomes "?"
 *     instead of ending the listing; a wrong entry stride (impacket pads FIND_FIRST
 *     entries but not FIND_NEXT ones) is recovered and flagged
 *   - a failing FIND_NEXT keeps the entries already read and flags the listing incomplete
 *   - FIND_NEXT sends the last file name and FileIndex of the previous reply
 *   - smb_session_get_find_flags() tells the caller what happened (SMB_FIND_*)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "bdsm_debug.h"
#include "smb_message.h"
#include "smb_session.h"
#include "smb_session_msg.h"
#include "smb_utils.h"
#include "smb_stat.h"

#define SMB_TR2_MAX_FRAGMENTS     64        /* messages making up one TRANS2 reply   */
#define SMB_FIND_MAX_ROUNDS       200000    /* FIND_NEXT requests for one listing    */
#define SMB_FIND_MAX_ENTRIES      1000000   /* entries kept for one listing          */
#define SMB_FIND_ENTRY_FIXED      94        /* bytes before the name in a BOTH_DIRECTORY_INFO entry */
#define SMB_FIND_MAX_NAME_BYTES   1024      /* sanity limit for one UTF-16 name      */
#define SMB_STATUS_NO_MORE_FILES  0x80000006u

/* A reassembled TRANS2 reply */
typedef struct
{
    uint8_t   *params;      /* malloc'ed, param_len bytes (never NULL when param_len > 0) */
    size_t    param_len;
    uint8_t   *data;        /* malloc'ed, data_len bytes (never NULL when data_len > 0)   */
    size_t    data_len;
} tr2_reply;

/* State of one listing being collected */
typedef struct
{
    smb_file  *head, *tail; /* entries in server order                                    */
    size_t    total;        /* entries in the list                                        */
    uint32_t  last_index;   /* FileIndex of the last entry parsed                         */
    uint8_t   *last_name;   /* malloc'ed raw UTF-16LE name of the last entry              */
    size_t    last_name_len;
} find_state;

/*
 * rd16 / rd32 / rd64 - little-endian loads from unaligned wire data
 * Inputs : p = pointer to at least 2 / 4 / 8 readable bytes
 * Outputs: the value
 * Clobbers: none
 */
static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((unsigned)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/*
 * tr2_reply_free - release a reassembled reply
 * Inputs : r = reply (may be all zero)
 * Outputs: none
 * Clobbers: *r (zeroed)
 */
static void tr2_reply_free(tr2_reply *r)
{
    free(r->params);
    free(r->data);
    memset(r, 0, sizeof(*r));
}

/*
 * Receive trans2 management
 */

/*
 * smb_tr2_recv - receive one complete TRANS2 reply (all fragments) and validate it
 * Inputs : s = session with a TRANS2 request outstanding, out = result
 * Outputs: DSM_SUCCESS with *out filled (parameters and data copied out of the session
 *          buffer, so later receives cannot overwrite them); DSM_ERROR_NT if the server
 *          returned an error status (session nt_status set); DSM_ERROR_NETWORK if the
 *          connection failed or the reply is malformed. *out is empty on failure.
 * Clobbers: the session receive buffer, s->nt_status
 */
static int smb_tr2_recv(smb_session *s, tr2_reply *out)
{
    smb_message     m;
    const uint8_t   *base, *pl, *w;
    size_t          psz, msg_len, hdr_end, got_p = 0, got_d = 0;
    unsigned        wct, frags = 0, first = 1;
    uint16_t        tpc, tdc, pc, po, pd, dc, dofs, dd;

    memset(out, 0, sizeof(*out));
    for (;;)
    {
        if (++frags > SMB_TR2_MAX_FRAGMENTS)
            goto malformed;

        psz = smb_session_recv_msg(s, &m);
        if (psz == 0)
        {
            tr2_reply_free(out);
            return DSM_ERROR_NETWORK;
        }
        if (!smb_session_check_nt_status(s, &m))
        {
            tr2_reply_free(out);
            return DSM_ERROR_NT;
        }
        if (m.packet->header.command != SMB_CMD_TRANS2)
            goto malformed;

        base    = (const uint8_t *)m.packet;
        pl      = m.packet->payload;
        msg_len = sizeof(smb_header) + psz;
        if (psz < 1)
            goto malformed;
        wct = pl[0];
        if (wct < 10 || psz < 1 + (size_t)wct * 2 + 2)
            goto malformed;
        hdr_end = sizeof(smb_header) + 1 + (size_t)wct * 2 + 2;
        w       = pl + 1;
        tpc     = rd16(w + 0);
        tdc     = rd16(w + 2);
        pc      = rd16(w + 6);
        po      = rd16(w + 8);
        pd      = rd16(w + 10);
        dc      = rd16(w + 12);
        dofs    = rd16(w + 14);
        dd      = rd16(w + 16);

        if (pc && ((size_t)po < hdr_end || (size_t)po + pc > msg_len))
            goto malformed;
        if (dc && ((size_t)dofs < hdr_end || (size_t)dofs + dc > msg_len))
            goto malformed;

        if (first)
        {
            out->params = (uint8_t *)malloc(tpc ? tpc : 1);
            out->data   = (uint8_t *)malloc(tdc ? tdc : 1);
            if (out->params == NULL || out->data == NULL)
            {
                tr2_reply_free(out);
                return DSM_ERROR_GENERIC;
            }
            out->param_len = tpc;
            out->data_len  = tdc;
            first = 0;
        }
        else
        {
            /* a later fragment may only shrink the announced totals */
            if (tpc > out->param_len || tdc > out->data_len)
                goto malformed;
            out->param_len = tpc;
            out->data_len  = tdc;
        }

        if ((size_t)pd + pc > out->param_len || (size_t)dd + dc > out->data_len)
            goto malformed;
        if (pc)
            memcpy(out->params + pd, base + po, pc);
        if (dc)
            memcpy(out->data + dd, base + dofs, dc);
        got_p += pc;
        got_d += dc;

        if (got_p >= out->param_len && got_d >= out->data_len)
            return DSM_SUCCESS;
        if (pc == 0 && dc == 0)         /* no progress: do not wait for ever */
            goto malformed;
    }

malformed:
    BDSM_dbg("[smb_tr2_recv]Malformed TRANS2 reply\n");
    tr2_reply_free(out);
    return DSM_ERROR_NETWORK;
}

/*
 * Find management
 */

/*
 * find_state_free - release a listing in progress
 * Inputs : st = state
 * Outputs: none
 * Clobbers: *st (zeroed), frees the list and the saved name
 */
static void find_state_free(find_state *st)
{
    smb_stat_list_destroy(st->head);
    free(st->last_name);
    memset(st, 0, sizeof(*st));
}

/*
 * find_entry_plausible - does a valid BOTH_DIRECTORY_INFO entry start at data+off?
 * Inputs : data/len = reply data, off = candidate offset, strict = 1 also requires
 *          NextEntryOffset to stay inside the data (used to accept a jump to the
 *          entry the server says follows); 0 only requires it to be 0 or to cover
 *          the entry (used for the entry being parsed: impacket declares a stride
 *          of 128 even for the last entry of a reply, which does not fit)
 * Outputs: 1 if the fixed part fits, the name length is even, non-zero, sane and fits,
 *          and NextEntryOffset is acceptable as described above
 * Clobbers: none
 */
static int find_entry_plausible(const uint8_t *data, size_t len, size_t off, int strict)
{
    uint32_t nxt, nl;

    if (off >= len || len - off < SMB_FIND_ENTRY_FIXED)
        return 0;
    nxt = rd32(data + off);
    nl  = rd32(data + off + 60);
    if (nl == 0 || (nl & 1) || nl > SMB_FIND_MAX_NAME_BYTES ||
        nl > len - off - SMB_FIND_ENTRY_FIXED)
        return 0;
    if (nxt != 0 && nxt < SMB_FIND_ENTRY_FIXED + nl)
        return 0;
    if (strict && nxt != 0 && nxt > len - off)
        return 0;
    return 1;
}

/*
 * find_parse_entries - turn the data part of a find reply into smb_file records
 * Inputs : s = session (flags are set here), data/len = reply data, count = entry count
 *          announced by the server, st = listing state (entries are appended)
 * Outputs: number of entries appended. Sets SMB_FIND_INCOMPLETE on s when entries are
 *          missing or malformed, SMB_FIND_RESYNCED when the entry stride had to be recovered.
 *          Entries are followed by the server's NextEntryOffset when that leads to a valid
 *          entry, else by the entry that follows directly. The data is complete when it
 *          ends cleanly after the last entry: a count one higher than the entries present
 *          is accepted when the stride had to be recovered (impacket counts FIND_NEXT
 *          replies that way); any other shortfall is INCOMPLETE.
 * Clobbers: s->find_flags, *st
 */
static size_t find_parse_entries(smb_session *s, const uint8_t *data, size_t len,
                                 unsigned count, find_state *st)
{
    size_t      off = 0, added = 0, next_off, cont;
    uint32_t    nxt, nl;
    smb_file    *f;
    const uint8_t *e;
    int         resynced = 0, bad = 0, done = 0;

    while (added < count && !done)
    {
        if (!find_entry_plausible(data, len, off, 0) || st->total >= SMB_FIND_MAX_ENTRIES)
        {
            bad = 1;
            break;
        }
        e   = data + off;
        nxt = rd32(e);
        nl  = rd32(e + 60);

        f = (smb_file *)calloc(1, sizeof(smb_file));
        if (f == NULL)
        {
            bad = 1;
            break;
        }
        f->name_len = smb_from_utf16((const char *)(e + SMB_FIND_ENTRY_FIXED), nl, &f->name);
        if (f->name_len == 0 || f->name == NULL)
        {
            /* cannot be converted at all: show a placeholder, keep the listing going */
            free(f->name);
            f->name = (char *)malloc(2);
            if (f->name == NULL)
            {
                free(f);
                bad = 1;
                break;
            }
            f->name[0]  = '?';
            f->name[1]  = '\0';
            f->name_len = 1;
        }
        f->created    = rd64(e + 8);
        f->accessed   = rd64(e + 16);
        f->written    = rd64(e + 24);
        f->changed    = rd64(e + 32);
        f->size       = rd64(e + 40);
        f->alloc_size = rd64(e + 48);
        f->attr       = rd32(e + 56);
        f->is_dir     = (f->attr & SMB_ATTR_DIR) ? 1 : 0;

        if (st->tail != NULL)
            st->tail->next = f;
        else
            st->head = f;
        st->tail = f;
        st->total++;
        added++;

        /* remember the last entry: FIND_NEXT must send its name and index */
        st->last_index = rd32(e + 4);
        {
            uint8_t *copy = (uint8_t *)malloc(nl);
            if (copy != NULL)
            {
                memcpy(copy, e + SMB_FIND_ENTRY_FIXED, nl);
                free(st->last_name);
                st->last_name     = copy;
                st->last_name_len = nl;
            }
        }

        /* where is the next entry? */
        cont = off + SMB_FIND_ENTRY_FIXED + nl;         /* directly after this one */
        if (nxt == 0)
        {
            done = 1;
            off  = cont;
        }
        else if (find_entry_plausible(data, len, next_off = off + nxt, 1))
        {
            off = next_off;
        }
        else if (find_entry_plausible(data, len, cont, 0))
        {
            /* impacket declares entries padded to 8 bytes in FIND_NEXT replies but
             * sends them without the padding: take the entry that follows directly */
            off = cont;
            resynced = 1;
        }
        else
        {
            done = 1;
            off  = cont;
        }
    }

    if (resynced)
        s->find_flags |= SMB_FIND_RESYNCED;
    if (bad)
        s->find_flags |= SMB_FIND_INCOMPLETE;
    else if (added < count)
    {
        /* the entries ended before the announced count: only the impacket
         * off-by-one with a clean end of the data is accepted */
        if (!(resynced && count - added == 1 && len - off < SMB_FIND_ENTRY_FIXED))
            s->find_flags |= SMB_FIND_INCOMPLETE;
    }
    return added;
}

/*
 * smb_trans2_find_request - build, send and receive one FIND_FIRST2 or FIND_NEXT2
 * Inputs : s/tid = session and tree, first = 1 for FIND_FIRST2 (pattern is the search
 *          pattern), 0 for FIND_NEXT2 (sid, resume_key and name/name_len = the last
 *          entry's raw UTF-16LE name from the previous reply are sent)
 *          pattern = local-charset pattern (FIND_FIRST2 only), out = reply
 * Outputs: DSM_SUCCESS with the reply in *out, or the smb_tr2_recv / send error code
 * Clobbers: the session buffers, s->nt_status
 */
static int smb_trans2_find_request(smb_session *s, smb_tid tid, int first,
                                   const char *pattern, uint16_t sid, uint32_t resume_key,
                                   const uint8_t *name, size_t name_len, tr2_reply *out)
{
    smb_message           *msg;
    smb_trans2_req        tr2;
    smb_tr2_findfirst2    ff;
    smb_tr2_findnext2     fn;
    size_t                utf_len, tr2_bct, tr2_param_count;
    char                  *utf = NULL;
    unsigned int          padding = 0;
    int                   ok = 1, res;

    assert(s != NULL);

    memset(out, 0, sizeof(*out));
    if (first)
    {
        assert(pattern != NULL);
        utf_len = smb_to_utf16(pattern, strlen(pattern) + 1, &utf);
        if (utf_len == 0)
            return DSM_ERROR_CHARSET;
    }
    else
    {
        /* the wire name plus a UTF-16 terminator */
        utf_len = name_len + 2;
        utf     = (char *)calloc(1, utf_len);
        if (utf == NULL)
            return DSM_ERROR_GENERIC;
        if (name_len)
            memcpy(utf, name, name_len);
    }

    tr2_bct = (first ? sizeof(smb_tr2_findfirst2) : sizeof(smb_tr2_findnext2)) + utf_len;
    tr2_param_count = tr2_bct;
    tr2_bct += 3;
    // Adds padding at the end if necessary.
    while ((tr2_bct % 4) != 3)
    {
        padding++;
        tr2_bct++;
    }

    msg = smb_message_new(SMB_CMD_TRANS2);
    if (!msg)
    {
        free(utf);
        return DSM_ERROR_GENERIC;
    }
    msg->packet->header.tid = tid;

    SMB_MSG_INIT_PKT(tr2);
    tr2.wct               = 15;
    tr2.total_param_count = tr2_param_count;
    tr2.max_param_count   = 10;
    tr2.max_data_count    = 0xffff;
    tr2.param_count       = tr2_param_count;
    tr2.param_offset      = 68;                                   // find params follow the 3 pad bytes
    tr2.data_count        = 0;
    tr2.data_offset       = (uint16_t)(68 + tr2_param_count + padding); // no data: end of message
    tr2.setup_count       = 1;
    tr2.cmd               = first ? SMB_TR2_FIND_FIRST : SMB_TR2_FIND_NEXT;
    tr2.bct               = tr2_bct;                              // 3 pad + params + trailing pad
    ok &= SMB_MSG_PUT_PKT(msg, tr2) > 0;

    if (first)
    {
        SMB_MSG_INIT_PKT(ff);
        ff.attrs    = SMB_FIND2_ATTR_DEFAULT;
        ff.count    = 1366;     // entries asked for; the server returns what fits
        ff.flags    = SMB_FIND2_FLAG_CLOSE_EOS | SMB_FIND2_FLAG_RESUME;
        ff.interest = SMB_FIND2_INTEREST_BOTH_DIRECTORY_INFO;
        ok &= SMB_MSG_PUT_PKT(msg, ff) > 0;
    }
    else
    {
        SMB_MSG_INIT_PKT(fn);
        fn.sid        = sid;
        fn.count      = 255;
        fn.interest   = SMB_FIND2_INTEREST_BOTH_DIRECTORY_INFO;
        fn.resume_key = resume_key;
        fn.flags      = SMB_FIND2_FLAG_CLOSE_EOS | SMB_FIND2_FLAG_CONTINUE;
        ok &= SMB_MSG_PUT_PKT(msg, fn) > 0;
    }
    ok &= smb_message_append(msg, utf, utf_len) > 0;
    while (padding--)
        ok &= smb_message_put8(msg, 0) > 0;
    free(utf);

    if (!ok)
    {
        smb_message_destroy(msg);
        return DSM_ERROR_GENERIC;
    }
    res = smb_session_send_msg(s, msg);
    smb_message_destroy(msg);
    if (!res)
    {
        BDSM_dbg("Unable to send FIND request\n");
        return DSM_ERROR_NETWORK;
    }
    return smb_tr2_recv(s, out);
}

/*
 * smb_find - list the files matching a pattern
 * Inputs : s = logged-in session, tid = tree id, pattern = e.g. "\dir\*" (local charset)
 * Outputs: list of smb_file records in server order, or NULL if nothing could be read
 *          (nt_status holds the server's error, or find_flags has SMB_FIND_INCOMPLETE
 *          for a network failure or malformed first reply; neither set = no match).
 *          Entries read before a later failure are returned and SMB_FIND_INCOMPLETE is
 *          set on the session.
 * Clobbers: s->find_flags (reset on entry), s->nt_status, the session buffers
 */
smb_file  *smb_find(smb_session *s, smb_tid tid, const char *pattern)
{
    find_state        st;
    tr2_reply         rp;
    uint16_t          sid, eos;
    unsigned          count, rounds = 0;
    size_t            got;
    int               rc;

    assert(s != NULL && pattern != NULL);

    memset(&st, 0, sizeof(st));
    s->find_flags = 0;

    // Send FIND_FIRST request
    rc = smb_trans2_find_request(s, tid, 1, pattern, 0, 0, NULL, 0, &rp);
    if (rc != DSM_SUCCESS)
    {
        BDSM_dbg("Error during FIND_FIRST request/reply\n");
        if (rc != DSM_ERROR_NT)
            s->find_flags |= SMB_FIND_INCOMPLETE;
        return NULL;
    }
    if (rp.param_len < 10)
    {
        BDSM_dbg("FIND_FIRST reply too short\n");
        s->find_flags |= SMB_FIND_INCOMPLETE;
        tr2_reply_free(&rp);
        return NULL;
    }
    sid   = rd16(rp.params);
    count = rd16(rp.params + 2);
    eos   = rd16(rp.params + 4);
    got   = find_parse_entries(s, rp.data, rp.data_len, count, &st);
    tr2_reply_free(&rp);
    if (got == 0)
    {
        if (count != 0)
            s->find_flags |= SMB_FIND_INCOMPLETE;
        find_state_free(&st);
        return NULL;
    }

    // Send FIND_NEXT queries until the find is finished or until an error occurs;
    // what was read so far is always kept
    while (!eos)
    {
        if (++rounds > SMB_FIND_MAX_ROUNDS)
        {
            s->find_flags |= SMB_FIND_INCOMPLETE;
            break;
        }
        rc = smb_trans2_find_request(s, tid, 0, NULL, sid, st.last_index,
                                     st.last_name, st.last_name_len, &rp);
        if (rc != DSM_SUCCESS)
        {
            if (rc == DSM_ERROR_NT && s->nt_status == SMB_STATUS_NO_MORE_FILES)
            {
                s->nt_status = 0;               // normal end of the search
                break;
            }
            BDSM_dbg("Error during FIND_NEXT request/reply\n");
            s->find_flags |= SMB_FIND_INCOMPLETE;
            break;
        }
        if (rp.param_len < 8)
        {
            BDSM_dbg("FIND_NEXT reply too short\n");
            s->find_flags |= SMB_FIND_INCOMPLETE;
            tr2_reply_free(&rp);
            break;
        }
        count = rd16(rp.params);
        eos   = rd16(rp.params + 2);
        got   = find_parse_entries(s, rp.data, rp.data_len, count, &st);
        tr2_reply_free(&rp);
        if (got == 0 && !eos)
        {
            BDSM_dbg("FIND_NEXT returned no entries but not end of search\n");
            s->find_flags |= SMB_FIND_INCOMPLETE;
            break;
        }
    }

    free(st.last_name);
    return st.head;
}

/*
 * Query management
 */

smb_file  *smb_fstat(smb_session *s, smb_tid tid, const char *path)
{
    smb_message           *msg, reply;
    smb_trans2_req        tr2;
    smb_trans2_resp       *tr2_resp;
    smb_tr2_query         query;
    smb_tr2_path_info     *info;
    smb_file              *file;
    size_t                utf_path_len, msg_len;
    char                  *utf_path;
    int                   res, padding = 0;

    assert(s != NULL && path != NULL);

    utf_path_len = smb_to_utf16(path, strlen(path) + 1, &utf_path);
    if (utf_path_len == 0)
        return 0;

    msg_len   = sizeof(smb_trans2_req) + sizeof(smb_tr2_query);
    msg_len  += utf_path_len;
    if (msg_len %4)
        padding = 4 - msg_len % 4;

    msg = smb_message_new(SMB_CMD_TRANS2);
    if (!msg) {
        free(utf_path);
        return 0;
    }
    msg->packet->header.tid = tid;

    SMB_MSG_INIT_PKT(tr2);
    tr2.wct                = 15;
    tr2.total_param_count  = utf_path_len + sizeof(smb_tr2_query);
    tr2.param_count        = tr2.total_param_count;
    tr2.max_param_count    = 2; // ?? Why not the same or 12 ?
    tr2.max_data_count     = 0xffff;
    tr2.param_offset       = 68; // Offset of find_first_params in packet;
    tr2.data_count         = 0;
    tr2.data_offset        = 96; // Offset of pattern in packet
    tr2.setup_count        = 1;
    tr2.cmd                = SMB_TR2_QUERY_PATH;
    tr2.bct                = sizeof(smb_tr2_query) + utf_path_len + padding;
    SMB_MSG_PUT_PKT(msg, tr2);

    SMB_MSG_INIT_PKT(query);
    query.interest   = SMB_FIND2_QUERY_FILE_ALL_INFO;
    SMB_MSG_PUT_PKT(msg, query);

    smb_message_append(msg, utf_path, utf_path_len);
    free(utf_path);

    // Adds padding at the end if necessary.
    while (padding--)
        smb_message_put8(msg, 0);

    res = smb_session_send_msg(s, msg);
    smb_message_destroy(msg);
    if (!res)
    {
        BDSM_dbg("Unable to query pattern: %s\n", path);
        return NULL;
    }

    if (!smb_session_recv_msg(s, &reply)
        || !smb_session_check_nt_status(s, &reply))
    {
        BDSM_dbg("Unable to recv msg or failure for %s\n", path);
        return NULL;
    }

    if (reply.payload_size < sizeof(smb_trans2_resp) + 4 + sizeof(smb_tr2_path_info))
    {
        BDSM_dbg("[smb_fstat]Malformed message %s\n", path);
        return NULL;
    }

    tr2_resp  = (smb_trans2_resp *)reply.packet->payload;
    info      = (smb_tr2_path_info *)(tr2_resp->payload + 4); //+4 is padding

    if (info->name_len > reply.payload_size ||
        info->name + info->name_len > reply.packet->payload + reply.payload_size)
    {
        BDSM_dbg("[smb_fstat]Malformed message %s\n", path);
        return NULL;
    }

    file      = calloc(1, sizeof(smb_file));
    if (!file)
        return NULL;

    file->name_len  = smb_from_utf16((const char *)info->name, info->name_len,
                                     &file->name);
    if (file->name_len == 0 || file->name == NULL)
    {
        free(file->name);
        free(file);
        return NULL;
    }

    file->created     = info->created;
    file->accessed    = info->accessed;
    file->written     = info->written;
    file->changed     = info->changed;
    file->alloc_size  = info->alloc_size;
    file->size        = info->size;
    file->attr        = info->attr;
    file->is_dir      = info->is_dir;

    return file;
}
