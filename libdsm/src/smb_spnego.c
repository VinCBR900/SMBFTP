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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "bdsm_debug.h"
#include "smb_session.h"
#include "smb_session_msg.h"
#include "smb_message.h"
#include "smb_ntlm.h"

/*
 * TCC port: this file used to build and parse its SPNEGO tokens with libtasn1
 * (a generic ASN.1 library, plus a generated spnego_asn1.c table). libdsm only
 * ever needs two fixed token shapes, so they are now written and read directly
 * as DER, which removes libtasn1 and its asn1Parser build step completely.
 *
 * Sent in SESSION_SETUP #1 (NegTokenInit, wrapped as a GSSAPI context token):
 *
 *   60 len                        [APPLICATION 0]
 *     06 06 <1.3.6.1.5.5.2>         thisMech = SPNEGO
 *     A0 len                        [0] negTokenInit
 *       30 len                        NegTokenInit
 *         A0 len                        [0] mechTypes
 *           30 len                        SEQUENCE OF MechType
 *             06 0A <1.3.6.1.4.1.311.2.2.10>   NTLMSSP
 *         A2 len                        [2] mechToken
 *           04 len <NTLMSSP NEGOTIATE message>
 *
 * Sent in SESSION_SETUP #2 (NegTokenResp):
 *
 *   A1 len                        [1] negTokenResp
 *     30 len                        NegTokenResp
 *       A2 len                        [2] responseToken
 *         04 len <NTLMSSP AUTHENTICATE message>
 *
 * Received in the reply to #1: a NegTokenResp; only its responseToken (the
 * NTLMSSP CHALLENGE message) is used, the other fields are skipped.
 */

/* complete TLVs: tag, length, OID content bytes */
static const uint8_t spnego_oid_tlv[]  = { 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 };
static const uint8_t ntlmssp_oid_tlv[] = { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
                                           0x37, 0x02, 0x02, 0x0A };

#define DER_MAX_LEN     0xFFFFu     /* largest length these writers encode */

/*
 * der_tlv_size - size of a DER element with the given content length
 * Inputs : n = content length (< 65536)
 * Outputs: bytes taken by tag + length field + content
 * Clobbers: none
 */
static size_t   der_tlv_size(size_t n)
{
    return 1 + (n < 0x80 ? 1 : (n < 0x100 ? 2 : 3)) + n;
}

/*
 * der_put_tl - write a DER tag and definite length
 * Inputs : p = output position, tag, n = content length (< 65536)
 * Outputs: position after the length field
 * Clobbers: the bytes written
 */
static uint8_t  *der_put_tl(uint8_t *p, uint8_t tag, size_t n)
{
    *p++ = tag;
    if (n < 0x80)
        *p++ = (uint8_t)n;
    else if (n < 0x100)
    {
        *p++ = 0x81;
        *p++ = (uint8_t)n;
    }
    else
    {
        *p++ = 0x82;
        *p++ = (uint8_t)(n >> 8);
        *p++ = (uint8_t)n;
    }
    return p;
}

/*
 * der_next - read the next DER element
 * Inputs : *pp = position, end = end of the enclosing data
 * Outputs: 0 on success with *tag, *val (content) and *len set and *pp moved
 *          past the element; -1 if the data is malformed or truncated.
 *          Only single-byte tags and definite lengths of up to 3 bytes are
 *          accepted; that is all SPNEGO uses.
 * Clobbers: *pp only on success
 */
static int      der_next(const uint8_t **pp, const uint8_t *end, uint8_t *tag,
                         const uint8_t **val, size_t *len)
{
    const uint8_t *p = *pp;
    size_t        n, nbytes, i;

    if (end - p < 2)
        return -1;
    *tag = *p++;
    if ((*tag & 0x1F) == 0x1F)          // multi-byte tag number
        return -1;
    n = *p++;
    if (n & 0x80)
    {
        nbytes = n & 0x7F;
        if (nbytes == 0 || nbytes > 3 || (size_t)(end - p) < nbytes)
            return -1;                  // indefinite or oversized length
        for (n = 0, i = 0; i < nbytes; i++)
            n = (n << 8) | *p++;
    }
    if ((size_t)(end - p) < n)
        return -1;
    *val = p;
    *len = n;
    *pp  = p + n;
    return 0;
}

/*
 * spnego_wrap_init - build the GSSAPI/SPNEGO NegTokenInit offering NTLMSSP
 * Inputs : tok/toklen = NTLMSSP NEGOTIATE message
 * Outputs: malloc'ed DER in *out, its size in *outlen; 0 on success, -1 on
 *          failure (*out is then NULL). The caller frees *out
 * Clobbers: *out, *outlen
 */
static int      spnego_wrap_init(const uint8_t *tok, size_t toklen,
                                 uint8_t **out, size_t *outlen)
{
    size_t  sz_seqof, sz_a0_mt, sz_oct, sz_a2, sz_init, sz_a0_neg, body, total;
    uint8_t *buf, *p;

    *out = NULL;
    if (toklen > 0x4000)
        return -1;
    sz_seqof  = der_tlv_size(sizeof(ntlmssp_oid_tlv));
    sz_a0_mt  = der_tlv_size(sz_seqof);
    sz_oct    = der_tlv_size(toklen);
    sz_a2     = der_tlv_size(sz_oct);
    sz_init   = der_tlv_size(sz_a0_mt + sz_a2);
    sz_a0_neg = der_tlv_size(sz_init);
    body      = sizeof(spnego_oid_tlv) + sz_a0_neg;
    total     = der_tlv_size(body);

    if ((buf = malloc(total)) == NULL)
        return -1;
    p = der_put_tl(buf, 0x60, body);
    memcpy(p, spnego_oid_tlv, sizeof(spnego_oid_tlv));
    p += sizeof(spnego_oid_tlv);
    p = der_put_tl(p, 0xA0, sz_init);
    p = der_put_tl(p, 0x30, sz_a0_mt + sz_a2);
    p = der_put_tl(p, 0xA0, sz_seqof);
    p = der_put_tl(p, 0x30, sizeof(ntlmssp_oid_tlv));
    memcpy(p, ntlmssp_oid_tlv, sizeof(ntlmssp_oid_tlv));
    p += sizeof(ntlmssp_oid_tlv);
    p = der_put_tl(p, 0xA2, sz_oct);
    p = der_put_tl(p, 0x04, toklen);
    memcpy(p, tok, toklen);
    p += toklen;
    assert((size_t)(p - buf) == total);

    *out    = buf;
    *outlen = total;
    return 0;
}

/*
 * spnego_wrap_resp - build a SPNEGO NegTokenResp carrying one NTLMSSP message
 * Inputs : tok/toklen = NTLMSSP AUTHENTICATE message
 * Outputs: malloc'ed DER in *out, its size in *outlen; 0 on success, -1 on
 *          failure (*out is then NULL). The caller frees *out
 * Clobbers: *out, *outlen
 */
static int      spnego_wrap_resp(const uint8_t *tok, size_t toklen,
                                 uint8_t **out, size_t *outlen)
{
    size_t  sz_oct, sz_a2, sz_seq, total;
    uint8_t *buf, *p;

    *out = NULL;
    if (toklen > 0x4000)
        return -1;
    sz_oct = der_tlv_size(toklen);
    sz_a2  = der_tlv_size(sz_oct);
    sz_seq = der_tlv_size(sz_a2);
    total  = der_tlv_size(sz_seq);

    if ((buf = malloc(total)) == NULL)
        return -1;
    p = der_put_tl(buf, 0xA1, sz_seq);
    p = der_put_tl(p, 0x30, sz_a2);
    p = der_put_tl(p, 0xA2, sz_oct);
    p = der_put_tl(p, 0x04, toklen);
    memcpy(p, tok, toklen);
    p += toklen;
    assert((size_t)(p - buf) == total);

    *out    = buf;
    *outlen = total;
    return 0;
}

/*
 * spnego_unwrap_resp - find the responseToken in a received NegTokenResp
 * Inputs : blob/blen = the server's SPNEGO blob
 * Outputs: 0 and *tok/*toklen pointing into blob, or -1 if blob is not a
 *          well-formed NegTokenResp with a responseToken. negResult,
 *          supportedMech and mechListMIC are skipped (the old code did not
 *          check them either)
 * Clobbers: *tok, *toklen only on success
 */
static int      spnego_unwrap_resp(const uint8_t *blob, size_t blen,
                                   const uint8_t **tok, size_t *toklen)
{
    const uint8_t *p = blob, *end = blob + blen;
    const uint8_t *v, *seq, *seq_end, *q, *oct;
    size_t        l, seq_len, octl;
    uint8_t       tag;

    if (der_next(&p, end, &tag, &v, &l) != 0 || tag != 0xA1)    // [1] negTokenResp
        return -1;
    p = v;
    end = v + l;
    if (der_next(&p, end, &tag, &seq, &seq_len) != 0 || tag != 0x30)
        return -1;
    seq_end = seq + seq_len;
    for (p = seq; p < seq_end; )
    {
        if (der_next(&p, seq_end, &tag, &v, &l) != 0)
            return -1;
        if (tag != 0xA2)                                        // not [2] responseToken
            continue;
        q = v;
        if (der_next(&q, v + l, &tag, &oct, &octl) != 0 || tag != 0x04)
            return -1;
        *tok    = oct;
        *toklen = octl;
        return 0;
    }
    return -1;
}

static int      negotiate(smb_session *s, const char *domain)
{
    smb_message           *msg = NULL;
    smb_session_xsec_req  req;
    smb_buffer            ntlm;
    uint8_t               *der = NULL;
    size_t                der_size = 0;
    int                   res;

    msg = smb_message_new(SMB_CMD_SETUP);
    if (!msg)
        return DSM_ERROR_GENERIC;

    // this struct will be set at the end when we know the payload size
    SMB_MSG_ADVANCE_PKT(msg, smb_session_xsec_req);

    smb_ntlmssp_negotiate(domain, domain, &ntlm);
    if (ntlm.data == NULL)
    {
        smb_message_destroy(msg);
        return DSM_ERROR_GENERIC;
    }
    res = spnego_wrap_init(ntlm.data, ntlm.size, &der, &der_size);
    smb_buffer_free(&ntlm);
    if (res != 0)
    {
        BDSM_dbg("smb_session_login negotiate(): SPNEGO encoding error\n");
        smb_message_destroy(msg);
        return DSM_ERROR_GENERIC;
    }

    smb_message_append(msg, der, der_size);
    free(der);
    smb_message_put_utf16(msg, SMB_OS, strlen(SMB_OS));
    smb_message_put16(msg, 0);
    smb_message_put_utf16(msg, SMB_LANMAN, strlen(SMB_LANMAN));
    smb_message_put16(msg, 0);
    smb_message_put16(msg, 0);

    SMB_MSG_INIT_PKT_ANDX(req);
    req.wct              = 12;
    req.max_buffer       = SMB_SESSION_MAX_BUFFER;
    req.mpx_count        = 16;
    req.vc_count         = 1;
    req.caps             = s->srv.caps;
    req.session_key      = s->srv.session_key;
    req.xsec_blob_size = der_size;
    req.payload_size   = msg->cursor - sizeof(smb_session_xsec_req);
    SMB_MSG_INSERT_PKT(msg, 0, req);

    if (!smb_session_send_msg(s, msg))
    {
        smb_message_destroy(msg);
        BDSM_dbg("Unable to send Session Setup AndX (NTLMSSP_NEGOTIATE) message\n");
        return DSM_ERROR_NETWORK;
    }

    smb_message_destroy(msg);
    return DSM_SUCCESS;
}

static int      challenge(smb_session *s)
{
    smb_message           msg;
    smb_session_xsec_resp *resp;
    smb_ntlmssp_challenge *challenge;
    const uint8_t         *token;
    size_t                token_size, tgt_end;
    uint8_t               *copy;

    assert(s != NULL);

    if (smb_session_recv_msg(s, &msg) == 0)
    {
        BDSM_dbg("spnego challenge(): Unable to receive message\n");
        return DSM_ERROR_NETWORK;
    }

    if (msg.packet->header.status != NT_STATUS_MORE_PROCESSING_REQUIRED)
    {
        BDSM_dbg("spnego challenge(): Bad status (0x%x)\n",
                 msg.packet->header.status);
        return DSM_ERROR_GENERIC;
    }

    if (msg.payload_size < sizeof(smb_session_xsec_resp))
    {
        BDSM_dbg("[smb_tree_disconnect]Malformed message\n");
        return DSM_ERROR_NETWORK;
    }

    resp = (smb_session_xsec_resp *)msg.packet->payload;

    if (msg.payload_size - sizeof(smb_session_xsec_resp) < resp->xsec_blob_size)
    {
        BDSM_dbg("spnego challenge(): SPNEGO blob exceeds the message\n");
        return DSM_ERROR_NETWORK;
    }

    // XXX Check the value of "negTokenResp.negResult"
    if (spnego_unwrap_resp(resp->payload, resp->xsec_blob_size,
                           &token, &token_size) != 0)
    {
        BDSM_dbg("NegTokenResp parsing error\n");
        return DSM_ERROR_GENERIC;
    }

    // The NTLMSSP CHALLENGE message must hold its fixed part, and the target
    // info it points at must lie inside it (the old code did not check this)
    if (token_size < sizeof(smb_ntlmssp_challenge))
    {
        BDSM_dbg("spnego challenge(): NTLMSSP challenge too short\n");
        return DSM_ERROR_GENERIC;
    }
    // copy: the token inside the received message is not suitably aligned
    if ((copy = malloc(token_size)) == NULL)
        return DSM_ERROR_GENERIC;
    memcpy(copy, token, token_size);
    challenge = (smb_ntlmssp_challenge *)copy;

    tgt_end = (size_t)challenge->tgt_offset + challenge->tgt_len;
    if (challenge->tgt_offset < sizeof(smb_ntlmssp_challenge) || tgt_end > token_size)
    {
        BDSM_dbg("spnego challenge(): target info outside the NTLMSSP challenge\n");
        free(copy);
        return DSM_ERROR_GENERIC;
    }

    // We got the server challenge, yeaaah.
    if (smb_buffer_alloc(&s->xsec_target, challenge->tgt_len) == 0)
    {
        free(copy);
        return DSM_ERROR_GENERIC;
    }
    memcpy(s->xsec_target.data,
           challenge->data + challenge->tgt_offset - sizeof(smb_ntlmssp_challenge),
           s->xsec_target.size);
    s->srv.challenge = challenge->challenge;
    s->srv.uid       = msg.packet->header.uid;
    free(copy);

    BDSM_dbg("Server challenge is 0x%"PRIx64"\n", s->srv.challenge);

    return DSM_SUCCESS;
}

static int      auth(smb_session *s, const char *domain, const char *user,
                     const char *password)
{
    smb_message           *msg = NULL, resp;
    smb_session_xsec_req  req;
    smb_buffer            ntlm;
    uint8_t               *der = NULL;
    size_t                der_size = 0;
    int                   res;

    msg = smb_message_new(SMB_CMD_SETUP);
    if (!msg)
        return DSM_ERROR_GENERIC;

    // this struct will be set at the end when we know the payload size
    SMB_MSG_ADVANCE_PKT(msg, smb_session_xsec_req);

    smb_ntlmssp_response(s->srv.challenge, s->srv.ts - 4200, domain, domain, user,
                         password, &s->xsec_target, &ntlm);
    if (ntlm.data == NULL)
    {
        smb_message_destroy(msg);
        return DSM_ERROR_GENERIC;
    }
    // NegTokenResp with only the 'responseToken' field present
    res = spnego_wrap_resp(ntlm.data, ntlm.size, &der, &der_size);
    smb_buffer_free(&ntlm);
    if (res != 0)
    {
        BDSM_dbg("smb_session_login auth(): SPNEGO encoding error\n");
        smb_message_destroy(msg);
        return DSM_ERROR_GENERIC;
    }

    smb_message_append(msg, der, der_size);
    free(der);
    if (msg->cursor % 2)
        smb_message_put8(msg, 0);
    smb_message_put_utf16(msg, SMB_OS, strlen(SMB_OS));
    smb_message_put16(msg, 0);
    smb_message_put_utf16(msg, SMB_LANMAN, strlen(SMB_LANMAN));
    smb_message_put16(msg, 0);
    smb_message_put16(msg, 0); // Empty PDC name

    SMB_MSG_INIT_PKT_ANDX(req);
    req.wct              = 12;
    req.max_buffer       = SMB_SESSION_MAX_BUFFER;
    req.mpx_count        = 16; // XXX ?
    req.vc_count         = 1;
    req.caps             = s->srv.caps; // XXX caps & our_caps_mask
    req.session_key      = s->srv.session_key;
    req.xsec_blob_size = der_size;
    req.payload_size   = msg->cursor - sizeof(smb_session_xsec_req);
    SMB_MSG_INSERT_PKT(msg, 0, req);

    if (!smb_session_send_msg(s, msg))
    {
        smb_message_destroy(msg);
        BDSM_dbg("Unable to send Session Setup AndX (NTLMSSP_AUTH) message\n");
        return DSM_ERROR_NETWORK;
    }
    smb_message_destroy(msg);

    if (smb_session_recv_msg(s, &resp) == 0)
        return DSM_ERROR_NETWORK;

    if (!smb_session_check_nt_status(s, &resp))
        return DSM_ERROR_NT;

    if (resp.payload_size < sizeof(smb_session_xsec_resp))
    {
        BDSM_dbg("[smb_tree_disconnect]Malformed message\n");
        return DSM_ERROR_NETWORK;
    }

    smb_session_xsec_resp *r = (smb_session_xsec_resp *)resp.packet->payload;
    if (r->action & 0x0001)
        s->guest = true;

    s->srv.uid  = resp.packet->header.uid;
    s->logged = true;

    return DSM_SUCCESS;
}

int             smb_session_login_spnego(smb_session *s, const char *domain,
        const char *user, const char *password)
{
    int           res;
    assert(s != NULL && domain != NULL && user != NULL && password != NULL);

    // Clear User ID that might exists from previous authentication attempt
    s->srv.uid = 0;

    if ((res = negotiate(s, domain)) != DSM_SUCCESS)
        goto error;
    if ((res = challenge(s)) != DSM_SUCCESS)
        goto error;

    return auth(s, domain, user, password);

error:
    BDSM_dbg("login_spnego Interrupted\n");
    return res;
}
