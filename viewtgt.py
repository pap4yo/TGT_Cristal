#!/usr/bin/env python3
"""
view_ticket.py  -  Visor de SOLO LECTURA de tickets Kerberos (.ccache).

Sin Impacket. Usa la key para descifrar el enc-part y mostrar su contenido.
NO modifica, NO re-firma, NO re-cifra: solo lee.

Cripto: pycryptodome (RC4/AES/MD4/MD5/SHA1/HMAC). ASN.1: parser DER propio.

Uso:
  python3 view_ticket.py ticket.ccache                 # solo parte en claro
  python3 view_ticket.py ticket.ccache -k <NThash>     # RC4 (etype 23)
  python3 view_ticket.py ticket.ccache -k <AESkey_hex> # AES (etype 17/18)

"""

import argparse
import binascii
import datetime
import struct
import sys

try:                                   # pycryptodome
    from Crypto.Cipher import ARC4, AES
    from Crypto.Hash import HMAC, MD5, SHA1
except ImportError:
    try:                               # pycryptodomex
        from Cryptodome.Cipher import ARC4, AES
        from Cryptodome.Hash import HMAC, MD5, SHA1
    except ImportError:
        sys.exit("[!] Falta pycryptodome. Instala con:\n"
                 "    pip install pycryptodome\n"
                 "  o usa el python del sistema:  /usr/bin/python3 "
                 + " ".join(sys.argv))

KEY_USAGE_ENC_TICKET_PART = 2


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def u8(self):
        v = self.d[self.i]; self.i += 1; return v

    def u16(self):
        v = struct.unpack_from("!H", self.d, self.i)[0]; self.i += 2; return v

    def u32(self):
        v = struct.unpack_from("!I", self.d, self.i)[0]; self.i += 4; return v

    def raw(self, n):
        v = self.d[self.i:self.i + n]; self.i += n; return v

    def cstr(self):
        n = self.u32(); return self.raw(n)

    def eof(self):
        return self.i >= len(self.d)


def parse_principal(r, version):
    name_type = r.u32()
    count = r.u32()
    if version == 0x0501:      # en 0x0501 el conteo incluye el realm
        count -= 1
    realm = r.cstr().decode("utf-8", "replace")
    comps = [r.cstr().decode("utf-8", "replace") for _ in range(count)]
    return {"name_type": name_type, "realm": realm, "components": comps,
            "str": "/".join(comps) + "@" + realm}


def parse_ccache(data):
    r = Reader(data)
    version = r.u16()
    if version in (0x0504,):
        hlen = r.u16()
        r.raw(hlen)            # cabeceras (offset de tiempo, etc.) -> ignorar
    default = parse_principal(r, version)

    creds = []
    while not r.eof():
        client = parse_principal(r, version)
        server = parse_principal(r, version)
        # keyblock
        keytype = r.u16()
        r.u16()                # etype (deprecado en el keyblock)
        keylen = r.u16()
        keyvalue = r.raw(keylen)
        authtime = r.u32(); starttime = r.u32()
        endtime = r.u32(); renew_till = r.u32()
        is_skey = r.u8()
        tktflags = r.u32()
        naddr = r.u32()
        for _ in range(naddr):
            r.u16(); r.cstr()
        nauth = r.u32()
        for _ in range(nauth):
            r.u16(); r.cstr()
        ticket = r.cstr()
        second = r.cstr()
        creds.append({
            "client": client, "server": server,
            "keytype": keytype, "keyvalue": keyvalue,
            "authtime": authtime, "starttime": starttime,
            "endtime": endtime, "renew_till": renew_till,
            "tktflags": tktflags, "ticket": ticket, "second": second,
        })
    return {"version": version, "default": default, "creds": creds}



def der_len(d, i):
    first = d[i]; i += 1
    if first < 0x80:
        return first, i
    nby = first & 0x7F
    val = int.from_bytes(d[i:i + nby], "big")
    return val, i + nby


def der_parse(d, i=0):
    """Devuelve (tag_byte, contenido_bytes, siguiente_indice)."""
    tag = d[i]; i += 1
    length, i = der_len(d, i)
    content = d[i:i + length]
    return tag, content, i + length


def der_children(content):
    out = []
    i = 0
    while i < len(content):
        tag, c, i = der_parse(content, i)
        out.append((tag, c))
    return out


def der_int(content):
    return int.from_bytes(content, "big")


def der_str(content):
    return content.decode("utf-8", "replace")


def unwrap_context(tag, content):
    """Un elemento [n] es constructed y envuelve un único valor interno."""
    inner_tag, inner_c, _ = der_parse(content, 0)
    return inner_tag, inner_c



def hmac_md5(key, data):
    return HMAC.new(key, data, MD5).digest()


def rc4_hmac_decrypt(key, usage, ct):
    """etype 23 (RFC 4757). key = NT hash (16 bytes)."""
    if usage in (3, 9):        # excepción de mapeo documentada
        usage = 8
    k1 = hmac_md5(key, struct.pack("<I", usage))
    checksum = ct[:16]
    k3 = hmac_md5(k1, checksum)
    dec = ARC4.new(k3).decrypt(ct[16:])
    if hmac_md5(k1, dec) != checksum:
        raise ValueError("checksum RC4 no coincide (key incorrecta?)")
    return dec[8:]             # quita el confounder de 8 bytes


def _nfold(data, nbytes):
    """n-fold (RFC 3961)."""
    inbits = len(data) * 8
    outbits = nbytes * 8
    # lcm
    a, b = inbits, outbits
    while b:
        a, b = b, a % b
    lcm = inbits * outbits // a
    reps = lcm // inbits
    big = bytearray(nbytes)
    buf = bytearray()
    for n in range(reps):
        rot = n * 13
        shifted = bytearray(len(data))
        for i in range(len(data)):
            src = (i * 8 - rot) % inbits
            byte = src // 8
            bit = src % 8
            v = ((data[byte] << bit) | (data[(byte + 1) % len(data)] >> (8 - bit))) & 0xFF
            shifted[i] = v
        buf += shifted

    out = bytearray(nbytes)
    carry = 0
    for pos in range(nbytes - 1, -1, -1):
        s = carry
        idx = pos
        while idx < len(buf):
            s += buf[idx]
            idx += nbytes
        out[pos] = s & 0xFF
        carry = s >> 8
    # propagar acarreo final
    i = nbytes - 1
    while carry and i >= 0:
        s = out[i] + carry
        out[i] = s & 0xFF
        carry = s >> 8
        i -= 1
    return bytes(out)


def _aes_dr(key, constant):
    bs = 16
    ki = _nfold(constant, bs)
    out = b""
    prev = ki
    ecb = AES.new(key, AES.MODE_ECB)
    while len(out) < len(key):
        prev = ecb.encrypt(prev)
        out += prev
    return out[:len(key)]


def _aes_dk(key, usage, kind):

    constant = struct.pack("!I", usage) + bytes([kind])
    return _aes_dr(key, constant)


def _aes_cts_decrypt(key, ct):
    """AES-CBC-CTS decrypt, IV=0 (RFC 3962)."""
    bs = 16
    ecb = AES.new(key, AES.MODE_ECB)

    def xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    n = len(ct)
    if n < bs:
        raise ValueError("ciphertext demasiado corto")
    if n == bs:
        return ecb.decrypt(ct)


    nblocks = (n + bs - 1) // bs
    rem = n - (nblocks - 1) * bs           # tamaño del último trozo (1..bs)

    blocks = [ct[i * bs:(i + 1) * bs] for i in range(nblocks - 2)]
    cn_1 = ct[(nblocks - 2) * bs:(nblocks - 1) * bs]   # penúltimo (completo)
    cn = ct[(nblocks - 1) * bs:]                        # último (rem bytes)

    prev = bytes(bs)                       # IV = 0
    plain = b""
    for blk in blocks:
        plain += xor(ecb.decrypt(blk), prev)
        prev = blk


    dn = ecb.decrypt(cn_1)                 # D(Cn-1)
    c = cn + dn[rem:]                       # completa Cn con la cola de D(Cn-1)
    pn = xor(dn[:rem], cn)                  # último bloque (parcial)
    pn_1 = xor(ecb.decrypt(c), prev)       # penúltimo
    plain += pn_1 + pn
    return plain


def aes_decrypt(key, usage, ct):
    """etype 17 (AES128) / 18 (AES256), CTS-HMAC-SHA1-96."""
    ke = _aes_dk(key, usage, 0xAA)
    ki = _aes_dk(key, usage, 0x55)
    enc, mac = ct[:-12], ct[-12:]
    plain = _aes_cts_decrypt(ke, enc)
    expect = HMAC.new(ki, plain, SHA1).digest()[:12]
    if expect != mac:
        raise ValueError("HMAC AES no coincide (key incorrecta?)")
    return plain[16:]          # quita el confounder (1 bloque)


def decrypt_enc_part(etype, key_bytes, cipher):
    if etype == 23:
        return rc4_hmac_decrypt(key_bytes, KEY_USAGE_ENC_TICKET_PART, cipher)
    if etype in (17, 18):
        return aes_decrypt(key_bytes, KEY_USAGE_ENC_TICKET_PART, cipher)
    raise ValueError(f"etype {etype} no soportado (solo 23, 17, 18)")



def parse_ticket(der):
    _, app, _ = der_parse(der, 0)          # [APPLICATION 1]
    inner_tag, inner_c, _ = der_parse(app, 0)   # SEQUENCE interno
    fields = {c[0]: c[1] for c in der_children(inner_c)}
    out = {}
    out["tkt_vno"] = der_int(unwrap_context(0xA0, fields[0xA0])[1])
    out["realm"] = der_str(unwrap_context(0xA1, fields[0xA1])[1])
    # sname
    _, sname_seq = unwrap_context(0xA2, fields[0xA2])
    out["sname"] = parse_principal_name(sname_seq)
    # enc-part (EncryptedData)
    _, enc = unwrap_context(0xA3, fields[0xA3])
    ef = {c[0]: c[1] for c in der_children(enc)}
    out["etype"] = der_int(unwrap_context(0xA0, ef[0xA0])[1])
    out["kvno"] = der_int(unwrap_context(0xA1, ef[0xA1])[1]) if 0xA1 in ef else None
    out["cipher"] = unwrap_context(0xA2, ef[0xA2])[1]
    return out


def parse_principal_name(seq_content):
    fields = {c[0]: c[1] for c in der_children(seq_content)}
    # [1] name-string SEQUENCE OF GeneralString
    comps = []
    if 0xA1 in fields:
        _, names, _ = der_parse(fields[0xA1], 0)  # SEQUENCE OF
        for tag, c in der_children(names):
            comps.append(der_str(c))
    return "/".join(comps)


def parse_enc_ticket_part(der):
    inner_tag, inner_c, _ = der_parse(der, 0)   # [APPLICATION 3] -> SEQUENCE
    seq_tag, seq_c, _ = der_parse(inner_c, 0)
    fields = {c[0]: c[1] for c in der_children(seq_c)}
    out = {}
    # [0] flags (BIT STRING)
    if 0xA0 in fields:
        _, bs, _ = der_parse(fields[0xA0], 0)
        out["flags"] = bs
    # [1] key
    if 0xA1 in fields:
        _, keyseq, _ = der_parse(fields[0xA1], 0)
        kf = {c[0]: c[1] for c in der_children(keyseq)}
        out["key_etype"] = der_int(unwrap_context(0xA0, kf[0xA0])[1])
        out["key_value"] = unwrap_context(0xA1, kf[0xA1])[1]
    # [2] crealm
    if 0xA2 in fields:
        out["crealm"] = der_str(unwrap_context(0xA2, fields[0xA2])[1])
    # [3] cname
    if 0xA3 in fields:
        _, cn, _ = der_parse(fields[0xA3], 0)
        out["cname"] = parse_principal_name(cn)
    # tiempos
    for tag, name in [(0xA5, "authtime"), (0xA6, "starttime"),
                      (0xA7, "endtime"), (0xA8, "renew_till")]:
        if tag in fields:
            out[name] = der_str(unwrap_context(tag, fields[tag])[1])
    # [10] authorization-data (guardamos el DER del SEQUENCE OF tal cual)
    if 0xAA in fields:
        out["authdata"] = fields[0xAA]
    return out



PAC_TYPES = {
    1: "LOGON_INFO", 2: "CREDENTIALS_INFO", 6: "SERVER_CHECKSUM",
    7: "KDC_CHECKSUM", 10: "CLIENT_INFO", 11: "DELEGATION_INFO",
    12: "UPN_DNS_INFO", 13: "CLIENT_CLAIMS", 14: "DEVICE_INFO",
    15: "DEVICE_CLAIMS", 16: "TICKET_CHECKSUM", 17: "ATTRIBUTES_INFO",
    18: "REQUESTOR_SID", 19: "FULL_CHECKSUM",
}
ETYPE_NAMES = {1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128-cts",
               18: "aes256-cts", 23: "rc4-hmac"}


def find_pac(ad_der):
    """Busca el AD-WIN2K-PAC (type 128) dentro de una AuthorizationData DER."""
    _, authdata, _ = der_parse(ad_der, 0)   # desenvuelve el SEQUENCE OF exterior
    for tag, entry in der_children(authdata):
        ef = {c[0]: c[1] for c in der_children(entry)}
        ad_type = der_int(unwrap_context(0xA0, ef[0xA0])[1])
        ad_data = unwrap_context(0xA1, ef[0xA1])[1]
        if ad_type == 1:       # AD-IF-RELEVANT -> recursivo
            r = find_pac(ad_data)
            if r:
                return r
        elif ad_type == 128:   # AD-WIN2K-PAC
            return ad_data
    return None


class NDR:
    """Lector NDR mínimo (little-endian) para KERB_VALIDATION_INFO."""
    def __init__(self, data):
        self.d = data
        self.p = 0

    def align(self, n):
       
        rem = self.p % n
        if rem:
            self.p += n - rem

    def u8(self):
        v = self.d[self.p]; self.p += 1; return v

    def u16(self):
        self.align(2)
        v = struct.unpack_from("<H", self.d, self.p)[0]; self.p += 2; return v

    def u32(self):
        self.align(4)
        v = struct.unpack_from("<I", self.d, self.p)[0]; self.p += 4; return v

    def raw(self, n):
        v = self.d[self.p:self.p + n]; self.p += n; return v

    def ustr_header(self):
        """RPC_UNICODE_STRING: Length, MaxLength, referente del buffer."""
        length = self.u16()
        maxlen = self.u16()
        ref = self.u32()
        return {"len": length, "ref": ref}

    def ustr_buffer(self):
        """Buffer diferido: array conformante+variable de wchar."""
        self.u32()                 # max_count
        self.u32()                 # offset
        actual = self.u32()        # actual_count
        data = self.raw(actual * 2)
        return data.decode("utf-16-le", "replace")

    def sid(self):
        """RPC_SID diferido (precedido por max_count conformante)."""
        self.u32()                 # max_count = SubAuthorityCount
        rev = self.u8()
        sub_count = self.u8()
        authority = int.from_bytes(self.raw(6), "big")
        subs = [self.u32() for _ in range(sub_count)]
        return "S-%d-%d-%s" % (rev, authority, "-".join(str(s) for s in subs))


def decode_logon_info(buf):
    """Decodifica KERB_VALIDATION_INFO (PAC_LOGON_INFO). Solo lectura."""
    r = NDR(buf)
    
    r.raw(8)
    r.raw(8)
    r.u32()                        # referente de la estructura raíz

    def ft(): return struct.unpack_from("<Q", r.raw(8), 0)[0]

   
    logon_time = ft(); logoff_time = ft(); kickoff_time = ft()
    pwd_last_set = ft(); pwd_can_change = ft(); pwd_must_change = ft()
    eff_name = r.ustr_header()
    full_name = r.ustr_header()
    logon_script = r.ustr_header()
    profile_path = r.ustr_header()
    home_dir = r.ustr_header()
    home_drive = r.ustr_header()
    logon_count = r.u16()
    bad_pwd_count = r.u16()
    user_id = r.u32()
    primary_gid = r.u32()
    group_count = r.u32()
    group_ids_ref = r.u32()
    user_flags = r.u32()
    session_key = r.raw(16)        # UserSessionKey
    logon_server = r.ustr_header()
    logon_domain = r.ustr_header()
    domain_sid_ref = r.u32()
    r.raw(8)                       # Reserved1[2]
    uac = r.u32()
    sub_auth_status = r.u32()
    last_ok_logon = ft(); last_fail_logon = ft()
    failed_logon_count = r.u32()
    r.u32()                        # Reserved3
    sid_count = r.u32()
    extra_sids_ref = r.u32()
    res_group_dom_ref = r.u32()
    res_group_count = r.u32()
    res_group_ids_ref = r.u32()

   
    out = {"user_id": user_id, "primary_gid": primary_gid,
           "group_count": group_count, "sid_count": sid_count,
           "uac": uac, "groups": [], "extra_sids": [], "res_groups": [],
           "logon_time": logon_time, "logoff_time": logoff_time,
           "kickoff_time": kickoff_time, "pwd_last_set": pwd_last_set,
           "pwd_can_change": pwd_can_change, "pwd_must_change": pwd_must_change,
           "last_ok_logon": last_ok_logon, "last_fail_logon": last_fail_logon,
           "logon_count": logon_count, "bad_pwd_count": bad_pwd_count,
           "failed_logon_count": failed_logon_count, "user_flags": user_flags,
           "sub_auth_status": sub_auth_status, "session_key": session_key}

    for hdr in (eff_name, full_name, logon_script, profile_path,
                home_dir, home_drive):
        if hdr["ref"]:
            s = r.ustr_buffer()
            if hdr is eff_name:
                out["account"] = s
            elif hdr is full_name:
                out["full_name"] = s

    if group_ids_ref:
        r.u32()                    # max_count
        for _ in range(group_count):
            rid = r.u32(); attr = r.u32()
            out["groups"].append((rid, attr))

    for hdr in (logon_server, logon_domain):
        if hdr["ref"]:
            s = r.ustr_buffer()
            if hdr is logon_domain:
                out["domain"] = s
            else:
                out["logon_server"] = s

    if domain_sid_ref:
        out["domain_sid"] = r.sid()

    if extra_sids_ref:
        r.u32()                    # max_count
        entries = [(r.u32(), r.u32()) for _ in range(sid_count)]  # (ref, attr)
        for ref, attr in entries:
            if ref:
                out["extra_sids"].append((r.sid(), attr))

    if res_group_dom_ref:
        out["res_group_domain_sid"] = r.sid()
    if res_group_ids_ref:
        r.u32()
        for _ in range(res_group_count):
            rid = r.u32(); attr = r.u32()
            out["res_groups"].append((rid, attr))

    return out


UAC_FLAGS = [
    (0x00000001, "ACCOUNT_DISABLED"), (0x00000002, "HOME_DIR_REQUIRED"),
    (0x00000004, "PASSWD_NOT_REQUIRED"), (0x00000008, "TEMP_DUPLICATE"),
    (0x00000010, "NORMAL_ACCOUNT"), (0x00000020, "MNS_LOGON"),
    (0x00000040, "INTERDOMAIN_TRUST"), (0x00000080, "WORKSTATION_TRUST"),
    (0x00000100, "SERVER_TRUST"), (0x00000200, "DONT_EXPIRE_PASSWD"),
    (0x00000400, "AUTO_LOCKED"), (0x00000800, "ENCRYPTED_TEXT_PWD"),
    (0x00001000, "SMARTCARD_REQUIRED"), (0x00002000, "TRUSTED_FOR_DELEGATION"),
    (0x00004000, "NOT_DELEGATED"), (0x00008000, "USE_DES_KEY_ONLY"),
    (0x00010000, "DONT_REQUIRE_PREAUTH"), (0x00020000, "PASSWORD_EXPIRED"),
    (0x00040000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x00080000, "NO_AUTH_DATA_REQUIRED"), (0x00100000, "PARTIAL_SECRETS"),
    (0x00200000, "USE_AES_KEYS"),
]
GROUP_ATTR = [
    (0x00000001, "MANDATORY"), (0x00000002, "ENABLED_BY_DEFAULT"),
    (0x00000004, "ENABLED"), (0x00000008, "OWNER"),
    (0x00000010, "DENY_ONLY"), (0x00000020, "INTEGRITY"),
    (0x00000040, "INTEGRITY_ENABLED"), (0x20000000, "RESOURCE"),
]


def flags_str(value, table):
    out = [name for bit, name in table if value & bit]
    return ", ".join(out) if out else "(ninguno)"


def parse_raw_sid(buf):
    """RPC_SID crudo (no NDR): rev, subcount, authority(6 BE), subs(LE)."""
    rev = buf[0]; count = buf[1]
    authority = int.from_bytes(buf[2:8], "big")
    subs = struct.unpack_from("<%dI" % count, buf, 8)
    return "S-%d-%d-%s" % (rev, authority, "-".join(str(s) for s in subs))


def decode_upn_dns(buf):
    upn_len, upn_off, dns_len, dns_off, flags = struct.unpack_from("<HHHHI", buf, 0)
    out = {"flags": flags}
    out["upn"] = buf[upn_off:upn_off + upn_len].decode("utf-16-le", "replace")
    out["dns"] = buf[dns_off:dns_off + dns_len].decode("utf-16-le", "replace")
    if flags & 0x2:                # S: extendido con SamName + SID
        sam_len, sam_off, sid_len, sid_off = struct.unpack_from("<HHHH", buf, 12)
        out["sam"] = buf[sam_off:sam_off + sam_len].decode("utf-16-le", "replace")
        out["sid"] = parse_raw_sid(buf[sid_off:sid_off + sid_len])
    return out


def decode_attributes(buf):
    length, flags = struct.unpack_from("<II", buf, 0)
    names = []
    if flags & 0x1:
        names.append("PAC_WAS_REQUESTED")
    if flags & 0x2:
        names.append("PAC_WAS_GIVEN_IMPLICITLY")
    return flags, ", ".join(names) if names else "(ninguno)"


# RIDs de grupos bien conocidos de dominio
WELLKNOWN_RID = {
    512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
    515: "Domain Computers", 516: "Domain Controllers", 518: "Schema Admins",
    519: "Enterprise Admins", 520: "Group Policy Creator Owners",
    525: "Protected Users", 500: "Administrator",
}


def filetime(ft):
    if ft in (0, 0x7FFFFFFFFFFFFFFF):
        return "sin expiración / vacío"
    return str(datetime.datetime(1601, 1, 1) +
               datetime.timedelta(microseconds=ft / 10)) + " UTC"


def epoch(ts):
    if ts == 0:
        return "0"
    return str(datetime.datetime(1970, 1, 1) +
               datetime.timedelta(seconds=ts)) + " UTC"


def parse_pac(pac):
    cbuffers, version = struct.unpack_from("<II", pac, 0)
    print(f"  PACTYPE: {cbuffers} buffers, version {version}")
    off = 8
    for _ in range(cbuffers):
        ultype, size, offset = struct.unpack_from("<IIQ", pac, off)
        off += 16
        name = PAC_TYPES.get(ultype, f"tipo {ultype}")
        print(f"    [{ultype:>2}] {name:<16} size={size} offset={offset}")
        buf = pac[offset:offset + size]
        if ultype == 1:                       # PAC_LOGON_INFO
            try:
                li = decode_logon_info(buf)
            except Exception as e:
                print(f"         [!] no pude decodificar LOGON_INFO: {e}")
                continue
            dsid = li.get("domain_sid", "")
            print(f"         Cuenta        : {li.get('account','?')}"
                  f"   FullName: {li.get('full_name','')}")
            print(f"         Dominio       : {li.get('domain','?')}"
                  f"   LogonServer: {li.get('logon_server','')}")
            print(f"         Domain SID    : {dsid}")
            print(f"         User RID      : {li['user_id']}"
                  f"   -> {dsid}-{li['user_id']}")
            print(f"         Primary group : {li['primary_gid']}")
            print(f"         UAC           : 0x{li['uac']:08x}"
                  f"  [{flags_str(li['uac'], UAC_FLAGS)}]")
            print(f"         UserFlags     : 0x{li['user_flags']:08x}")
            print(f"         LogonCount    : {li['logon_count']}"
                  f"   BadPwdCount: {li['bad_pwd_count']}"
                  f"   FailedLogon: {li['failed_logon_count']}")
            print(f"         LogonTime     : {filetime(li['logon_time'])}")
            print(f"         LogoffTime    : {filetime(li['logoff_time'])}")
            print(f"         KickOffTime   : {filetime(li['kickoff_time'])}")
            print(f"         PwdLastSet    : {filetime(li['pwd_last_set'])}")
            print(f"         PwdCanChange  : {filetime(li['pwd_can_change'])}")
            print(f"         PwdMustChange : {filetime(li['pwd_must_change'])}")
            print(f"         SessionKey    : "
                  f"{binascii.hexlify(li['session_key']).decode()}")
            print(f"         Grupos ({li['group_count']}):")
            for rid, attr in li["groups"]:
                nm = WELLKNOWN_RID.get(rid, "")
                nm = f" [{nm}]" if nm else ""
                print(f"             {dsid}-{rid}{nm}  "
                      f"attr=0x{attr:08x} ({flags_str(attr, GROUP_ATTR)})")
            if li["extra_sids"]:
                print(f"         Extra SIDs ({li['sid_count']}):")
                for sid, attr in li["extra_sids"]:
                    print(f"             {sid}  attr=0x{attr:08x} "
                          f"({flags_str(attr, GROUP_ATTR)})")
            if li["res_groups"]:
                rdom = li.get("res_group_domain_sid", "")
                print(f"         Resource groups ({len(li['res_groups'])}):")
                for rid, attr in li["res_groups"]:
                    print(f"             {rdom}-{rid}  attr=0x{attr:08x}")
        elif ultype == 12:                    # UPN_DNS_INFO
            try:
                u = decode_upn_dns(buf)
                print(f"         Flags : 0x{u['flags']:08x}")
                print(f"         UPN   : {u['upn']}")
                print(f"         DNS   : {u['dns']}")
                if "sam" in u:
                    print(f"         SAM   : {u['sam']}")
                    print(f"         SID   : {u['sid']}")
            except Exception as e:
                print(f"         [!] error UPN_DNS: {e}")
        elif ultype == 17:                    # PAC_ATTRIBUTES_INFO
            try:
                fl, names = decode_attributes(buf)
                print(f"         Flags : 0x{fl:08x}  [{names}]")
            except Exception as e:
                print(f"         [!] error ATTRIBUTES: {e}")
        elif ultype == 18:                    # PAC_REQUESTOR (SID)
            try:
                print(f"         SID   : {parse_raw_sid(buf)}")
            except Exception as e:
                print(f"         [!] error REQUESTOR_SID: {e}")
        elif ultype == 10:                    # PAC_CLIENT_INFO
            clientid = struct.unpack_from("<Q", buf, 0)[0]
            namelen = struct.unpack_from("<H", buf, 8)[0]
            cname = buf[10:10 + namelen].decode("utf-16-le", "replace")
            print(f"         ClientId: {filetime(clientid)}")
            print(f"         Name    : {cname}")
        elif ultype in (6, 7, 16, 19):        # firmas
            sigtype = struct.unpack_from("<I", buf, 0)[0]
            sig = buf[4:]
            stname = {16: "HMAC_SHA1_96_AES256", 15: "HMAC_SHA1_96_AES128",
                      0xFFFFFF76: "HMAC_MD5"}.get(sigtype & 0xFFFFFFFF, "?")
            print(f"         SignatureType: {sigtype} ({stname})")
            print(f"         Signature    : {binascii.hexlify(sig).decode()}")


# --------------------------------------------------------------------------
def tktflags_str(flags):
    names = ["reserved", "forwardable", "forwarded", "proxiable", "proxy",
             "may-postdate", "postdated", "invalid", "renewable", "initial",
             "pre-authent", "hw-authent", "transited-policy-checked",
             "ok-as-delegate"]
    out = []
    for i, nm in enumerate(names):
        if flags & (1 << (31 - i)):
            out.append(nm)
    return ", ".join(out) if out else "(ninguna)"


def main():
    ap = argparse.ArgumentParser(description="Visor de solo lectura de tickets Kerberos")
    ap.add_argument("ccache")
    ap.add_argument("-k", "--key", help="NT hash (RC4) o AES key en hex")
    args = ap.parse_args()

    with open(args.ccache, "rb") as f:
        data = f.read()

    cc = parse_ccache(data)
    print("=" * 70)
    print(f".ccache versión 0x{cc['version']:04x}")
    print(f"principal por defecto: {cc['default']['str']}")
    print(f"credenciales: {len(cc['creds'])}")

    for n, cred in enumerate(cc["creds"]):
        print("=" * 70)
        print(f"[Credencial {n}]")
        print(f"  client : {cred['client']['str']}")
        print(f"  server : {cred['server']['str']}")
        print(f"  flags  : 0x{cred['tktflags']:08x}  "
              f"[{tktflags_str(cred['tktflags'])}]")
        print(f"  session key: etype {cred['keytype']} "
              f"({ETYPE_NAMES.get(cred['keytype'],'?')}) "
              f"{binascii.hexlify(cred['keyvalue']).decode()}")
        for t in ["authtime", "starttime", "endtime", "renew_till"]:
            print(f"  ccache {t:<10}: {epoch(cred[t])}")

        try:
            tkt = parse_ticket(cred["ticket"])
        except Exception as e:
            print(f"  [!] no pude parsear el Ticket: {e}")
            continue
        print(f"  Ticket -> realm={tkt['realm']} sname={tkt['sname']} "
              f"etype={tkt['etype']} ({ETYPE_NAMES.get(tkt['etype'],'?')}) "
              f"kvno={tkt['kvno']}")

        if not args.key:
            print("  (sin -key: no se descifra el enc-part)")
            continue

        key_bytes = binascii.unhexlify(args.key)
        try:
            plain = decrypt_enc_part(tkt["etype"], key_bytes, tkt["cipher"])
        except Exception as e:
            print(f"  [!] no pude descifrar: {e}")
            continue

        print("  --- EncTicketPart (descifrado) ---")
        etp = parse_enc_ticket_part(plain)
        print(f"  crealm : {etp.get('crealm')}")
        print(f"  cname  : {etp.get('cname')}")
        for t in ["authtime", "starttime", "endtime", "renew_till"]:
            if t in etp:
                print(f"  {t:<10}: {etp[t]}")
        if "key_value" in etp:
            print(f"  ticket session key: etype {etp['key_etype']} "
                  f"{binascii.hexlify(etp['key_value']).decode()}")

        if "authdata" in etp:
            pac = find_pac(etp["authdata"])
            if pac:
                print("  --- PAC ---")
                try:
                    parse_pac(pac)
                except Exception as e:
                    print(f"  [!] error parseando PAC: {e}")
            else:
                print("  (sin PAC en authorization-data)")


if __name__ == "__main__":
    main()
