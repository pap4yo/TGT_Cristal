# Kerberos Ticket Toolkit

Conjunto de utilidades en Python para **inspeccionar y modificar tickets Kerberos**
(`.ccache`, formato MIT) y su **PAC** (Privilege Attribute Certificate), pensado para
equipos de **Red Team / pentesting en entornos Active Directory**.

- **`view_ticket.py`** — visor de *solo lectura*: parsea el `.ccache`, descifra el
  ticket y decodifica el PAC.
- **`edit_ticket.py`** — editor *in situ*: abre un ticket existente, cambia solo los
  campos indicados (grupos, SIDs, RID, UAC…), **re-firma el PAC y re-cifra**, y
  reescribe el `.ccache`.
- **`ticket_web.py`** *(opcional)* — interfaz web local sobre el motor de
  `edit_ticket.py` para editar de forma visual y dinámica.

> ⚠️ **Uso autorizado únicamente.** Estas herramientas forjan/alteran material de
> autenticación. Empléalas exclusivamente en **engagements con autorización por
> escrito**, laboratorios propios o CTF. El uso no autorizado contra sistemas de
> terceros es ilegal.

---

## Requisitos

- Python 3.7+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) (o `pycryptodomex`)
- `flask` *(solo para `ticket_web.py`)*

```bash
pip install pycryptodome flask
```

Las herramientas necesitan la **clave** del principal que cifra el ticket:
- **Golden ticket** → hash/clave de **KRBTGT** (NT hash para RC4, o clave AES).
- **Silver ticket** → clave de la **cuenta de servicio**.

Formatos de clave soportados (según `etype` del ticket):

| etype | Algoritmo       | Clave (hex)        |
|------:|-----------------|--------------------|
| 23    | RC4-HMAC        | NT hash (32 hex)   |
| 17    | AES128-CTS      | 32 hex (16 bytes)  |
| 18    | AES256-CTS      | 64 hex (32 bytes)  |

---

## `view_ticket.py` — Visor de tickets (solo lectura)

Parsea el contenedor `.ccache`, muestra los metadatos de cada credencial y, si se
indica la clave, **descifra** la parte cifrada del ticket y **decodifica el PAC**
(usuario, dominio, SID, grupos, SIDs extra, UAC, firmas, etc.).

### Uso

```bash
# Solo la parte en claro (sin descifrar)
python3 view_ticket.py ticket.ccache

# Descifrar y mostrar el PAC (RC4 / etype 23)
python3 view_ticket.py ticket.ccache -k <NT_hash>

# Descifrar y mostrar el PAC (AES / etype 17 ó 18)
python3 view_ticket.py ticket.ccache -k <AES_key_hex>

# Exportar los parámetros extraídos como JSON
python3 view_ticket.py ticket.ccache -k <key> --json
```

### Opciones

| Opción          | Descripción                                             |
|-----------------|---------------------------------------------------------|
| `ccache`        | Ruta al fichero `.ccache` (obligatorio).                |
| `-k`, `--key`   | Clave en hex (NT hash o AES) para descifrar.            |
| `--json`        | Vuelca los parámetros extraídos en JSON (requiere `-k`).|

### Qué muestra

- **Contenedor**: versión, principal por defecto, nº de credenciales.
- **Por credencial**: client, server (`sname`), flags, clave de sesión, tiempos.
- **Ticket**: realm, `sname`, `etype`, `kvno`.
- **EncTicketPart** (descifrado): `crealm`, `cname`, tiempos, clave de sesión.
- **PAC**: `LOGON_INFO` (cuenta, dominio, SID, RID, grupos, SIDs extra, UAC, claves,
  tiempos), `UPN_DNS_INFO`, `CLIENT_INFO`, `ATTRIBUTES_INFO`, `REQUESTOR_SID` y las
  firmas (`SERVER_CHECKSUM`, `KDC_CHECKSUM`, …).

---

## `edit_ticket.py` — Editor in situ

Abre un ticket **existente**, descifra con su clave, aplica **solo** los cambios que
indiques sobre el `PAC_LOGON_INFO` y **conserva todo lo demás byte a byte** (tiempos,
flags, clave de sesión, `sname`, `cname`, y los demás buffers del PAC como
`CLIENT_INFO`). Después **recalcula las dos firmas del PAC** (server + KDC), **re-cifra**
con la misma clave y `etype`, y reescribe el `.ccache`.

Es una herramienta **autónoma** (solo depende de `pycryptodome`).

### Uso

```bash
# Añadir Domain Admins (512) y un extra-SID, conservando el resto
python3 edit_ticket.py admin.ccache -k <key> \
    --add-groups 512 --add-extra-sids S-1-5-21-10-20-30-519

# Cambiar el RID del usuario a 500 (Administrator) sin tocar tiempos/clave
python3 edit_ticket.py admin.ccache -k <key> --user-id 500 -o editado.ccache

# Reemplazar por completo la lista de grupos
python3 edit_ticket.py admin.ccache -k <key> --groups 513,512,518,519,520
```

### Opciones

| Opción               | Descripción                                             |
|----------------------|---------------------------------------------------------|
| `ccache`             | Fichero `.ccache` a modificar (obligatorio).            |
| `-k`, `--key`        | La **misma clave** que abre el ticket (hex).            |
| `-o`, `--out`        | Fichero de salida (por defecto: sobrescribe la entrada).|
| `--cred N`           | Índice de credencial a editar (por defecto `0`).        |
| `--account`          | Cambia el nombre de cuenta.                             |
| `--user-id`          | Cambia el RID del usuario.                              |
| `--primary-gid`      | Cambia el RID del grupo primario.                       |
| `--groups`           | **Reemplaza** la lista de grupos (RIDs, csv).           |
| `--add-groups`       | **Añade** RIDs de grupo (csv).                          |
| `--extra-sids`       | **Reemplaza** los extra-SIDs (csv).                     |
| `--add-extra-sids`   | **Añade** extra-SIDs (csv).                             |
| `--uac`              | Cambia el valor de UAC (hex, p. ej. `0x210`).           |

> La herramienta necesita la clave que **descifra** el ticket: no puede editar lo que
> no puede abrir. Para un golden es la KRBTGT; para un silver, la de servicio.

---

## `ticket_web.py` *(opcional)* — Editor web

Interfaz local que usa `edit_ticket.py` como motor. Subes el `.ccache` + la clave, lo
descifra y presenta un editor dinámico de **casi todos los campos**: principales,
realm, `cname`/`crealm`, **flags del ticket como bits**, clave de sesión, tiempos y
todo el `PAC_LOGON_INFO` (grupos con `attr`, extra-SIDs con `attr`, **UAC como bits**,
SID de dominio, RID…), con añadir/quitar filas. Al generar, re-firma y re-cifra y
descarga el ticket resultante.

```bash
python3 ticket_web.py      # abre http://127.0.0.1:8000
```

> El servidor escucha **solo en `127.0.0.1`** (local). No lo expongas en red.

---

## Flujo típico (extraer → modificar → re-forjar)

```bash
# 1) Inspeccionar y extraer parámetros
python3 view_ticket.py base.ccache -k <key>
python3 view_ticket.py base.ccache -k <key> --json > params.json

# 2) Modificar (p. ej. escalar privilegios)
python3 edit_ticket.py base.ccache -k <key> \
    --add-groups 512 --user-id 500 -o escalado.ccache

# 3) Verificar el resultado (round-trip)
python3 view_ticket.py escalado.ccache -k <key>
```

---

## Notas técnicas

- Soporta `etype` **23 (RC4-HMAC)**, **17 (AES128-CTS)** y **18 (AES256-CTS)**.
- Implementa las primitivas de RFC 3961/3962 (n-fold, derivación de claves, CBC-CTS)
  y la verificación/cálculo de firmas del PAC (HMAC-SHA1-96 y HMAC-MD5).
- Al editar el PAC, **las firmas se recalculan siempre**: cambiar el contenido invalida
  las firmas previas, por lo que `SERVER_CHECKSUM`/`KDC_CHECKSUM` se regeneran.
- `edit_ticket.py` preserva los buffers del PAC que no modifica (`CLIENT_INFO`, etc.);
  actualmente `CLIENT_INFO` no se sincroniza automáticamente al cambiar la cuenta.

---

## Aplicación defensiva (Blue Team)

Además del uso ofensivo, el toolkit sirve para **generar muestras controladas** con las
que afinar detecciones: tickets con vigencia anómala (p. ej. 10 años), ausencia de
`UPN_DNS_INFO`, inconsistencias de PAC o firmas, útiles para validar reglas de SIEM,
telemetría de Kerberos y hardening de AD.

---

## Aviso legal

Este software se proporciona con fines de **seguridad ofensiva autorizada,
investigación y formación**. El usuario es el único responsable de contar con permiso
explícito sobre los sistemas objetivo. Los autores no se responsabilizan del mal uso.
