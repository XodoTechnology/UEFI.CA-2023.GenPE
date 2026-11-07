/*
 * GenPE - UEFI CA 2023 Secure Boot updater for Windows / WinPE
 *
 * Single-file, dependency-free tool (kernel32 + advapi32 only) that:
 *   - enrolls "Microsoft Corporation KEK 2K CA 2023" into KEK using the
 *     per-OEM PK-signed update published by Microsoft
 *   - appends "Windows UEFI CA 2023", "Microsoft UEFI CA 2023" and
 *     (optionally) "Microsoft Option ROM UEFI CA 2023" to db
 *   - optionally applies dbx revocation updates (guarded)
 *   - marks the running OS, or an offline Windows install, as updated
 *     (HKLM\SYSTEM\...\Control\SecureBoot) or opts it in to the
 *     Microsoft-managed servicing path (AvailableUpdates=0x5944)
 *
 * Payloads are the signed .bin files from github.com/microsoft/secureboot_objects
 * embedded at build time.  All writes are APPEND_WRITE only - this tool will
 * never perform a destructive replace of a Secure Boot database.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
/* SetFirmwareEnvironmentVariableExW needs _WIN32_WINNT >= 0x0602;
 * llvm-mingw headers default lower than gcc's */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>

#include "sha1.h"
#include "generated/payloads.h"

#define G_EFI   L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"  /* EFI_GLOBAL_VARIABLE */
#define G_IMGDB L"{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}"  /* EFI_IMAGE_SECURITY_DATABASE */

/* EFI variable attribute bits */
#define ATTR_NV     0x01
#define ATTR_BS     0x02
#define ATTR_RT     0x04
#define ATTR_AW     0x10  /* authenticated write (deprecated) */
#define ATTR_TBAT   0x20  /* time-based authenticated write */
#define ATTR_APPEND 0x40  /* append write */

#define SB_KEY      L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot"
#define HIVENAME    L"GENPE$SYSTEM"
#define HIVENAME_SW L"GENPE$SOFTWARE"
#define OPTIN_MASK  0x5944

static int g_verbose;
static int g_dryrun;
static int g_json;

/* when set (GUI mode), all output goes here instead of stdout/stderr */
static void (*g_msgfn)(const char *line);

static void emit(const char *line)
{
    if (g_msgfn) g_msgfn(line);
    else         fputs(line, stdout);
}

static void vlog(const char *fmt, ...)
{
    char buf[2048] = "  [dbg] ";
    va_list ap;
    if (!g_verbose) return;
    va_start(ap, fmt);
    vsnprintf(buf + 8, sizeof(buf) - 10, fmt, ap);
    va_end(ap);
    strcat(buf, "\n");
    emit(buf);
}

static void msg(const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    strcat(buf, "\n");
    emit(buf);
}

/* ------------------------------------------------------------------ */
/* privileges                                                          */
/* ------------------------------------------------------------------ */

static int enable_privilege(LPCWSTR name)
{
    HANDLE tok = NULL;
    TOKEN_PRIVILEGES tp;
    BOOL ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL) &&
            GetLastError() == ERROR_SUCCESS)
            ok = TRUE;
    }
    CloseHandle(tok);
    return ok;
}

static int is_elevated(void)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &sid)) {
        CheckTokenMembership(NULL, sid, &member);
        FreeSid(sid);
    }
    return member;
}

static void grab_privileges(void)
{
    enable_privilege(SE_SYSTEM_ENVIRONMENT_NAME);
    enable_privilege(SE_BACKUP_NAME);
    enable_privilege(SE_RESTORE_NAME);
}

/* ------------------------------------------------------------------ */
/* UEFI variable I/O                                                   */
/* ------------------------------------------------------------------ */

static unsigned char *read_var(LPCWSTR name, LPCWSTR guid,
                               DWORD *plen, DWORD *pattrs)
{
    DWORD attr = 0, cap = 64 * 1024;
    unsigned char *buf = malloc(cap);
    DWORD n;

    if (!buf) return NULL;
    for (;;) {
        SetLastError(0);
        n = GetFirmwareEnvironmentVariableExW(name, guid, buf, cap, &attr);
        if (n == 0) {
            vlog("read %ls -> err %lu", name, GetLastError());
            free(buf);
            return NULL;
        }
        if (n <= cap) break;
        if (n > 8 * 1024 * 1024) { free(buf); return NULL; }
        cap = n;
        buf = realloc(buf, cap);
        if (!buf) return NULL;
    }
    if (plen) *plen = n;
    if (pattrs) *pattrs = attr;
    return buf;
}

/* Try appending an authenticated payload.  Every attribute combo includes
 * ATTR_APPEND - we never offer a replace write for embedded payloads. */
static int set_var_append(LPCWSTR name, LPCWSTR guid,
                          const void *data, DWORD len, DWORD *err)
{
    static const DWORD combos[] = {
        ATTR_NV | ATTR_BS | ATTR_RT | ATTR_AW | ATTR_TBAT | ATTR_APPEND,
        ATTR_NV | ATTR_BS | ATTR_RT | ATTR_TBAT | ATTR_APPEND,
        ATTR_NV | ATTR_BS | ATTR_RT | ATTR_APPEND,
        ATTR_APPEND,
    };
    DWORD e = ERROR_INVALID_FUNCTION;
    size_t i;
    if (g_dryrun) {
        msg("    [dry-run] would append %lu bytes to %ls", (unsigned long)len,
            name);
        if (err) *err = 0;
        return TRUE;
    }
    for (i = 0; i < sizeof(combos) / sizeof(combos[0]); i++) {
        SetLastError(0);
        if (SetFirmwareEnvironmentVariableExW(name, guid, (PVOID)data, len,
                                              combos[i])) {
            if (err) *err = 0;
            return TRUE;
        }
        e = GetLastError();
        vlog("set %ls attrs=0x%02lx -> err %lu", name,
             (unsigned long)combos[i], (unsigned long)e);
    }
    if (err) *err = e;
    return FALSE;
}

/* Explicitly dangerous: replace-write for user-supplied payloads only. */
static int set_var_replace(LPCWSTR name, LPCWSTR guid,
                           const void *data, DWORD len, DWORD *err)
{
    static const DWORD combos[] = {
        ATTR_NV | ATTR_BS | ATTR_RT | ATTR_TBAT | ATTR_AW,
        ATTR_NV | ATTR_BS | ATTR_RT | ATTR_TBAT,
        ATTR_NV | ATTR_BS | ATTR_RT,
    };
    DWORD e = ERROR_INVALID_FUNCTION;
    size_t i;
    if (g_dryrun) {
        msg("    [dry-run] would REPLACE %lu bytes in %ls", (unsigned long)len,
            name);
        if (err) *err = 0;
        return TRUE;
    }
    for (i = 0; i < sizeof(combos) / sizeof(combos[0]); i++) {
        SetLastError(0);
        if (SetFirmwareEnvironmentVariableExW(name, guid, (PVOID)data, len,
                                              combos[i])) {
            if (err) *err = 0;
            return TRUE;
        }
        e = GetLastError();
        vlog("set(replace) %ls attrs=0x%02lx -> err %lu", name,
             (unsigned long)combos[i], (unsigned long)e);
    }
    if (err) *err = e;
    return FALSE;
}

static int uefi_available(void)
{
    DWORD attr;
    unsigned char *b = read_var(L"SecureBoot", G_EFI, NULL, &attr);
    if (!b) b = read_var(L"PK", G_EFI, NULL, &attr);
    if (!b) b = read_var(L"BootOrder", G_EFI, NULL, &attr);
    if (b) free(b);
    return b != NULL;
}

#include "sigparse.h"
#include "sigcheck.h"

/* ------------------------------------------------------------------ */
/* registry                                                            */
/* ------------------------------------------------------------------ */

static void reg_set_dword(HKEY k, LPCWSTR name, DWORD v)
{
    LONG e;
    if (g_dryrun) {
        msg("    [dry-run] would set %ls = 0x%08lx", name, (unsigned long)v);
        return;
    }
    e = RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    if (e) msg("    ! failed to set %ls (err %ld)", name, (long)e);
}

static void reg_set_sz(HKEY k, LPCWSTR name, LPCWSTR v)
{
    LONG e;
    if (g_dryrun) {
        msg("    [dry-run] would set %ls = \"%ls\"", name, v);
        return;
    }
    e = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)v,
                       (DWORD)((wcslen(v) + 1) * sizeof(WCHAR)));
    if (e) msg("    ! failed to set %ls (err %ld)", name, (long)e);
}

static void reg_show_str(HKEY k, LPCWSTR name)
{
    WCHAR buf[64];
    DWORD type = 0, size = sizeof(buf), d = 0;
    if (RegQueryValueExW(k, name, NULL, &type, (BYTE *)buf, &size) ==
        ERROR_SUCCESS) {
        if (type == REG_SZ)
            msg("    %-28ls %ls", name, buf);
        else if (type == REG_DWORD) {
            memcpy(&d, buf, sizeof(d));
            msg("    %-28ls 0x%08lx", name, (unsigned long)d);
        }
    }
}

/* open (or create) Control\SecureBoot inside root key; root may be a
 * mounted offline hive under HKLM\GENPE$SYSTEM */
static HKEY open_sb_key(HKEY root, const WCHAR *sub, int create)
{
    HKEY k = NULL;
    if (create)
        RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL,
                        &k, NULL);
    else
        RegOpenKeyExW(root, sub, 0, KEY_READ, &k);
    return k;
}

/* resolve "ControlSet%03u" inside a mounted SYSTEM hive via Select\Current */
static HKEY open_sb_key_hive(HKEY hive, int create)
{
    HKEY sel = NULL;
    DWORD cur = 1, type = 0, size = sizeof(cur);
    WCHAR path[160];

    if (RegOpenKeyExW(hive, L"Select", 0, KEY_READ, &sel) == ERROR_SUCCESS) {
        RegQueryValueExW(sel, L"Current", NULL, &type, (BYTE *)&cur, &size);
        RegCloseKey(sel);
    }
    _snwprintf(path, 160, L"ControlSet%03lu\\Control\\SecureBoot",
               (unsigned long)cur);
    return open_sb_key(hive, path, create);
}

/* Mark one SecureBoot servicing key as Updated or Pending(opt-in). */
static void mark_values(HKEY sb, int pending, DWORD mask, int ms_optin)
{
    if (pending) {
        reg_set_dword(sb, L"AvailableUpdates", mask);
        {
            WCHAR st[32]; DWORD type = 0, size = sizeof(st);
            int upd = RegQueryValueExW(sb, L"UEFICA2023Status", NULL, &type,
                                       (BYTE *)st, &size) == ERROR_SUCCESS &&
                      type == REG_SZ && !wcscmp(st, L"Updated");
            if (!upd)
                reg_set_sz(sb, L"UEFICA2023Status", L"NotStarted");
        }
        msg("    AvailableUpdates = 0x%04lx (OS servicing will apply on boot)",
            (unsigned long)mask);
    } else {
        reg_set_sz(sb, L"UEFICA2023Status", L"Updated");
        reg_set_dword(sb, L"UEFICA2023Error", 0);
        reg_set_dword(sb, L"UEFICA2023ErrorEvent", 0);
        reg_set_dword(sb, L"AvailableUpdates", 0);
        msg("    UEFICA2023Status = \"Updated\"");
    }
    if (ms_optin) {
        reg_set_dword(sb, L"MicrosoftUpdateManagedOptIn", 1);
        msg("    MicrosoftUpdateManagedOptIn = 1");
    }
}

/* drive like L"D:" or L"D:\\"; NULL = running OS */
static int mark_os(const WCHAR *drive, int pending, DWORD mask, int ms_optin)
{
    if (!drive) {
        HKEY k = open_sb_key(HKEY_LOCAL_MACHINE, SB_KEY, 1);
        if (!k) { msg("error: cannot open %ls (err %ld)", SB_KEY,
                      (long)GetLastError()); return 1; }
        msg("  running OS:");
        mark_values(k, pending, mask, ms_optin);
        RegFlushKey(k);
        RegCloseKey(k);
        return 0;
    }

    {
        WCHAR hive[MAX_PATH];
        HKEY root = NULL, sb = NULL;
        DWORD err;

        _snwprintf(hive, MAX_PATH,
                   L"%ls\\Windows\\System32\\config\\SYSTEM", drive);
        if (GetFileAttributesW(hive) == INVALID_FILE_ATTRIBUTES) {
            msg("error: no SYSTEM hive at %ls (not a Windows install?)", hive);
            return 1;
        }
        err = (DWORD)RegLoadKeyW(HKEY_LOCAL_MACHINE, HIVENAME, hive);
        if (err) {
            msg("error: RegLoadKey %ls failed (err %lu)", hive,
                (unsigned long)err);
            return 1;
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, HIVENAME, 0,
                          KEY_READ | KEY_WRITE, &root) != ERROR_SUCCESS) {
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HIVENAME);
            msg("error: cannot open loaded hive");
            return 1;
        }
        msg("  offline OS at %ls:", drive);
        sb = open_sb_key_hive(root, 1);
        if (sb) {
            mark_values(sb, pending, mask, ms_optin);
            RegFlushKey(sb);
            RegCloseKey(sb);
        } else {
            msg("    ! could not open Control\\SecureBoot in hive");
        }
        RegCloseKey(root);
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HIVENAME);
        return sb ? 0 : 1;
    }
}

/* ------------------------------------------------------------------ */
/* firmware apply helpers                                              */
/* ------------------------------------------------------------------ */

static int apply_payload(LPCWSTR var, LPCWSTR guid,
                         const unsigned char *data, unsigned int len,
                         const char *desc)
{
    DWORD err = 0;
    msg("  applying %s to %ls (%u bytes, append)...", desc, var, len);
    if (set_var_append(var, guid, data, len, &err)) {
        msg("    OK");
        return 0;
    }
    msg("    FAILED (err %lu)", (unsigned long)err);
    return 1;
}

static int cert_present_in(LPCWSTR var, LPCWSTR guid, const char *name)
{
    DWORD n = 0;
    unsigned char *b = read_var(var, guid, &n, NULL);
    int r = 0;
    if (b) { r = var_has_named_cert(b, n, name); free(b); }
    return r;
}

/* ------------------------------------------------------------------ */
/* commands                                                            */
/* ------------------------------------------------------------------ */

struct inv_ctx { int n; };
static void inv_cb(const unsigned char *t, const unsigned char *o,
                   const unsigned char *d, unsigned int n, void *ctx)
{
    struct inv_ctx *c = ctx;
    WCHAR cn[80];
    (void)o;
    if (!memcmp(t, SIG_X509, 16)) {
        unsigned char h[20];
        const char *kn;
        sha1(d, n, h);
        kn = known_cert_name(h);
        msg("      [%d] x509  %ls%s%s", c->n,
            cert_cn(d, n, cn, 80) ? cn : L"(cn?)",
            kn ? "  <-- " : "", kn ? kn : "");
        if (g_verbose) {
            int i;
            fprintf(stderr, "          sha1 ");
            for (i = 0; i < 20; i++) fprintf(stderr, "%02x", h[i]);
            fputc('\n', stderr);
        }
    } else {
        msg("      [%d] %-7s %u bytes", c->n, sigtype_name(t), n);
    }
    c->n++;
}

static void dump_var(const char *title, LPCWSTR name, LPCWSTR guid)
{
    DWORD n = 0, attr = 0;
    unsigned char *b = read_var(name, guid, &n, &attr);
    struct inv_ctx c = { 0 };
    msg("  %s (%ls):", title, name);
    if (!b) { msg("      <not present>"); return; }
    for_each_sig(b, n, inv_cb, &c);
    msg("      (%d entries, %lu bytes, attrs 0x%02lx)", c.n,
        (unsigned long)n, (unsigned long)attr);
    free(b);
}

static void show_registry(HKEY sb)
{
    msg("  OS servicing state (HKLM\\%ls):", SB_KEY);
    reg_show_str(sb, L"UEFICA2023Status");
    reg_show_str(sb, L"UEFICA2023Error");
    reg_show_str(sb, L"AvailableUpdates");
    reg_show_str(sb, L"MicrosoftUpdateManagedOptIn");
    reg_show_str(sb, L"HighConfidenceOptOut");
    reg_show_str(sb, L"WindowsUEFICA2023Capable");
}

static int cmd_status(void)
{
    DWORD n = 0;
    unsigned char *b;
    struct pk_ctx pki;
    const kek_entry_t *match;

    msg("UEFI CA 2023 status");
    msg("===================");

    b = read_var(L"SecureBoot", G_EFI, &n, NULL);
    if (b) { msg("  SecureBoot: %s", b[0] ? "enabled" : "disabled"); free(b); }
    b = read_var(L"SetupMode", G_EFI, &n, NULL);
    if (b) { msg("  SetupMode:  %s", b[0] ? "SETUP (no PK enrolled)" :
                 "user"); free(b); }

    b = read_var(L"PK", G_EFI, &n, NULL);
    msg("  PK:");
    if (b) {
        memset(&pki, 0, sizeof(pki));
        match = find_kek_update(b, n, &pki);
        msg("      %ls", pki.saw_cert ? pki.cn : L"(no x509)");
        if (match)
            msg("      KEK update: %s", match->path);
        else if (pki.saw_cert)
            msg("      KEK update: none (PK not in Microsoft map - use"
                " 'apply' with an OEM-signed payload)");
        free(b);
    } else msg("      <not present>");

    dump_var("Key Exchange Key", L"KEK", G_EFI);
    dump_var("Signature Database", L"db", G_IMGDB);
    dump_var("Forbidden Database", L"dbx", G_IMGDB);

    msg("  2023 CA coverage:");
    msg("      KEK 2K CA 2023 .......... %s",
        cert_present_in(L"KEK", G_EFI,
                        "Microsoft Corporation KEK 2K CA 2023")
        ? "present" : "MISSING");
    msg("      Windows UEFI CA 2023 .... %s",
        cert_present_in(L"db", G_IMGDB, "Windows UEFI CA 2023")
        ? "present" : "MISSING");
    msg("      Microsoft UEFI CA 2023 .. %s",
        cert_present_in(L"db", G_IMGDB, "Microsoft UEFI CA 2023")
        ? "present" : "MISSING");
    msg("      Option ROM UEFI CA 2023 . %s",
        cert_present_in(L"db", G_IMGDB, "Microsoft Option ROM UEFI CA 2023")
        ? "present" : "not present (optional)");

    {
        HKEY k = open_sb_key(HKEY_LOCAL_MACHINE, SB_KEY, 0);
        if (k) { show_registry(k); RegCloseKey(k); }
    }
    return 0;
}

static int cmd_scan(void)
{
    WCHAR letter;
    msg("Scanning fixed drive letters for Windows installs...");
    for (letter = L'C'; letter <= L'Z'; letter++) {
        WCHAR sys[MAX_PATH], sw[MAX_PATH];
        HKEY h = NULL;
        _snwprintf(sys, MAX_PATH, L"%lc:\\Windows\\System32\\config\\SYSTEM",
                   letter);
        if (GetFileAttributesW(sys) == INVALID_FILE_ATTRIBUTES) continue;

        WCHAR prod[128] = L"";
        _snwprintf(sw, MAX_PATH, L"%lc:\\Windows\\System32\\config\\SOFTWARE",
                   letter);
        if (RegLoadKeyW(HKEY_LOCAL_MACHINE, HIVENAME_SW, sw) ==
            ERROR_SUCCESS &&
            RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          HIVENAME_SW L"\\Microsoft\\Windows NT\\CurrentVersion",
                          0, KEY_READ, &h) == ERROR_SUCCESS) {
            DWORD size = sizeof(prod);
            RegQueryValueExW(h, L"ProductName", NULL, NULL, (BYTE *)prod,
                             &size);
            RegCloseKey(h);
        }
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HIVENAME_SW);
        msg("  %lc:\\  %ls", letter, prod[0] ? prod : L"(Windows install)");
    }
    msg("Done. Use 'genpe mark X:' or 'genpe optin X:' to update an OS.");
    return 0;
}

static int confirm_yes(int argc, WCHAR **argv)
{
    int i;
    for (i = 0; i < argc; i++)
        if (!wcscmp(argv[i], L"--yes") || !wcscmp(argv[i], L"-y"))
            return 1;
    return 0;
}

static int cmd_install(int argc, WCHAR **argv)
{
    int orom = 0, dbx = 0, dbxsvn = 0, dbx2024 = 0, nomark = 0;
    int kekonly = 0, dbonly = 0, i, fails = 0;
    struct pk_ctx pki;
    const kek_entry_t *ke;
    DWORD n = 0;
    unsigned char *pkbuf;

    for (i = 0; i < argc; i++) {
        if (!wcscmp(argv[i], L"--orom")) orom = 1;
        else if (!wcscmp(argv[i], L"--dbx")) dbx = 1;
        else if (!wcscmp(argv[i], L"--dbx-svn")) dbxsvn = 1;
        else if (!wcscmp(argv[i], L"--dbx-2024")) dbx2024 = 1;
        else if (!wcscmp(argv[i], L"--no-mark")) nomark = 1;
        else if (!wcscmp(argv[i], L"--kek-only")) kekonly = 1;
        else if (!wcscmp(argv[i], L"--db-only")) dbonly = 1;
    }

    msg("Firmware Secure Boot update to 2023 CAs");
    msg("=======================================");

    if (!is_elevated()) {
        msg("error: run elevated (Administrator/SYSTEM).");
        return 1;
    }
    if (!uefi_available()) {
        msg("error: UEFI variables not available (legacy BIOS boot? not on"
            " UEFI Windows?).");
        return 1;
    }
    if (!confirm_yes(argc, argv)) {
        msg("This writes to UEFI NVRAM Secure Boot variables (KEK/db%s).",
            (dbx || dbxsvn || dbx2024) ? "/dbx" : "");
        msg("Re-run with --yes to proceed.");
        return 2;
    }

    /* ---- KEK ---- */
    if (!dbonly) {
        if (cert_present_in(L"KEK", G_EFI,
                            "Microsoft Corporation KEK 2K CA 2023")) {
            msg("  KEK: 2K CA 2023 already present, skipping.");
        } else {
            pkbuf = read_var(L"PK", G_EFI, &n, NULL);
            if (!pkbuf) {
                msg("  KEK: cannot read PK - skipping KEK update.");
            } else {
                ke = find_kek_update(pkbuf, n, &pki);
                if (!ke) {
                    msg("  KEK: PK '%ls' not in Microsoft vendor map -",
                        pki.saw_cert ? pki.cn : L"?");
                    msg("       no signed KEK update for this device."
                        "  Use 'genpe apply KEK <file>' with an OEM"
                        " payload.");
                } else {
                    msg("  KEK: PK is '%ls', using %s",
                        pki.saw_cert ? pki.cn : L"?", ke->path);
                    fails += apply_payload(L"KEK", G_EFI, ke->data, ke->len,
                                           "KEK 2K CA 2023");
                    if (cert_present_in(L"KEK", G_EFI,
                                        "Microsoft Corporation KEK 2K CA 2023"))
                        msg("    verified: KEK 2K CA 2023 enrolled");
                    else
                        msg("    ! write reported success but cert not"
                            " visible yet (may need reboot)");
                }
                free(pkbuf);
            }
        }
    }

    /* ---- db ---- */
    if (!kekonly) {
        struct { const char *cert; const unsigned char *d; unsigned int l;
                 const char *desc; int on; } jobs[3];
        jobs[0].cert = "Windows UEFI CA 2023";
        jobs[0].d = g_db_win2023; jobs[0].l = sizeof(g_db_win2023);
        jobs[0].desc = "db/windows2023"; jobs[0].on = 1;
        jobs[1].cert = "Microsoft UEFI CA 2023";
        jobs[1].d = g_db_3p2023; jobs[1].l = sizeof(g_db_3p2023);
        jobs[1].desc = "db/3p2023"; jobs[1].on = 1;
        jobs[2].cert = "Microsoft Option ROM UEFI CA 2023";
        jobs[2].d = g_db_orom2023; jobs[2].l = sizeof(g_db_orom2023);
        jobs[2].desc = "db/orom2023"; jobs[2].on = orom;

        for (i = 0; i < 3; i++) {
            if (!jobs[i].on) continue;
            if (cert_present_in(L"db", G_IMGDB, jobs[i].cert)) {
                msg("  db: %s already present, skipping.", jobs[i].cert);
                continue;
            }
            fails += apply_payload(L"db", G_IMGDB, jobs[i].d, jobs[i].l,
                                   jobs[i].desc);
            msg("    %s", cert_present_in(L"db", G_IMGDB, jobs[i].cert)
                ? "verified" : "! not visible yet (may need reboot)");
        }
    }

    /* ---- dbx (explicit opt-in only) ---- */
    if (dbx || dbxsvn || dbx2024) {
        if (!cert_present_in(L"db", G_IMGDB, "Windows UEFI CA 2023")) {
            msg("  dbx: refusing - Windows UEFI CA 2023 is not enrolled in db.");
            msg("       Apply db updates first or the device may not boot.");
            fails++;
        } else {
            if (dbx)
                fails += apply_payload(L"dbx", G_IMGDB, g_dbx_update,
                                       sizeof(g_dbx_update), "dbx/update");
            if (dbxsvn) {
                msg("  ! DBXUpdateSVN revokes pre-2023 Windows boot managers"
                    " via SVN.");
                msg("    Ensure a Windows UEFI CA 2023 signed boot manager is"
                    " installed on the ESP before rebooting.");
                fails += apply_payload(L"dbx", G_IMGDB, g_dbx_svn,
                                       sizeof(g_dbx_svn), "dbx/svn");
            }
            if (dbx2024) {
                msg("  ! DBXUpdate2024 revokes Windows Production PCA 2011"
                    " boot managers.");
                fails += apply_payload(L"dbx", G_IMGDB, g_dbx_2024,
                                       sizeof(g_dbx_2024), "dbx/2024");
            }
        }
    }

    /* ---- registry ---- */
    if (!nomark && !kekonly) {
        if (fails == 0) {
            msg("Marking running OS as updated:");
            mark_os(NULL, 0, 0, 0);
        } else {
            msg("Not marking OS (some firmware writes failed).");
        }
    }

    msg("%s", fails ? "Finished with failures - see above." :
        "All requested updates applied.");
    return fails ? 1 : 0;
}

static int cmd_mark_optin(int argc, WCHAR **argv, int pending)
{
    const WCHAR *drive = NULL;
    DWORD mask = OPTIN_MASK;
    int ms_optin = 0, i;

    for (i = 0; i < argc; i++) {
        if (!wcscmp(argv[i], L"--pending")) pending = 1;
        else if (!wcscmp(argv[i], L"--updated")) pending = 0;
        else if (!wcscmp(argv[i], L"--ms-optin")) ms_optin = 1;
        else if (!wcscmp(argv[i], L"--mask") && i + 1 < argc)
            mask = wcstoul(argv[++i], NULL, 0);
        else if (wcslen(argv[i]) >= 2 && argv[i][1] == L':' &&
                 ((argv[i][0] >= L'A' && argv[i][0] <= L'Z') ||
                  (argv[i][0] >= L'a' && argv[i][0] <= L'z')))
            drive = argv[i];
    }

    if (!is_elevated()) {
        msg("error: run elevated.");
        return 1;
    }
    return mark_os(drive, pending, mask, ms_optin);
}

static int cmd_dump(int argc, WCHAR **argv)
{
    const WCHAR *name = NULL, *file = NULL;
    unsigned int i;
    int a;
    char an[260];
    HANDLE f;
    DWORD w;

    for (a = 0; a < argc; a++) {
        if (!name) name = argv[a];
        else if (!file) file = argv[a];
    }
    if (!name) {
        msg("Embedded payloads (%u):", PAYLOAD_ITEM_COUNT);
        for (i = 0; i < PAYLOAD_ITEM_COUNT; i++)
            msg("  %-56s %6u bytes", g_payload_items[i].name,
                g_payload_items[i].len);
        return 0;
    }
    snprintf(an, sizeof(an), "%ls", name);
    for (i = 0; i < PAYLOAD_ITEM_COUNT; i++) {
        const char *base = strchr(g_payload_items[i].name, '/');
        if (!strcmp(g_payload_items[i].name, an) ||
            (base && !strcmp(base + 1, an)))
            break;
    }
    if (i == PAYLOAD_ITEM_COUNT) {
        msg("error: unknown payload '%ls'. Run 'genpe dump' for the list.",
            name);
        return 1;
    }
    if (!file) {
        msg("%s: %u bytes embedded. Give an output file to write it.",
            g_payload_items[i].name, g_payload_items[i].len);
        return 0;
    }
    f = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        msg("error: cannot create %ls", file);
        return 1;
    }
    WriteFile(f, g_payload_items[i].data, g_payload_items[i].len, &w, NULL);
    CloseHandle(f);
    msg("wrote %ls (%u bytes)", file, g_payload_items[i].len);
    return 0;
}

static int cmd_apply(int argc, WCHAR **argv)
{
    const WCHAR *var = NULL, *file = NULL;
    int replace = 0, i;
    HANDLE f;
    DWORD sz, rd;
    unsigned char *buf;
    LPCWSTR guid;
    DWORD err;

    for (i = 0; i < argc; i++) {
        if (!wcscmp(argv[i], L"--replace")) { replace = 1; continue; }
        if (!wcscmp(argv[i], L"--yes") || !wcscmp(argv[i], L"-y")) continue;
        if (!var) var = argv[i];
        else if (!file) file = argv[i];
    }
    if (!var || !file ||
        (wcscmp(var, L"PK") && wcscmp(var, L"KEK") &&
         wcscmp(var, L"db") && wcscmp(var, L"dbx"))) {
        msg("usage: genpe apply <PK|KEK|db|dbx> <signed.bin> [--replace] --yes");
        return 2;
    }
    if (!confirm_yes(argc, argv)) {
        msg("Re-run with --yes to write %ls.", var);
        return 2;
    }
    f = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { msg("error: open %ls", file); return 1; }
    sz = GetFileSize(f, NULL);
    buf = malloc(sz);
    if (!buf || !ReadFile(f, buf, sz, &rd, NULL) || rd != sz) {
        CloseHandle(f); free(buf); msg("error: read %ls", file); return 1;
    }
    CloseHandle(f);
    guid = (!wcscmp(var, L"db") || !wcscmp(var, L"dbx")) ? G_IMGDB : G_EFI;
    i = replace ? set_var_replace(var, guid, buf, sz, &err)
                : set_var_append(var, guid, buf, sz, &err);
    msg("%ls %ls -> %s (err %lu)", replace ? L"replace" : L"append", var,
        i ? "OK" : "FAILED", (unsigned long)err);
    free(buf);
    return i ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* ESP / 2023-signed boot manager update                               */
/* ------------------------------------------------------------------ */

/* read a file fully (cap 16MB) */
static unsigned char *slurp_file(const WCHAR *path, DWORD *outn)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    unsigned char *b;
    DWORD sz, rd = 0;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(f, NULL);
    if (sz > 16 * 1024 * 1024 || !(b = malloc(sz))) {
        CloseHandle(f); return NULL;
    }
    if (!ReadFile(f, b, sz, &rd, NULL) || rd != sz) {
        CloseHandle(f);
        free(b); return NULL;
    }
    CloseHandle(f);
    *outn = sz;
    return b;
}

/* trust-anchor check for Authenticode chain verification: accepts a CA
 * cert if it is enrolled in the device's db right now, or matches an
 * embedded 2023 CA (for offline analysis / pre-enrollment). */
struct anchor_ctx { const unsigned char *db; DWORD dblen; };
static const char *anchor_ok(const unsigned char *der, size_t len, void *vctx)
{
    struct anchor_ctx *c = vctx;
    unsigned char h[20];
    unsigned int i;
    const char *kn;
    sha1(der, len, h);
    kn = known_cert_name(h);
    if (c->db && var_has_cert(c->db, c->dblen, h))
        return kn ? kn : "enrolled CA";
    for (i = 0; i < CA_CERT_COUNT; i++)
        if (g_ca_certs[i].len == len &&
            !memcmp(g_ca_certs[i].der, der, len))
            return g_ca_certs[i].name ? g_ca_certs[i].name : "2023 CA";
    return NULL;
}

/* cryptographically verify a PE's Authenticode signature chains to a
 * Secure Boot CA.  Returns CA name or NULL. */
static const char *verify_efi(const WCHAR *path)
{
    DWORD n = 0;
    unsigned char *b = slurp_file(path, &n);
    struct anchor_ctx c = { NULL, 0 };
    const char *r;
    if (!b) return NULL;
    c.db = read_var(L"db", G_IMGDB, &c.dblen, NULL);
    r = efi_sig_verify(b, n, anchor_ok, &c);
    free((void *)c.db);
    free(b);
    return r;
}

/* boot-manager paths tried on an ESP, in priority order.  bootmgfw.efi is
 * x64, bootaa64.efi is ARM64; bootx64/bootaa64 under EFI\Boot\ are the
 * removable-media fallbacks.  esp_inject only touches paths that already
 * exist, so arch-appropriate files are never clobbered. */
static const WCHAR *const BOOT_RELS[] = {
    L"EFI\\Microsoft\\Boot\\bootmgfw.efi",
    L"EFI\\Microsoft\\Boot\\bootaa64.efi",
    L"EFI\\Boot\\bootx64.efi",
    L"EFI\\Boot\\bootaa64.efi",
};
#define NBOOT_RELS (sizeof(BOOT_RELS) / sizeof(BOOT_RELS[0]))

/* first existing boot-manager path under a volume root; returns index or -1 */
static int esp_boot_path(const WCHAR *volroot, WCHAR *out, int cap)
{
    size_t i;
    for (i = 0; i < NBOOT_RELS; i++) {
        _snwprintf(out, cap, L"%ls%ls", volroot, BOOT_RELS[i]);
        if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES)
            return (int)i;
    }
    return -1;
}

/* enumerate \\?\Volume{guid}\ paths containing a Windows boot manager */
static int find_windows_esps(WCHAR vols[][64], int max)
{
    WCHAR v[64], p[MAX_PATH];
    HANDLE h = FindFirstVolumeW(v, 64);
    int n = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (esp_boot_path(v, p, MAX_PATH) >= 0 && n < max)
            wcscpy(vols[n++], v);
    } while (FindNextVolumeW(h, v, 64) && n < max);
    FindVolumeClose(h);
    return n;
}

/* enumerate all volumes that have an EFI directory (for restore) */
static int find_esps_all(WCHAR vols[][64], int max)
{
    WCHAR v[64], p[MAX_PATH];
    HANDLE h = FindFirstVolumeW(v, 64);
    int n = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        _snwprintf(p, MAX_PATH, L"%lsEFI", v);
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES && n < max)
            wcscpy(vols[n++], v);
    } while (FindNextVolumeW(h, v, 64) && n < max);
    FindVolumeClose(h);
    return n;
}

static int esp_inject(const WCHAR *volroot, const WCHAR *donor, int *wrote)
{
    size_t i;
    for (i = 0; i < NBOOT_RELS; i++) {
        WCHAR dst[MAX_PATH], bak[MAX_PATH];
        _snwprintf(dst, MAX_PATH, L"%ls%ls", volroot, BOOT_RELS[i]);
        if (GetFileAttributesW(dst) == INVALID_FILE_ATTRIBUTES) continue;
        _snwprintf(bak, MAX_PATH, L"%ls.genpebak", dst);
        if (g_dryrun) {
            msg("      [dry-run] would update %ls (backup %ls)", dst, bak);
            (*wrote)++;
            continue;
        }
        if (GetFileAttributesW(bak) == INVALID_FILE_ATTRIBUTES &&
            !CopyFileW(dst, bak, TRUE)) {
            msg("      ! backup of %ls failed (err %lu) - skipping", dst,
                (unsigned long)GetLastError());
            continue;
        }
        if (!CopyFileW(donor, dst, FALSE)) {
            msg("      ! write to %ls failed (err %lu)", dst,
                (unsigned long)GetLastError());
            continue;
        }
        msg("      updated %ls (backup: %ls)", dst, bak);
        (*wrote)++;
    }
    return *wrote > 0;
}

/* is the anchor CA a 2023 CA?  verify_efi returns the anchor's name; a
 * 2011-signed file may chain to an enrolled 2011 CA - we want 2023 only. */
static int is_2023_ca(const char *n)
{
    return n && strstr(n, "2023") != NULL;
}

/* candidate donor paths for a 2023-signed bootmgfw.efi: updated Windows
 * staging dirs, install media, and other ESPs that already carry one */
static int find_donor(WCHAR out[MAX_PATH])
{
    WCHAR letter, p[MAX_PATH], vols[16][64];
    static const WCHAR *rel[] = {
        L"\\Windows\\Boot\\EFI\\bootmgfw.efi",
        L"\\Windows\\Boot\\EFI\\bootaa64.efi",
        L"\\efi\\microsoft\\boot\\bootmgfw.efi",
        L"\\efi\\microsoft\\boot\\bootaa64.efi",
    };
    size_t r;
    int nv, i;
    for (letter = L'C'; letter <= L'Z'; letter++)
        for (r = 0; r < sizeof(rel) / sizeof(rel[0]); r++) {
            _snwprintf(p, MAX_PATH, L"%lc:%ls", letter, rel[r]);
            if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES &&
                is_2023_ca(verify_efi(p))) {
                wcscpy(out, p);
                return 1;
            }
        }
    nv = find_windows_esps(vols, 16);
    for (i = 0; i < nv; i++) {
        if (esp_boot_path(vols[i], p, MAX_PATH) >= 0 &&
            is_2023_ca(verify_efi(p))) {
            wcscpy(out, p);
            return 1;
        }
    }
    return 0;
}

static int cmd_bootfiles(int argc, WCHAR **argv)
{
    const WCHAR *from = NULL, *espletter = NULL;
    int force = 0, i, wrote = 0, done = 0;
    WCHAR donor[MAX_PATH], vols[16][64];
    int nvol = 0, nold = 0, outdated[16];

    for (i = 0; i < argc; i++) {
        if (!wcscmp(argv[i], L"--from") && i + 1 < argc) from = argv[++i];
        else if (!wcscmp(argv[i], L"--esp") && i + 1 < argc) espletter = argv[++i];
        else if (!wcscmp(argv[i], L"--force")) force = 1;
    }

    msg("Install a 2023-signed Windows boot manager on the ESP");
    msg("=====================================================");

    if (!is_elevated()) { msg("error: run elevated."); return 1; }

    /* first (read-only): check what each ESP already has */
    if (espletter) {
        _snwprintf(vols[0], 64, L"%ls\\", espletter);
        nvol = 1;
    } else {
        nvol = find_windows_esps(vols, 16);
        if (!nvol) {
            msg("error: no EFI System Partition with a Windows boot manager"
                " found.");
            return 1;
        }
    }
    for (i = 0; i < nvol; i++) {
        WCHAR p[MAX_PATH];
        const char *ca;
        if (esp_boot_path(vols[i], p, MAX_PATH) < 0) {
            msg("  ESP %d %ls: no boot manager found - skipping", i + 1,
                vols[i]);
            outdated[i] = 0;
            continue;
        }
        ca = verify_efi(p);
        outdated[i] = !is_2023_ca(ca);
        if (!outdated[i])
            msg("  ESP %d %ls: already 2023-signed (%s)", i + 1, vols[i], ca);
        else
            msg("  ESP %d %ls: %s", i + 1, vols[i],
                ca ? "outdated signature" : "unsigned/unknown");
        nold += outdated[i];
    }
    if (!nold) {
        msg("All ESPs already have a 2023-signed boot manager.");
        return 0;
    }
    msg("%d ESP(s) need a 2023-signed boot manager.", nold);

    if (!confirm_yes(argc, argv)) {
        msg("This copies boot files onto EFI System Partitions.");
        msg("Re-run with --yes to proceed.");
        return 2;
    }

    /* donor file */
    if (from) {
        DWORD at = GetFileAttributesW(from);
        if (at == INVALID_FILE_ATTRIBUTES) {
            msg("error: donor path %ls not found", from);
            return 1;
        }
        if (at & FILE_ATTRIBUTE_DIRECTORY)
            _snwprintf(donor, MAX_PATH, L"%ls\\bootmgfw.efi", from);
        else
            wcscpy(donor, from);
        if (GetFileAttributesW(donor) == INVALID_FILE_ATTRIBUTES) {
            msg("error: no bootmgfw.efi at %ls", donor);
            return 1;
        }
        if (!force) {
            const char *ca = verify_efi(donor);
            if (!ca) {
                msg("error: %ls has no valid signature chaining to a"
                    " Secure Boot CA (%s).", donor, sigcheck_last_error());
                msg("       (--force to override; get one from an updated"
                    " Windows' \\Windows\\Boot\\EFI)");
                return 1;
            }
            if (!is_2023_ca(ca)) {
                msg("error: %ls is signed by \"%s\" - not a 2023 CA.",
                    donor, ca);
                return 1;
            }
            msg("  donor signature verified: chains to \"%s\"", ca);
        }
    } else {
        if (!find_donor(donor)) {
            msg("error: no 2023-signed bootmgfw.efi found on any"
                " \\Windows\\Boot\\EFI or boot media ESP.");
            msg("       Supply one with --from <dir-or-file> (e.g. an updated"
                " Windows install or install media).");
            return 1;
        }
    }
    msg("  donor: %ls", donor);

    /* db must trust the signer or the machine will not boot */
    if (!cert_present_in(L"db", G_IMGDB, "Windows UEFI CA 2023") &&
        !cert_present_in(L"db", G_IMGDB, "Microsoft UEFI CA 2023") &&
        !force) {
        msg("error: no 2023 UEFI CA is enrolled in db yet.");
        msg("       Run 'genpe install --yes' first, or --force to override.");
        return 1;
    }

    /* update only the outdated ESPs */
    for (i = 0; i < nvol; i++) {
        if (!outdated[i]) continue;
        msg("  ESP %d: %ls", i + 1, vols[i]);
        wrote = 0;
        if (esp_inject(vols[i], donor, &wrote)) done = 1;
    }

    if (done) {
        msg("Boot manager updated on %s ESP(s).", espletter ? "the" : "all found");
        msg("NOTE: boot-file changes alter Secure Boot measurements - have");
        msg("      BitLocker recovery keys ready for the first reboot.");
        return 0;
    }
    msg("No boot files were updated.");
    return 1;
}

/* restore .genpebak boot-file backups on ESPs */
static int cmd_restore(int argc, WCHAR **argv)
{
    const WCHAR *espletter = NULL;
    WCHAR vols[16][64], p[MAX_PATH], bak[MAX_PATH];
    int i, nvol, nrest = 0;

    for (i = 0; i < argc; i++)
        if (!wcscmp(argv[i], L"--esp") && i + 1 < argc) espletter = argv[++i];

    msg("Restore backed-up boot files (.genpebak)");
    msg("======================================");

    if (!is_elevated()) { msg("error: run elevated."); return 1; }

    if (espletter) {
        _snwprintf(vols[0], 64, L"%ls\\", espletter);
        nvol = 1;
    } else {
        nvol = find_esps_all(vols, 16);
        if (!nvol) { msg("error: no EFI System Partitions found."); return 1; }
    }

    if (!confirm_yes(argc, argv)) {
        msg("This overwrites boot files with their .genpebak backups.");
        msg("Re-run with --yes to proceed.");
        return 2;
    }

    for (i = 0; i < nvol; i++) {
        size_t k;
        for (k = 0; k < NBOOT_RELS; k++) {
            _snwprintf(p, MAX_PATH, L"%ls%ls", vols[i], BOOT_RELS[k]);
            _snwprintf(bak, MAX_PATH, L"%ls.genpebak", p);
            if (GetFileAttributesW(bak) == INVALID_FILE_ATTRIBUTES) continue;
            if (g_dryrun) {
                msg("  [dry-run] would restore %ls -> %ls", bak, p);
            } else if (CopyFileW(bak, p, FALSE)) {
                msg("  restored %ls", p);
            } else {
                msg("  ! restore of %ls failed (err %lu)", p,
                    (unsigned long)GetLastError());
                continue;
            }
            nrest++;
        }
    }
    msg(nrest ? "Restored %d file(s). Backups (.genpebak) kept in place."
              : "No .genpebak backups found on the ESPs.", nrest);
    return nrest ? 0 : 1;
}

/* one-shot fleet mode: firmware install -> boot files -> OS mark.
 * optional positional drive letter marks that offline OS instead of the
 * running one.  --json emits a machine-readable summary line. */
static int cmd_auto(int argc, WCHAR **argv)
{
    const WCHAR *drive = NULL;
    WCHAR *iargs[8];
    int ni = 0, i, r_fw, r_bf, r_os = 0;
    const char *s_fw, *s_bf, *s_os;

    for (i = 0; i < argc; i++) {
        if (!wcscmp(argv[i], L"--drive") && i + 1 < argc)
            drive = argv[++i];
        else if (wcschr(argv[i], L':') && wcslen(argv[i]) <= 4 &&
                 argv[i][0] >= L'A' && argv[i][0] <= L'Z' &&
                 !drive)
            drive = argv[i];
    }

    msg("Auto mode: install certs -> update boot files -> mark OS%s",
        drive ? " (offline)" : "");
    msg("==========================================================");

    if (!confirm_yes(argc, argv)) {
        msg("Auto mode applies all updates. Re-run with --yes.");
        return 2;
    }
    if (!is_elevated()) { msg("error: run elevated."); return 1; }

    /* firmware: --no-mark when an offline drive is targeted so we don't
     * mark the running OS by mistake */
    iargs[ni++] = (WCHAR *)L"--yes";
    if (drive) iargs[ni++] = (WCHAR *)L"--no-mark";
    r_fw = cmd_install(ni, iargs);
    s_fw = r_fw == 0 ? "ok" : r_fw == 2 ? "skipped" : "fail";

    iargs[0] = (WCHAR *)L"--yes";
    r_bf = cmd_bootfiles(1, iargs);
    s_bf = r_bf == 0 ? "ok" : "fail";

    if (drive) {
        r_os = mark_os(drive, 0, 0, 0);
        s_os = r_os == 0 ? "ok" : "fail";
    } else {
        /* install already marked the running OS on success */
        s_os = r_fw == 0 ? "ok" : "fail";
    }

    msg("==========================================================");
    msg("Summary: firmware=%s bootfiles=%s os=%s", s_fw, s_bf, s_os);
    if (g_json)
        msg("{\"firmware\":\"%s\",\"bootfiles\":\"%s\",\"os\":\"%s\"}",
            s_fw, s_bf, s_os);
    return (r_fw || r_bf || r_os) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* minimal Win32 GUI (still system DLLs only)                          */
/* ------------------------------------------------------------------ */

#include <commctrl.h>

enum {
    IDC_STATUS = 1001, IDC_INSTALL, IDC_BOOTFILES, IDC_SCAN,
    IDC_MARK, IDC_OPTIN, IDC_DRIVE, IDC_LOG, IDC_REFRESH,
    IDC_AUTO, IDC_RESTORE
};

static HWND g_logedit, g_driveedit, g_hwnd;

/* append a UTF-8 line to the log pane (adds CRLF) */
static void gui_out(const char *s)
{
    WCHAR w[4096];
    char tmp[2200];
    size_t i, j;
    for (i = 0, j = 0; s[i] && j < sizeof(tmp) - 3; i++) {
        if (s[i] == '\n') { tmp[j++] = '\r'; tmp[j++] = '\n'; }
        else tmp[j++] = s[i];
    }
    tmp[j] = 0;
    MultiByteToWideChar(CP_UTF8, 0, tmp, -1, w, 4096);
    {
        int len = GetWindowTextLengthW(g_logedit);
        SendMessageW(g_logedit, EM_SETSEL, len, len);
        SendMessageW(g_logedit, EM_REPLACESEL, 0, (LPARAM)w);
        SendMessageW(g_logedit, EM_SCROLLCARET, 0, 0);
    }
}

static void gui_drive(WCHAR *out, int cap)
{
    GetWindowTextW(g_driveedit, out, cap);
    if (out[0] == 0) wcscpy(out, L"C:");
    else if (out[0] >= 'a' && out[0] <= 'z') out[0] -= 'a' - 'A';
}

static void gui_exec(int (*fn)(void))
{
    g_msgfn = gui_out;
    SetCursor(LoadCursorW(NULL, IDC_WAIT));
    fn();
    SetCursor(LoadCursorW(NULL, IDC_ARROW));
    g_msgfn = NULL;
    gui_out("\r\n");
}

static void gui_exec_argv(int (*fn)(int, WCHAR **), int argc, WCHAR **argv)
{
    g_msgfn = gui_out;
    SetCursor(LoadCursorW(NULL, IDC_WAIT));
    fn(argc, argv);
    SetCursor(LoadCursorW(NULL, IDC_ARROW));
    g_msgfn = NULL;
    gui_out("\r\n");
}

static int gui_yes(LPCWSTR what)
{
    return MessageBoxW(g_hwnd, what, L"GenPE - confirm",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

static int gui_mark_wrap(int c, WCHAR **v) { return cmd_mark_optin(c, v, 0); }
static int gui_optin_wrap(int c, WCHAR **v) { return cmd_mark_optin(c, v, 1); }

static LRESULT CALLBACK gui_wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_COMMAND) {
        WCHAR d[8];
        WCHAR *a[8];
        switch (LOWORD(wp)) {
        case IDC_STATUS:   gui_exec(cmd_status); break;
        case IDC_SCAN:     gui_exec(cmd_scan); break;
        case IDC_INSTALL:
            if (gui_yes(L"Write the 2023 CA certificates to UEFI KEK + db "
                        L"now?\n\n(append-only; existing keys are kept)")) {
                a[0] = L"--yes";
                gui_exec_argv(cmd_install, 1, a);
            }
            break;
        case IDC_BOOTFILES:
            if (gui_yes(L"Install the 2023-signed boot manager onto the "
                        L"ESP?\n\nHave BitLocker recovery keys ready before "
                        L"the next reboot.")) {
                a[0] = L"--yes";
                gui_exec_argv(cmd_bootfiles, 1, a);
            }
            break;
        case IDC_MARK:
            gui_drive(d, 8);
            a[0] = d;
            gui_exec_argv(gui_mark_wrap, 1, a);
            break;
        case IDC_OPTIN:
            gui_drive(d, 8);
            a[0] = d;
            gui_exec_argv(gui_optin_wrap, 1, a);
            break;
        case IDC_AUTO:
            if (gui_yes(L"Run the full update now?\n\n"
                        L"1. Install 2023 CA certificates (KEK + db)\n"
                        L"2. Update boot files on all ESPs\n"
                        L"3. Mark the running OS as updated\n\n"
                        L"BitLocker recovery keys recommended before reboot.")) {
                a[0] = L"--yes";
                gui_exec_argv(cmd_auto, 1, a);
            }
            break;
        case IDC_RESTORE:
            if (gui_yes(L"Restore boot files from .genpebak backups "
                        L"on all ESPs?")) {
                a[0] = L"--yes";
                gui_exec_argv(cmd_restore, 1, a);
            }
            break;
        }
    } else if (m == WM_DESTROY) {
        PostQuitMessage(0);
    }
    return DefWindowProcW(h, m, wp, lp);
}

static HWND mk(HWND parent, LPCWSTR cls, LPCWSTR txt, DWORD style,
               int x, int y, int w, int hgt, int id)
{
    return CreateWindowExW(0, cls, txt,
        style | WS_CHILD | WS_VISIBLE, x, y, w, hgt, parent,
        (HMENU)(UINT_PTR)id, NULL, NULL);
}

static int gui_main(void)
{
    WNDCLASSW wc;
    HWND h;
    HFONT mono, norm;
    MSG m;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = gui_wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"GenPEWindow";
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);

    g_hwnd = h = CreateWindowExW(0, L"GenPEWindow",
        L"GenPE - UEFI CA 2023 Secure Boot updater",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
        WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 520,
        NULL, NULL, wc.hInstance, NULL);

    norm = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    mono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                       0, 0, 0, 0, L"Consolas");

    mk(h, L"STATIC", L"Actions:", 0, 10, 10, 60, 20, -1);
    mk(h, L"BUTTON", L"Status", 0, 10, 32, 100, 26, IDC_STATUS);
    mk(h, L"BUTTON", L"Scan disks", 0, 116, 32, 100, 26, IDC_SCAN);
    mk(h, L"BUTTON", L"Install 2023 certs", 0, 222, 32, 130, 26, IDC_INSTALL);
    mk(h, L"BUTTON", L"Update boot files", 0, 358, 32, 130, 26, IDC_BOOTFILES);

    mk(h, L"STATIC", L"OS drive:", 0, 10, 66, 60, 20, -1);
    g_driveedit = mk(h, L"EDIT", L"C:", WS_BORDER | ES_AUTOHSCROLL,
                     72, 64, 40, 22, IDC_DRIVE);
    mk(h, L"BUTTON", L"Mark OS updated", 0, 118, 64, 130, 26, IDC_MARK);
    mk(h, L"BUTTON", L"Opt-in OS updates", 0, 254, 64, 130, 26, IDC_OPTIN);
    mk(h, L"BUTTON", L"Auto (all steps)", 0, 396, 64, 130, 26, IDC_AUTO);
    mk(h, L"BUTTON", L"Restore backups", 0, 532, 64, 130, 26, IDC_RESTORE);

    g_logedit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
        ES_AUTOVSCROLL,
        10, 100, 774, 360, h, (HMENU)IDC_LOG, NULL, NULL);

    {
        HWND c = NULL;
        for (c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
            SendMessageW(c, WM_SETFONT, (WPARAM)norm, 1);
        SendMessageW(g_logedit, WM_SETFONT, (WPARAM)mono, 1);
    }

    g_msgfn = gui_out;
    gui_out(is_elevated()
            ? "Running elevated - firmware + registry writes allowed.\r\n"
            : "NOT elevated - read-only. Restart as administrator.\r\n");
    g_msgfn = NULL;

    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}

/* ------------------------------------------------------------------ */

static int usage(void)
{
    msg(
"GenPE - UEFI CA 2023 Secure Boot updater (for Windows / WinPE)\n"
"\n"
"  genpe                             Launch the GUI (also: genpe gui)\n"
"  genpe status                      Show Secure Boot certs + OS servicing state\n"
"  genpe scan                        List Windows installs on attached disks\n"
"  genpe install --yes               Enroll KEK 2023 + db 2023 CAs, mark OS updated\n"
"      --orom                          also enroll Option ROM UEFI CA 2023\n"
"      --kek-only | --db-only          restrict which variables are updated\n"
"      --dbx [--dbx-svn] [--dbx-2024]  also apply dbx revocation updates\n"
"      --no-mark                       do not write OS registry state\n"
"  genpe mark [X:] [--pending]       Mark an OS Updated (or Pending) - running\n"
"                                    OS if no drive, offline OS at X:\\ otherwise\n"
"  genpe optin [X:] [--mask 0x5944]  Set AvailableUpdates so OS servicing applies\n"
"                                    the certs on next boot\n"
"  genpe bootfiles --yes             Copy a 2023-signed boot manager onto the ESP\n"
"      --from <dir-or-file>            donor bootmgfw.efi (auto-detected if omitted)\n"
"      --esp X:                        only this ESP (default: all Windows ESPs)\n"
"  genpe restore [--esp X:] [--yes]  Restore .genpebak boot-file backups\n"
"  genpe auto [X:] --yes [--json]    Full sequence: certs -> boot files -> OS mark\n"
"                                    (X: marks that offline OS instead)\n"
"  genpe dump [name [out.bin]]       List / extract an embedded signed payload\n"
"  genpe apply <PK|KEK|db|dbx> file  Apply an external signed payload (--yes;\n"
"                                    --replace to overwrite instead of append)\n"
"\n"
"Global flags: --dry-run (show writes without performing them), --json\n"
"(machine-readable summary for 'auto'), -v (debug).  x64 and ARM64 builds.\n"
"All firmware writes are authenticated append writes using Microsoft's signed\n"
"payloads (github.com/microsoft/secureboot_objects). KEK updates are matched\n"
"to the device's enrolled Platform Key. Requires admin + UEFI boot.");
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"-v") || !wcscmp(argv[i], L"--verbose"))
            g_verbose = 1;
        else if (!wcscmp(argv[i], L"--dry-run"))
            g_dryrun = 1;
        else if (!wcscmp(argv[i], L"--json"))
            g_json = 1;
    }

    grab_privileges();

    if (argc < 2) return gui_main();
    if (!wcscmp(argv[1], L"gui")) return gui_main();
    if (!wcscmp(argv[1], L"status")) return cmd_status();
    if (!wcscmp(argv[1], L"scan")) return cmd_scan();
    if (!wcscmp(argv[1], L"install")) return cmd_install(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"mark")) return cmd_mark_optin(argc - 2, argv + 2, 0);
    if (!wcscmp(argv[1], L"optin")) return cmd_mark_optin(argc - 2, argv + 2, 1);
    if (!wcscmp(argv[1], L"bootfiles")) return cmd_bootfiles(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"restore")) return cmd_restore(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"auto")) return cmd_auto(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"dump")) return cmd_dump(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"apply")) return cmd_apply(argc - 2, argv + 2);
    if (!wcscmp(argv[1], L"help") || !wcscmp(argv[1], L"-h") ||
        !wcscmp(argv[1], L"--help") || !wcscmp(argv[1], L"/?"))
        return usage();
    msg("unknown command '%ls'", argv[1]);
    return usage();
}
