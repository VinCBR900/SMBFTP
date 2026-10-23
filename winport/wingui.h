/*
 * wingui.h - Win32 GUI declarations for WinSMBFTP.exe, built with TCC
 *
 * Version : 1.6
 * Author  : VinCBR900
 *
 * Purpose
 *   winmini.h declares only the Winsock/kernel32 subset smbftp.c and libdsm
 *   need. winsmbftp.c additionally needs windowing: a message loop and a
 *   handful of Common Controls. This header declares that subset by hand,
 *   the same way winmini.h does for Winsock, instead of pulling in TCC's own
 *   bundled <windows.h>/<commctrl.h> - so it stays kept separate from
 *   winmini.h, which smb_engine.c/smbftp.c (and libdsm's own winsock2.h
 *   shim) also include: there is no reason to put ListView/toolbar message
 *   constants on that shared path.
 *
 *   Only CreateWindowExA-built controls are declared (STATIC/EDIT/BUTTON are
 *   built into user32 already; ListView/toolbar/status bar/progress bar
 *   classes are registered by InitCommonControlsEx): this project has no
 *   resource compiler, so winsmbftp.c never uses a DIALOGEX template - every
 *   window, including the Connect window, is built the same way the main
 *   frame is.
 *
 *   This file relies on winmini.h having already been included (by
 *   smb_engine.h, which winsmbftp.c includes first) for two things: the
 *   <stddef.h>/<stdint.h> includes that make TCC define the __stdcall macro
 *   at all (without them, "__stdcall" is just an unknown identifier to TCC's
 *   parser - found the hard way), and SMB_STDCALL itself, reused here for
 *   every declaration below rather than inventing a second name for the same
 *   calling convention.
 *
 * Usage
 *   #include "smb_engine.h" first (brings in winmini.h), then this header.
 *   Link requirements (see build.cmd's "gui" target):
 *     user32, comctl32  -> user32.def, comctl32.def (supplied, next to
 *                          smbftp.c - same place as ws2_32.def)
 *     kernel32 / msvcrt  -> shipped with TCC (GetModuleHandleA, GetLastError
 *                           need no .def, same as the kernel32 calls already
 *                           used via winmini.h)
 *   A side-car WinSMBFTP.exe.manifest next to the built exe asks Windows to
 *   use ComCtl32 v6 (the themed look) for these controls; no resource
 *   compiler is involved, Windows loads a same-named ".manifest" file next
 *   to the exe on its own.
 *
 * History
 *   1.5  2026-10-18  Added GetOpenFileNameA/GetSaveFileNameA and OPENFILENAMEA
 *                    (comdlg32, new comdlg32.def) for Get/Put's file dialogs;
 *                    the progress bar class and PBM_SETPOS/PBM_SETRANGE, and
 *                    LVM_GETITEMA/LVM_GETNEXTITEM/LVNI_SELECTED so Get can
 *                    find the ListView's selected row (comctl32, already
 *                    linked), and SW_HIDE (the progress bar stays hidden
 *                    outside a transfer). Values checked against Wine's
 *                    commdlg.h/commctrl.h, same reasoning as 1.1.
 *   1.6  2026-10-23  Added WaitForSingleObject, WAIT_OBJECT_0 and WAIT_TIMEOUT
 *                    (kernel32, auto-linked): winsmbftp.c waits a few seconds
 *                    for its worker thread at exit before closing the SMB
 *                    session. Values are the standard Win32 ones.
 *   1.4  2026-10-17  Added OutputDebugStringA (kernel32, auto-linked). Not
 *                    for correctness - for testing winsmbftp.c's threaded
 *                    jobs without depending on screen captures of a Wine
 *                    session, which turned out to be unreliable in the
 *                    environment used for this (see archive/REGRESSION.md).
 *                    Also doubles as real instrumentation for the person
 *                    building this on actual Windows later, with DebugView
 *                    or a debugger attached.
 *   1.3  2026-10-15  Added CreateThread/CloseHandle (kernel32, auto-linked -
 *                    smb_engine's connect/list calls are blocking, so
 *                    winsmbftp.c runs them off a worker thread) and
 *                    PostMessageA/GetWindowTextA/SetWindowTextA/EnableWindow/
 *                    SetForegroundWindow (user32, added to user32.def) for
 *                    the worker thread's completion message and the Connect
 *                    window. Also WM_APP and ES_PASSWORD. Signatures checked
 *                    against Wine's winbase.h/winuser.h, same reasoning as 1.1.
 *   1.2  2026-10-15  Fixed a real bug in 1.1's own history comment below: it
 *                    listed several Win32 macro-name prefixes separated by
 *                    slashes, and two of them landed back to back as an
 *                    asterisk immediately followed by a slash - which closes
 *                    a C comment early, so everything after it in that
 *                    comment block silently became code and failed to
 *                    compile. Caught by actually building winsmbftp.c with
 *                    TCC (see archive/REGRESSION.md) rather than assuming
 *                    the 1.1 edit was fine because the rest of the file
 *                    looked right. (This entry itself avoids typing that
 *                    same character sequence, for the obvious reason.)
 *   1.1  2026-10-14  Added the toolbar (ToolbarWindow32), ListView report
 *                    view (SysListView32) and WM_NOTIFY/NM_DBLCLK pieces for
 *                    the frame chrome. TBBUTTON/LVITEMA/LVCOLUMNA/NMHDR/
 *                    NMITEMACTIVATE and the TB_, LVM_, LVS_, LVCF_ and NM_
 *                    values were checked against Wine's own windows/commctrl.h
 *                    (installed in this environment for exactly this reason)
 *                    rather than taken from memory, since a wrong message
 *                    number or struct layout here would be a silent bug, not
 *                    a compile error.
 *   1.0  2026-10-14  Initial version: base Win32 types, window class/message
 *                    loop, and enough of comctl32 (InitCommonControlsEx, the
 *                    status bar class) for a minimal frame window. Verified
 *                    with the real win32-targeting TCC (built from source,
 *                    see archive/REGRESSION.md) running under Wine with a
 *                    virtual display - not just "compiles".
 */
#ifndef SMBFTP_WINGUI_H
#define SMBFTP_WINGUI_H

#ifndef _WIN32
#error wingui.h is for Windows builds only
#endif

/* ------------------------------------------------------------------------ */
/* Base types (the small subset windows.h would otherwise provide)          */
/* ------------------------------------------------------------------------ */

typedef int            BOOL;
typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef unsigned long   DWORD;      /* 32 bits on Win32 and Win64, as winmini.h's u_long */
typedef long            LONG;
typedef unsigned int    UINT;
typedef void            *HANDLE;
typedef HANDLE           HWND;
typedef HANDLE           HINSTANCE;
typedef HANDLE           HMODULE;
typedef HANDLE           HICON;
typedef HANDLE           HCURSOR;
typedef HANDLE           HBRUSH;
typedef HANDLE           HMENU;
typedef HANDLE           HDC;
typedef UINT             WPARAM;    /* classic (non pointer-widened) 32-bit ABI, */
typedef LONG             LPARAM;    /* matching the i386-win32 target this project builds */
typedef LONG             LRESULT;
typedef const char      *LPCSTR;
typedef char             *LPSTR;

#define TRUE  1
#define FALSE 0

/* MAKEINTRESOURCEA - turn a numeric resource id into the LPCSTR shape the
 * *A functions below expect (LoadCursorA(NULL, IDC_ARROW) and similar) */
#define MAKEINTRESOURCEA(i)  ((LPCSTR)(uintptr_t)(unsigned short)(i))
#define IDC_ARROW            MAKEINTRESOURCEA(32512)
#define IDI_APPLICATION      MAKEINTRESOURCEA(32512)

typedef struct tagPOINT { LONG x, y; } POINT;
typedef struct tagRECT  { LONG left, top, right, bottom; } RECT;

typedef struct tagMSG {
    HWND    hwnd;
    UINT    message;
    WPARAM  wParam;
    LPARAM  lParam;
    DWORD   time;
    POINT   pt;
} MSG;

typedef LRESULT (SMB_STDCALL *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagWNDCLASSEXA {
    UINT       cbSize;
    UINT       style;
    WNDPROC    lpfnWndProc;
    int        cbClsExtra;
    int        cbWndExtra;
    HINSTANCE  hInstance;
    HICON      hIcon;
    HCURSOR    hCursor;
    HBRUSH     hbrBackground;
    LPCSTR     lpszMenuName;
    LPCSTR     lpszClassName;
    HICON      hIconSm;
} WNDCLASSEXA;

/* ------------------------------------------------------------------------ */
/* Window / class styles, messages, show commands                          */
/* ------------------------------------------------------------------------ */

#define CS_VREDRAW            0x0001
#define CS_HREDRAW            0x0002

#define WS_OVERLAPPED         0x00000000UL
#define WS_CAPTION            0x00C00000UL
#define WS_SYSMENU            0x00080000UL
#define WS_THICKFRAME         0x00040000UL
#define WS_MINIMIZEBOX        0x00020000UL
#define WS_MAXIMIZEBOX        0x00010000UL
#define WS_OVERLAPPEDWINDOW   (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | \
                                WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
#define WS_VISIBLE            0x10000000UL
#define WS_CHILD              0x40000000UL
#define WS_CLIPCHILDREN       0x02000000UL
#define WS_CLIPSIBLINGS       0x04000000UL
#define WS_BORDER             0x00800000UL
#define CW_USEDEFAULT         ((int)0x80000000)

#define SW_HIDE               0
#define SW_SHOW               5
#define SW_SHOWDEFAULT        10

/* LOWORD/HIWORD - split a 32-bit message parameter into its two 16-bit
 * halves, e.g. LOWORD(wParam) on WM_COMMAND is the control/menu id */
#define LOWORD(l)  ((WORD)((uintptr_t)(l) & 0xffff))
#define HIWORD(l)  ((WORD)(((uintptr_t)(l) >> 16) & 0xffff))

#define WM_CREATE             0x0001
#define WM_DESTROY            0x0002
#define WM_SIZE               0x0005
#define WM_CLOSE              0x0010
#define WM_COMMAND            0x0111
#define WM_NOTIFY             0x004E
#define WM_USER               0x0400
#define WM_APP                0x8000

#define COLOR_WINDOW          5
#define COLOR_BTNFACE         15
/* class background brush from a system color, the standard Win32 idiom */
#define COLOR_BRUSH(c)        ((HBRUSH)(uintptr_t)((c) + 1))

#define MB_OK                 0x00000000UL
#define MB_ICONERROR          0x00000010UL

/* ------------------------------------------------------------------------ */
/* user32.dll                                                                */
/* ------------------------------------------------------------------------ */

unsigned short SMB_STDCALL RegisterClassExA(const WNDCLASSEXA *);
HWND           SMB_STDCALL CreateWindowExA(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int,
                                           HWND, HMENU, HINSTANCE, void *);
LRESULT        SMB_STDCALL DefWindowProcA(HWND, UINT, WPARAM, LPARAM);
BOOL           SMB_STDCALL DestroyWindow(HWND);
BOOL           SMB_STDCALL ShowWindow(HWND, int);
BOOL           SMB_STDCALL UpdateWindow(HWND);
BOOL           SMB_STDCALL GetMessageA(MSG *, HWND, UINT, UINT);
BOOL           SMB_STDCALL TranslateMessage(const MSG *);
LRESULT        SMB_STDCALL DispatchMessageA(const MSG *);
void           SMB_STDCALL PostQuitMessage(int);
HCURSOR        SMB_STDCALL LoadCursorA(HINSTANCE, LPCSTR);
HICON          SMB_STDCALL LoadIconA(HINSTANCE, LPCSTR);
int            SMB_STDCALL MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
BOOL           SMB_STDCALL GetClientRect(HWND, RECT *);
BOOL           SMB_STDCALL MoveWindow(HWND, int, int, int, int, BOOL);
LRESULT        SMB_STDCALL SendMessageA(HWND, UINT, WPARAM, LPARAM);
BOOL           SMB_STDCALL PostMessageA(HWND, UINT, WPARAM, LPARAM);
int            SMB_STDCALL GetWindowTextA(HWND, LPSTR, int);
BOOL           SMB_STDCALL SetWindowTextA(HWND, LPCSTR);
BOOL           SMB_STDCALL EnableWindow(HWND, BOOL);
BOOL           SMB_STDCALL SetForegroundWindow(HWND);

/* ------------------------------------------------------------------------ */
/* kernel32.dll (auto-linked by TCC, same as GetTickCount etc in winmini.h) */
/* ------------------------------------------------------------------------ */

HINSTANCE      SMB_STDCALL GetModuleHandleA(LPCSTR);
DWORD          SMB_STDCALL GetLastError(void);

/* a worker-thread entry point: DWORD return, one void* parameter, __stdcall */
typedef DWORD (SMB_STDCALL *THREAD_START)(void *);

HANDLE         SMB_STDCALL CreateThread(void *sec_attrs, DWORD stack_size,
                                         THREAD_START start, void *param,
                                         DWORD creation_flags, DWORD *out_tid);
BOOL           SMB_STDCALL CloseHandle(HANDLE);
DWORD          SMB_STDCALL WaitForSingleObject(HANDLE, DWORD);
#define WAIT_OBJECT_0   0
#define WAIT_TIMEOUT    0x102
void           SMB_STDCALL OutputDebugStringA(LPCSTR);

/* ------------------------------------------------------------------------ */
/* comctl32.dll - Common Controls                                           */
/* ------------------------------------------------------------------------ */

typedef struct tagINITCOMMONCONTROLSEX {
    DWORD dwSize;
    DWORD dwICC;
} INITCOMMONCONTROLSEX;

#define ICC_LISTVIEW_CLASSES     0x00000001   /* ListView, header            */
#define ICC_BAR_CLASSES            0x00000004   /* toolbar, status bar, trackbar */
#define ICC_PROGRESS_CLASS           0x00000020

BOOL SMB_STDCALL InitCommonControlsEx(const INITCOMMONCONTROLSEX *);

#define STATUSCLASSNAME  "msctls_statusbar32"
#define SB_SETTEXTA      (WM_USER + 1)

/* ------------------------------------------------------------------------ */
/* EDIT control (built into user32; the address bar uses it)                */
/* ------------------------------------------------------------------------ */

#define ES_AUTOHSCROLL   0x0080
#define ES_PASSWORD      0x0020
#define ES_READONLY      0x0800

/* ------------------------------------------------------------------------ */
/* Toolbar (comctl32 "ToolbarWindow32"), text-only buttons - no icons: this  */
/* build has no resource compiler and no image list                         */
/* ------------------------------------------------------------------------ */

#define TOOLBARCLASSNAME  "ToolbarWindow32"
#define TBSTYLE_BUTTON    0x0000
#define TBSTYLE_SEP       0x0001
#define TBSTYLE_FLAT      0x0800
#define TBSTYLE_LIST      0x1000
#define TBSTATE_ENABLED   0x04
#define I_IMAGENONE       (-2)

#define TB_ADDBUTTONSA        (WM_USER + 20)
#define TB_BUTTONSTRUCTSIZE   (WM_USER + 30)
#define TB_AUTOSIZE           (WM_USER + 33)

/* bReserved is BYTE[2] only on a 32-bit target (BYTE[6] on 64-bit) - fine
 * here since wingui.h is i386-win32 only, see the #error at the top */
typedef struct tagTBBUTTON {
    int   iBitmap;
    int   idCommand;
    BYTE  fsState;
    BYTE  fsStyle;
    BYTE  bReserved[2];
    DWORD dwData;
    LONG  iString;        /* a string pointer cast in here directly, which
                            * TBBUTTON.iString documents as supported, is
                            * simpler than the indirect TB_ADDSTRINGA pool */
} TBBUTTON;

/* ------------------------------------------------------------------------ */
/* ListView (comctl32 "SysListView32"), report view only                    */
/* ------------------------------------------------------------------------ */

#define WC_LISTVIEWA  "SysListView32"

#define LVS_REPORT             0x0001
#define LVS_SHOWSELALWAYS      0x0008
#define LVS_EX_FULLROWSELECT   0x00000020

#define LVM_FIRST                      0x1000
#define LVM_SETITEMA                   (LVM_FIRST + 6)
#define LVM_INSERTITEMA                (LVM_FIRST + 7)
#define LVM_DELETEALLITEMS             (LVM_FIRST + 9)
#define LVM_INSERTCOLUMNA              (LVM_FIRST + 27)
#define LVM_GETITEMTEXTA               (LVM_FIRST + 45)
#define LVM_SETEXTENDEDLISTVIEWSTYLE   (LVM_FIRST + 54)

#define LVCF_TEXT      0x0004
#define LVCF_WIDTH     0x0002
#define LVCF_SUBITEM   0x0008
#define LVIF_TEXT      0x0001
#define LVIF_PARAM     0x0004

/* trailing fields LVITEMA/LVCOLUMNA grew over the years (group view,
 * Vista+); included in full, even though this project only ever sets
 * LVIF_TEXT/LVCF_TEXT|WIDTH|SUBITEM, because comctl32 v6 (this build's
 * manifest asks for it) expects the struct at its full size - truncating it
 * risks comctl32 touching memory past a shorter struct regardless of mask */
typedef unsigned int *PUINT;
typedef int           *PINT;

typedef struct tagLVCOLUMNA {
    UINT   mask;
    int    fmt;
    int    cx;
    LPSTR  pszText;
    int    cchTextMax;
    int    iSubItem;
    int    iImage;
    int    iOrder;
    int    cxMin;
    int    cxDefault;
    int    cxIdeal;
} LVCOLUMNA;

typedef struct tagLVITEMA {
    UINT   mask;
    int    iItem;
    int    iSubItem;
    UINT   state;
    UINT   stateMask;
    LPSTR  pszText;
    int    cchTextMax;
    int    iImage;
    LPARAM lParam;
    int    iIndent;
    int    iGroupId;
    UINT   cColumns;
    PUINT  puColumns;
    PINT   piColFmt;
    int    iGroup;
} LVITEMA;

/* ------------------------------------------------------------------------ */
/* WM_NOTIFY (the ListView's double-click notification uses this)           */
/* ------------------------------------------------------------------------ */

typedef struct tagNMHDR {
    HWND hwndFrom;
    UINT idFrom;         /* UINT_PTR in the real header; same size as UINT on
                           * the 32-bit target this project builds */
    UINT code;
} NMHDR;

typedef struct tagNMITEMACTIVATE {
    NMHDR  hdr;
    int    iItem;
    int    iSubItem;
    UINT   uNewState;
    UINT   uOldState;
    UINT   uChanged;
    POINT  ptAction;
    LPARAM lParam;
    UINT   uKeyFlags;
} NMITEMACTIVATE;

#define NM_FIRST   ((UINT)0 - 0U)
#define NM_DBLCLK  ((UINT)(NM_FIRST - 3))

#define LVM_GETITEMA       (LVM_FIRST + 5)
#define LVM_GETNEXTITEM    (LVM_FIRST + 12)
#define LVNI_SELECTED      0x0002

/* ------------------------------------------------------------------------ */
/* Progress bar (comctl32 "msctls_progress32")                              */
/* ------------------------------------------------------------------------ */

#define PROGRESS_CLASS  "msctls_progress32"
#define PBM_SETRANGE    (WM_USER + 1)
#define PBM_SETPOS      (WM_USER + 2)

/* ------------------------------------------------------------------------ */
/* comdlg32.dll - the Open/Save common file dialogs                         */
/* ------------------------------------------------------------------------ */

#define OFN_READONLY          0x00000001
#define OFN_OVERWRITEPROMPT   0x00000002
#define OFN_HIDEREADONLY      0x00000004
#define OFN_PATHMUSTEXIST     0x00000800
#define OFN_FILEMUSTEXIST     0x00001000
#define OFN_EXPLORER          0x00080000

/* Full size, matching the real OPENFILENAMEA ABI (the dialog reads/writes
 * past lpTemplateName unconditionally in some Windows versions, same
 * truncation risk noted for LVITEMA/LVCOLUMNA above) - this program only
 * sets the fields up through Flags/lpstrTitle and leaves the rest zeroed */
typedef struct tagOPENFILENAMEA {
    DWORD  lStructSize;
    HWND   hwndOwner;
    HINSTANCE hInstance;
    LPCSTR lpstrFilter;
    LPSTR  lpstrCustomFilter;
    DWORD  nMaxCustFilter;
    DWORD  nFilterIndex;
    LPSTR  lpstrFile;
    DWORD  nMaxFile;
    LPSTR  lpstrFileTitle;
    DWORD  nMaxFileTitle;
    LPCSTR lpstrInitialDir;
    LPCSTR lpstrTitle;
    DWORD  Flags;
    WORD   nFileOffset;
    WORD   nFileExtension;
    LPCSTR lpstrDefExt;
    LPARAM lCustData;
    void  *lpfnHook;
    LPCSTR lpTemplateName;
    void  *pvReserved;
    DWORD  dwReserved;
    DWORD  FlagsEx;
} OPENFILENAMEA;

BOOL SMB_STDCALL GetOpenFileNameA(OPENFILENAMEA *);
BOOL SMB_STDCALL GetSaveFileNameA(OPENFILENAMEA *);

#endif /* SMBFTP_WINGUI_H */
