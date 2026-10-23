@echo off
rem ============================================================================
rem  build.cmd - build smbftp.exe (command line) and WinSMBFTP.exe (GUI) on
rem  Windows with TCC (tcc.exe) only
rem
rem  Version : 2.0
rem
rem  No GNU tools, WSL, MinGW, meson, make, libtasn1 or iconv are needed. TCC
rem  compiles libdsm, smb_engine.c and smbftp.c (or winsmbftp.c) together and
rem  links them statically into one exe (no libdsm DLL, no import library).
rem
rem  libdsm is not part of this source tree. The first build downloads the
rem  upstream commit named in patches\libdsm.cfg, checks its SHA-256, unpacks it
rem  into .\libdsm and applies patches\*.diff with tools\applydiff.c, a small
rem  patch tool that this script compiles with TCC. Changing patches\libdsm.cfg
rem  or a patch file makes the next build redo this. See README.md.
rem
rem  Usage:   build.cmd             release build of smbftp.exe (default)
rem           build.cmd debug       smbftp.exe with libdsm's debug trace and asserts, -g
rem           build.cmd gui         build WinSMBFTP.exe (the GUI frontend)
rem           build.cmd gui debug   as gui, plus -g and -DWINSMB_DEBUG: dbg_log() writes
rem                                 winsmbftp-debug.log next to the exe (a plain gui
rem                                 build has no logging code at all)
rem           build.cmd fetch       only download, verify and patch libdsm
rem           build.cmd clean       delete smbftp.exe and WinSMBFTP.exe
rem           build.cmd distclean   clean, and delete .\libdsm and the download cache .\deps
rem
rem  Needs:   TCC, and for the download curl.exe, tar.exe and certutil.exe, which
rem           come with Windows 10 version 1803 and later and Windows 11. Without
rem           curl.exe, PowerShell is used for the download. For an offline build,
rem           put the file deps\libdsm-COMMIT.tar.gz in place by hand first.
rem
rem  Finding TCC, first match wins:
rem     1. the TCC environment variable, e.g.  set TCC=C:\tools\tcc\tcc.exe
rem     2. tcc.exe on PATH
rem     3. a tcc folder next to this script, or ..\tcc, %SystemDrive%\tcc,
rem        %ProgramFiles%\tcc, %ProgramFiles(x86)%\tcc, %USERPROFILE%\tcc
rem
rem  Expected layout, everything relative to this script:
rem     build.cmd  smbftp.c  smbftp.h  smb_engine.c  smb_engine.h  ws2_32.def  sources.lst
rem     winsmbftp.c  user32.def  comctl32.def  comdlg32.def  WinSMBFTP.exe.manifest  (gui only)
rem     winport\   support files for TCC on Windows (config.h, winmini.h, wingui.h, ...)
rem     patches\   libdsm.cfg and the patch series for libdsm
rem     tools\     applydiff.c, the patch tool
rem     libdsm\    made by this script (do not edit; change patches\ instead)
rem     deps\      download cache and the compiled patch tool, made by this script
rem
rem  Exit status: 0 = built (smbftp.exe: and smoke-tested), 1 = failure, 2 = bad argument.
rem
rem  History : 2.0  2026-10-23  Merge of the two build.cmd lineages. From SMBFTP-main:
rem                 libdsm is downloaded, SHA-256 checked and patched (patches\,
rem                 tools\applydiff.c, fetch, distclean) instead of bundled. From the
rem                 WinSMBFTP tree 1.1: gui and gui debug (WINSMB_DEBUG), smb_engine.c
rem                 in both exes, clean removes both exes.
rem            1.1  2026-10-22  (WinSMBFTP tree) gui debug; clean removes both exes.
rem            1.0  earlier builds: release, debug, gui, clean (no version was kept).
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" 2>nul
if errorlevel 1 (
    echo [build] cannot change to the script folder "%~dp0"
    exit /b 1
)

set "OUT=smbftp.exe"
set "MODE=release"
set "ACTION=build"
set "GUIDBG=0"

if /i "%~1"=="clean"     goto :clean
if /i "%~1"=="distclean" goto :distclean
if /i "%~1"=="fetch"     set "ACTION=fetch"  & goto :modeok
if /i "%~1"=="debug"     set "MODE=debug"    & goto :modeok
if /i "%~1"=="release"   set "MODE=release"  & goto :modeok
if /i "%~1"=="gui"       set "MODE=gui" & set "OUT=WinSMBFTP.exe" & goto :modeok
if /i "%~1"=="help"      goto :usage
if /i "%~1"=="-h"        goto :usage
if /i "%~1"=="/?"        goto :usage
if not "%~1"==""         goto :badarg
:modeok
if "%~2"=="" goto :argok
if /i "%MODE%"=="gui" if /i "%~2"=="debug" set "GUIDBG=1" & goto :argok
goto :badarg
:argok

rem ---- locate TCC ------------------------------------------------------------
if defined TCC (
    if not exist "!TCC!" (
        echo [build] the TCC environment variable names a file that does not exist:
        echo [build]     !TCC!
        goto :fail
    )
    goto :have_tcc
)
for %%P in (tcc.exe) do set "TCC=%%~$PATH:P"
if defined TCC goto :have_tcc

set "PF86=%ProgramFiles(x86)%"
for %%D in ("%CD%\tcc" "%CD%\..\tcc" "%SystemDrive%\tcc" "%ProgramFiles%\tcc" "%PF86%\tcc" "%USERPROFILE%\tcc") do if not defined TCC if exist "%%~D\tcc.exe" set "TCC=%%~D\tcc.exe"
if not defined TCC (
    echo [build] tcc.exe not found. Install TinyCC ^(Windows binary packages are at
    echo [build] https://download.savannah.gnu.org/releases/tinycc/^) and either put
    echo [build] it on PATH, or run:  set TCC=C:\path\to\tcc.exe
    goto :fail
)
:have_tcc

echo [build] compiler : !TCC!
"!TCC!" -v
if errorlevel 1 (
    echo [build] "!TCC!" does not run
    goto :fail
)

rem ---- libdsm: download, verify and patch it when missing or out of date ------
call :get_libdsm
if errorlevel 1 goto :fail
if /i "%ACTION%"=="fetch" (
    popd
    endlocal
    exit /b 0
)

rem ---- check the source tree -------------------------------------------------
set "MISSING="
set "NEED=smbftp.c smbftp.h smb_engine.c smb_engine.h ws2_32.def sources.lst"
set "NEED=%NEED% winport\winmini.h winport\config.h winport\winsock2.h"
set "NEED=%NEED% winport\ws2tcpip.h winport\unistd.h"
set "NEED=%NEED% libdsm\include\bdsm.h libdsm\include\bdsm\smb_session.h"
if /i "%MODE%"=="gui" (
    set "NEED=!NEED! winsmbftp.c WinSMBFTP.exe.manifest"
    set "NEED=!NEED! user32.def comctl32.def comdlg32.def winport\wingui.h"
)
for %%F in (!NEED!) do call :need "%%~F"

rem ---- libdsm sources: the list is in sources.lst, shared with the Makefile ---
set "SRCS="
for /f "usebackq eol=# tokens=*" %%F in ("sources.lst") do call :addsrc "%%F"
if defined MISSING (
    echo [build] the source tree is incomplete; see the layout at the top of build.cmd
    goto :fail
)

rem ---- compile and link ------------------------------------------------------
rem  -Iwinport comes first so that config.h, winsock2.h, ws2tcpip.h and unistd.h
rem  are found there. HAVE_CONFIG_H makes libdsm include that config.h.
set "INCS=-Iwinport -I. -Ilibdsm -Ilibdsm\include -Ilibdsm\contrib"
if /i "%MODE%"=="debug" (
    set "FLAGS=-g -DHAVE_CONFIG_H=1"
) else (
    set "FLAGS=-DHAVE_CONFIG_H=1 -DNDEBUG"
)
rem  gui debug: -g and WINSMB_DEBUG (winsmbftp.c's dbg_log). NDEBUG stays: a GUI
rem  exe has no console, so libdsm's stderr trace and assert messages would not
rem  be seen anyway - the debug log file is the diagnostic there.
if "%GUIDBG%"=="1" set "FLAGS=-g -DHAVE_CONFIG_H=1 -DNDEBUG -DWINSMB_DEBUG"

if exist "%OUT%" del /q "%OUT%" 2>nul
if exist "%OUT%" (
    echo [build] cannot delete the old %OUT% - is it still running?
    goto :fail
)

echo [build] mode     : %MODE%
if "%GUIDBG%"=="1" echo [build] WINSMB_DEBUG on: %OUT% will write winsmbftp-debug.log next to itself
if /i "%MODE%"=="gui" (
    echo [build] compiling winsmbftp.c + smb_engine.c + libdsm into %OUT% ...
    "!TCC!" !FLAGS! !INCS! -o "%OUT%" winsmbftp.c smb_engine.c !SRCS! ws2_32.def user32.def comctl32.def comdlg32.def
) else (
    echo [build] compiling smbftp.c + smb_engine.c + libdsm into %OUT% ...
    "!TCC!" !FLAGS! !INCS! -o "%OUT%" smbftp.c smb_engine.c !SRCS! ws2_32.def
)
if errorlevel 1 goto :compile_failed
if not exist "%OUT%" goto :compile_failed

for %%A in ("%OUT%") do echo [build] built    : %%~fA ^(%%~zA bytes^)

if /i "%MODE%"=="gui" (
    echo [build] no automated smoke test for a GUI exe - run %OUT% and check that
    echo [build] a window opens, resizes cleanly, and closes.
    echo [build] WinSMBFTP.exe.manifest must stay next to %OUT% for the themed look.
    echo [build] Scan: click Scan, check the range, press Scan in its window.
    popd
    endlocal
    exit /b 0
)

rem ---- smoke test (smbftp.exe only) ---------------------------------------
rem  -h checks that the program starts. "-S 127.0.0.1" scans only this machine's
rem  own address, which is never probed, so no packets are sent, but it does call
rem  WSAStartup, WSAIoctl and socket, which proves the Winsock imports resolved.
".\%OUT%" -h >nul 2>&1
if errorlevel 1 (
    echo [build] SMOKE TEST FAILED: "%OUT% -h" did not exit with status 0
    goto :fail
)
".\%OUT%" -S 127.0.0.1 >nul 2>&1
if errorlevel 1 (
    echo [build] SMOKE TEST FAILED: "%OUT% -S 127.0.0.1" did not exit with status 0
    goto :fail
)
echo [build] smoke test passed
echo [build] run:  %OUT% ^<IPv4-address^>      or      %OUT% -S      or      %OUT% -h
popd
endlocal
exit /b 0

:compile_failed
echo.
echo [build] BUILD FAILED: TCC reported errors above
goto :fail

:clean
if exist "smbftp.exe" del /q "smbftp.exe"
if exist "WinSMBFTP.exe" del /q "WinSMBFTP.exe"
echo [build] removed smbftp.exe and WinSMBFTP.exe ^(where present^)
popd
endlocal
exit /b 0

:distclean
if exist "smbftp.exe" del /q "smbftp.exe"
if exist "WinSMBFTP.exe" del /q "WinSMBFTP.exe"
if exist libdsm rmdir /s /q libdsm
if exist deps rmdir /s /q deps
echo [build] removed smbftp.exe, WinSMBFTP.exe, .\libdsm and .\deps
popd
endlocal
exit /b 0

:usage
echo Usage: build.cmd [release ^| debug ^| gui [debug] ^| fetch ^| clean ^| distclean]
echo   release    build smbftp.exe (default)
echo   debug      build smbftp.exe with libdsm's debug trace on stderr, asserts enabled, and -g
echo   gui        build WinSMBFTP.exe
echo   gui debug  build WinSMBFTP.exe with -g and winsmbftp-debug.log logging
echo   fetch      only download, verify and patch libdsm into .\libdsm
echo   clean      delete smbftp.exe and WinSMBFTP.exe
echo   distclean  clean, and delete .\libdsm and the download cache .\deps
echo The TCC compiler is found via the TCC environment variable, then PATH, then
echo a few usual folders; see the comments at the top of this file.
popd
endlocal
exit /b 0

:badarg
echo [build] unknown argument "%~1 %~2"
echo Usage: build.cmd [release ^| debug ^| gui [debug] ^| fetch ^| clean ^| distclean]
popd
endlocal
exit /b 2

:fail
popd
endlocal
exit /b 1

rem ---- subroutines, only reached through "call" ------------------------------

:need
if not exist "%~1" (
    echo [build] missing file: %~1
    set "MISSING=1"
)
exit /b 0

:addsrc
rem sources.lst uses forward slashes; build.cmd wants backslashes for "if exist"
set "SRCF=%~1"
set "SRCF=!SRCF:/=\!"
if not exist "libdsm\!SRCF!" (
    echo [build] missing file: libdsm\!SRCF!
    set "MISSING=1"
)
set "SRCS=!SRCS! libdsm\!SRCF!"
exit /b 0

rem ---- :get_libdsm -----------------------------------------------------------
rem  Reads patches\libdsm.cfg. Leaves .\libdsm alone when libdsm\.stamp already
rem  records this commit and these patch files. Otherwise: download if the file
rem  is not cached in deps\, check its SHA-256, unpack into deps\stage, patch
rem  there, and only then move it to .\libdsm, so a failed run never leaves a
rem  half-patched .\libdsm. Returns 0 = ready, 1 = failed.
:get_libdsm
if not exist "patches\libdsm.cfg" (
    echo [build] missing patches\libdsm.cfg
    exit /b 1
)
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("patches\libdsm.cfg") do set "%%A=%%B"
for %%V in (LIBDSM_COMMIT LIBDSM_URL LIBDSM_SHA256 LIBDSM_PATCHES) do if not defined %%V (
    echo [build] patches\libdsm.cfg does not define %%V
    exit /b 1
)

rem  signature = commit + SHA-256 of every patch, in order
set "SIG=%LIBDSM_COMMIT%"
for %%P in (%LIBDSM_PATCHES%) do (
    if not exist "patches\%%P" (
        echo [build] missing patch file patches\%%P
        exit /b 1
    )
    call :sha256 "patches\%%P" PH
    set "SIG=!SIG! !PH!"
)
set "OLDSIG="
if exist "libdsm\.stamp" set /p OLDSIG=<"libdsm\.stamp"
if "!OLDSIG!"=="!SIG!" (
    echo [build] libdsm is up to date
    exit /b 0
)
if exist libdsm if not exist "libdsm\.stamp" (
    echo [build] .\libdsm exists but was not made by build.cmd: it has no .stamp file.
    echo [build] Move it away, or run: build.cmd distclean - then it is downloaded and patched again.
    exit /b 1
)

if not exist deps mkdir deps
set "ARC=deps\libdsm-%LIBDSM_COMMIT%.tar.gz"
if exist "!ARC!" goto :gl_have_archive
echo [build] downloading %LIBDSM_URL%
call :download "%LIBDSM_URL%" "!ARC!.part"
if errorlevel 1 (
    echo [build] the download failed. Check the network or proxy, or download that URL by hand to
    echo [build]     !ARC!
    if exist "!ARC!.part" del /q "!ARC!.part"
    exit /b 1
)
move /y "!ARC!.part" "!ARC!" >nul
:gl_have_archive

call :sha256 "!ARC!" AH
if not defined AH (
    echo [build] could not compute the SHA-256 of !ARC! - is certutil.exe available?
    exit /b 1
)
if /i "!AH!"=="%LIBDSM_SHA256%" goto :gl_hash_ok
echo [build] the SHA-256 of !ARC! does not match patches\libdsm.cfg
echo [build]     expected %LIBDSM_SHA256%
echo [build]     got      !AH!
del /q "!ARC!"
exit /b 1
:gl_hash_ok

if exist "deps\stage" rmdir /s /q "deps\stage"
mkdir "deps\stage"
set "TAREXE=tar"
if exist "%SystemRoot%\System32\tar.exe" set "TAREXE=%SystemRoot%\System32\tar.exe"
"!TAREXE!" -xzf "!ARC!" -C "deps\stage"
if errorlevel 1 (
    echo [build] could not unpack !ARC!. tar.exe comes with Windows 10 version 1803 and later.
    exit /b 1
)

echo [build] compiling the patch tool tools\applydiff.c
"!TCC!" -o "deps\applydiff.exe" "tools\applydiff.c"
if errorlevel 1 (
    echo [build] could not compile tools\applydiff.c
    exit /b 1
)
set "STAGED=deps\stage\libdsm-%LIBDSM_COMMIT%"
for %%P in (%LIBDSM_PATCHES%) do (
    echo [build] applying %%P
    "deps\applydiff.exe" -p1 -d "!STAGED!" "patches\%%P" >nul
    if errorlevel 1 (
        echo [build] patches\%%P did not apply to the downloaded sources
        rmdir /s /q "deps\stage"
        exit /b 1
    )
)

if exist libdsm rmdir /s /q libdsm
move "!STAGED!" libdsm >nul
if errorlevel 1 (
    echo [build] could not move the patched sources to .\libdsm
    exit /b 1
)
rmdir /s /q "deps\stage"
>"libdsm\.stamp" echo !SIG!
echo [build] libdsm is ready
exit /b 0

rem ---- :sha256 file varname --------------------------------------------------
rem  Puts the SHA-256 of "file" in the variable "varname", lower case with no
rem  blanks, or leaves it empty. certutil prints a header line, the hash, then a
rem  trailer line; older Windows prints the hash with a blank between the bytes.
:sha256
set "%~2="
for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "%~1" SHA256 2^>nul') do if not defined %~2 set "%~2=%%H"
if defined %~2 set "%~2=!%~2: =!"
exit /b 0

rem ---- :download url file ----------------------------------------------------
:download
where curl.exe >nul 2>&1
if errorlevel 1 goto :download_ps
curl.exe -fL --retry 3 -sS -o "%~2" "%~1"
exit /b %errorlevel%
:download_ps
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri '%~1' -OutFile '%~2'"
exit /b %errorlevel%
