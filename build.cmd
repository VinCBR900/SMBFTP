@echo off
rem ============================================================================
rem  build.cmd - build smbftp.exe on Windows with TCC (tcc.exe) only
rem
rem  No GNU tools, WSL, MinGW, meson, make, libtasn1 or iconv are needed. TCC
rem  compiles the bundled libdsm sources and smbftp.c together and links them
rem  statically into one smbftp.exe (no libdsm DLL, no import library for it).
rem
rem  Usage:   build.cmd           release build (default)
rem           build.cmd debug     keep libdsm's debug trace and asserts, add -g
rem           build.cmd clean     delete smbftp.exe
rem
rem  Finding TCC, first match wins:
rem     1. the TCC environment variable, e.g.  set TCC=C:\tools\tcc\tcc.exe
rem     2. tcc.exe on PATH
rem     3. a tcc folder next to this script, or ..\tcc, %SystemDrive%\tcc,
rem        %ProgramFiles%\tcc, %ProgramFiles(x86)%\tcc, %USERPROFILE%\tcc
rem
rem  Expected layout, everything relative to this script:
rem     build.cmd  smbftp.c  smbftp.h  ws2_32.def
rem     winport\   support files for TCC on Windows (config.h, winmini.h, ...)
rem     libdsm\    the libdsm source tree, modified for TCC (see README.md)
rem
rem  Exit status: 0 = built and smoke-tested, 1 = failure, 2 = bad argument.
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" 2>nul
if errorlevel 1 (
    echo [build] cannot change to the script folder "%~dp0"
    exit /b 1
)

set "OUT=smbftp.exe"
set "MODE=release"

if /i "%~1"=="clean"    goto :clean
if /i "%~1"=="debug"    set "MODE=debug"    & goto :modeok
if /i "%~1"=="release"  set "MODE=release"  & goto :modeok
if /i "%~1"=="help"     goto :usage
if /i "%~1"=="-h"       goto :usage
if /i "%~1"=="/?"       goto :usage
if not "%~1"==""        goto :badarg
:modeok

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

rem ---- check the source tree -------------------------------------------------
set "MISSING="
set "NEED=smbftp.c smbftp.h ws2_32.def"
set "NEED=%NEED% winport\winmini.h winport\config.h winport\winsock2.h"
set "NEED=%NEED% winport\ws2tcpip.h winport\unistd.h"
set "NEED=%NEED% libdsm\include\bdsm.h libdsm\include\bdsm\smb_session.h"
for %%F in (%NEED%) do call :need "%%~F"

rem ---- libdsm sources --------------------------------------------------------
rem netbios_ns.c (NetBIOS name lookup, needs pthreads) is left out on purpose:
rem smbftp connects by IPv4 address and does not use it. compat\clock_gettime.c
rem is only needed by netbios_ns.c.
set "SRCS="
set "LIST=contrib\mdx\md4 contrib\mdx\md5 contrib\rc4\rc4"
set "LIST=%LIST% src\hmac_md5 src\netbios_query src\netbios_session src\netbios_utils"
set "LIST=%LIST% src\smb_buffer src\smb_dir src\smb_fd src\smb_file"
set "LIST=%LIST% src\smb_message src\smb_ntlm src\smb_session src\smb_session_msg"
set "LIST=%LIST% src\smb_share src\smb_spnego src\smb_stat src\smb_trans2"
set "LIST=%LIST% src\smb_transport src\smb_utils"
set "LIST=%LIST% compat\strlcpy compat\strndup"
for %%F in (%LIST%) do call :addsrc "%%~F"
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

if exist "%OUT%" del /q "%OUT%" 2>nul
if exist "%OUT%" (
    echo [build] cannot delete the old %OUT% - is it still running?
    goto :fail
)

echo [build] mode     : %MODE%
echo [build] compiling smbftp.c + libdsm into %OUT% ...
"!TCC!" !FLAGS! !INCS! -o "%OUT%" smbftp.c !SRCS! ws2_32.def
if errorlevel 1 goto :compile_failed
if not exist "%OUT%" goto :compile_failed

for %%A in ("%OUT%") do echo [build] built    : %%~fA ^(%%~zA bytes^)

rem ---- smoke test ------------------------------------------------------------
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
if exist "%OUT%" del /q "%OUT%"
echo [build] removed %OUT%
popd
endlocal
exit /b 0

:usage
echo Usage: build.cmd [release ^| debug ^| clean]
echo   release  build smbftp.exe (default)
echo   debug    build with libdsm's debug trace on stderr, asserts enabled, and -g
echo   clean    delete smbftp.exe
echo The TCC compiler is found via the TCC environment variable, then PATH, then
echo a few usual folders; see the comments at the top of this file.
popd
endlocal
exit /b 0

:badarg
echo [build] unknown argument "%~1"
echo Usage: build.cmd [release ^| debug ^| clean]
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
if not exist "libdsm\%~1.c" (
    echo [build] missing file: libdsm\%~1.c
    set "MISSING=1"
)
set "SRCS=!SRCS! libdsm\%~1.c"
exit /b 0
