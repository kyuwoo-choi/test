
@echo off
 :: BatchGotAdmin
 :-------------------------------------
 REM  --> Check for permissions
 >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
 if '%errorlevel%' NEQ '0' (
     echo Requesting administrative privileges...
     goto UACPrompt
 ) else ( goto gotAdmin )

:UACPrompt
     echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
     echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
     exit /B

:gotAdmin
     if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
     pushd "%CD%"
     CD /D "%~dp0"
 :-------------------------------------- 
 
 
setlocal
setlocal EnableDelayedExpansion
chcp 949


chdir >> set=script
color 97

echo ************관리자 권한으로 실행해주세요.************
echo 해당 시스템의 IP 주소를 입력해주세요.
set /p IPINFO= (ex.192.168.30.1) : 

chcp 437

@echo on

echo Window Checking ======================================================== > ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ======== start time ========================================================= > ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
date /t  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
time /t >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ======== ipconfig /all ====================================================== >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ipconfig /all >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ======== Process Information ========================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
tasklist /v>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ======== netstat -an ======================================================== >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
c:\windows\system32\netstat -an >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ======== net start ======================================================== >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


echo ======== System Information ======================================================== >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
xp32-systeminfo >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
xp32-systeminfo > systeminfo.txt   
echo ============================================================================= >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

psservice > ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%_Ref.txt

type systeminfo.txt | find /i "x64-based" 

if NOT ERRORLEVEL 1 goto x64-based




echo ############################################################################################# >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ###################																			>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ###################            windows 32bit   check                      						>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################																			>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo #############################################################################################  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt



echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

:: pc-01 패스워드의 주기적 변경
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-01 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 최대 암호 사용 기간을 확인하고 활성 계정에도 적용되어 있는지 확인필요 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "최대 암호"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "최소 암호 사용"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "암호 기록 개수"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net user   > user.txt
type user.txt | find /V "--" | find /V "실행했습니다." | find /V "사용자 계정" > usercheck.txt 
REM FOR /F "tokens=1" %%a in (user2.txt) do SET KISATEMP=%%a



net accounts | find "Maximum password"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                         

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Minimum password age"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Length of password history maintained"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


FOR /F "tokens=1" %%a IN (usercheck.txt) DO net user %%a | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=2" %%b IN (usercheck.txt) DO net user %%b | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=3" %%c IN (usercheck.txt) DO net user %%c | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=4" %%d IN (usercheck.txt) DO net user %%d | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=5" %%e IN (usercheck.txt) DO net user %%e | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    

chcp 437

del usercheck.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 최대 암호 사용 기간이 90일 이하로 설정되어 있고 활성계정에 설정되어 있는 경우 양호        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-01 END




:: pc-02 패스워드 정책이 해당기관의 보안정책에 적합하게 설정
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-02 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts > net-accounts.txt  
type net-accounts.txt | find "length"						     > length.txt
FOR /F "tokens=4" %%k in (length.txt) do SET KISATEMP=%%k
secedit /export /cfg LocalSecurityPolicy.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity" | find "1" > nul

if "%ERRORLEVEL%" EQU "0" (
	if "%KISATEMP%" GEQ "8" (
		goto length-SETTING-OK
		)
)


echo [Result]: Weak                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 패스워드 정책이 적합하게 설정되어 있지 않으므로 취약함                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length" 						                                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
goto length-end


:length-SETTING-OK
     
echo [Result]: Good   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 패스워드 정책이 적합하게 설정되어 있으므로 양호함                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.
goto length-end

:length-end
set KISATEMP=
del length.txt
del net-accounts.txt
del LocalSecurityPolicy.txt

echo.                                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 최소 암호 길이가 8자리 이상으로 되어 있고 암호 복잡도가 정책에 맞게 설정되어 있는 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ※ Minimum password length 값이 8 이상이고 PasswordComplexity 값이 1이면 양호  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ※ 정책 설정 이전에 생성된 계정에 대한 복잡도 정책이 적절하게 설정되어 있는지 인터뷰 필요 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-02 END








:: pc-03 공유폴더 제거
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-03                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info                                                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 불필요한 공유폴더가 있는지 확인필요                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. 불필요한 공유폴더 확인                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

setlocal enabledelayedexpansion
echo # net share >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net share >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo # cacls [Share Directory] >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type systeminfo.txt | findstr /i /C:"os name" | findstr "7 8 10"
if !ERRORLEVEL! EQU 0 (
	reg query "HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Shares" /SE "|" > share_registry.txt
	for /f "tokens=4 delims=|" %%i in ('type share_registry.txt ^| findstr /i ^"^Path^"') do (
		set share_path=%%i
		cacls "!share_path:~5!" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
	)
) else (
	reg query "HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Shares" /SE "|" > share_registry.txt
	for /f "tokens=3 delims=|" %%i in ('type share_registry.txt ^| findstr /i ^"^Path^"') do (
		set share_path=%%i
		cacls !%share_path:~5!" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt 
	)
)
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. 레지스트리 확인                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareWks"	>> harddisk-reg.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareServer"	>> harddisk-reg.txt
Type harddisk-reg.txt | Find /I "AutoShareWks"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareWks 레지스트리값이 존재하지 않음												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
Type harddisk-reg.txt | Find /I "AutoShareServer"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareServer 레지스트리값이 존재하지 않음												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del harddisk-reg.txt
del share_registry.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 공유폴더 제거                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. $표시된 기본 공유폴더가 존재하면 취약 그외 공유폴더 사용유무 및 공유폴더 권한 여부에 따라 판단            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 공유디렉토리에 Everyone 계정 권한 확인(Everyone 그룹이 존재한다면 모든사용자 접속가능) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 그외 불필요 사용자가 모든권한(F) 및 Write 권한이 있다면 판단후 취약          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. 양호 = Everyone 사용자 삭제, 사용자(Users그룹사용자)의 권한에 쓰기권한 거부                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. 취약 = Everyone 사용자 존재, 사용자(Users그룹사용자)의 권한에 쓰기권한 허용                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. 사용자 계정에 쓰기권한(F) 혹은 FILE_WRITE_DATA권한 존재한다면 취약             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-03 END






:: pc-04 불필요한 서비스 제거
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-04                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Alerter"                                          > Alerterservice.txt
find /I "Alerter" Alerterservice.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                      
net start | find /I "Computer Browser"                                          > ComputerBrowser.txt
find /I "Computer Browser" ComputerBrowser.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                        
net start | find /I "Fast User Switching Compatibility"                                          > Switching.txt
find /I "Fast User Switching Compatibility" switching.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Messenger"                                          > Messenger.txt
find /I "Messenger" Messenger.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Netmeeting Remote Desktop Sharing"        > Netmeeting.txt
find /I "Netmeeting Remote Desktop Sharing" Netmeeting.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Telnet"                                          > Telnet.txt
find /I "Telnet" Telnet.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         

echo [Result]: Good                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드에서 지정한 불필요한 서비스가 존재하지 않으므로 양호함                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Alerter 서비스 미구동       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Computer Browser 서비스 미구동       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Fast User Switching Compatibility 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Messenger 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Netmeeting Remote Desktop Sharing 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Telnet 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


goto PC-04-SERVICE-END


:PC-04-SERVICE-fail

echo [Result]: Weak                                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드에서 지정한 불필요한 서비스가 존재함으로 취약함                                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 불필요 규정 서비스 구동중인 항목                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Alerter"                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Computer Browser"                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Fast User Switching Compatibility"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Messenger"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Netmeeting Remote Desktop Sharing"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Telnet"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:PC-04-SERVICE-END


del Alerterservice.txt
del ComputerBrowser.txt
del Switching.txt
del Messenger.txt
del Netmeeting.txt
del Telnet.txt


echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 불필요한 서비스 제거                                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Alerter(xp만존재) = 서버에서 클라이언트로 경고메세지를 보냄                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Computer Browser(모든OS 존재) = 네트워크에 있는 모든 컴퓨터 목록을 갱신하고 관리하며 이 목록을 브라우저로 지정된 컴퓨터에 제공하는 서비스                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Fast User Switching Compatibility(xp만존재) = 여러 사람이 공동으로 사용하는 컴퓨터에서 컴퓨터를 이용하던 이용자가 로그오프하지 않은 채 다른 사용자가 로그온하여 컴퓨터를 사용할 수 있게 한다.      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Messenger(xp만존재) = 네트워크상에서 메시지를 전달하는 기능을 하는 서비스로써, 성인광고 등의 스팸메시지가 이 서비스를 통해 보내어진다.                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. Netmeeting Remote Desktop Sharing(xp만 존재) = 자신의 컴퓨터에 원격으로 접근할 수 있도록 허용하고 다른 컴퓨터와 바탕 화면 원격 공유를 사용할 수 있게 하는 서비스                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Telnet(모든OS 존재) = 원격 사용자가 접속하여 파일검색, 삭제 등 각종 명령어를 실행시킬 수 있게 하는 서비스        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. 유의사항 = 검색어에 해당 단어를 포함하는 서비스가 있을경우 오탐가능성있으니 확인 요망 .                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-04 END





:: pc-05 Windows Messenger(MSN, .NET 메신저 등)와 같은 상용 메신저의 사용 금지
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-05  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >> Messeger_check.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >>  Messeger_check.txt

::type Messagner_check.txt | find /i "KakaoTalk" 
findstr /I "Kakao" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "카카오톡" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "NATEON" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /L "LINE" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "Telegram" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Good       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 상용메신저가 설치되어 있지 않으므로 양호함          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-05-Messenger-END

:PC-05-Messenger-fail

ECHO [Result]: Weak                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ECHO [Comment]: 상용메신저가 설치되어 있으므로 취약함         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type Messeger_check.txt | findstr /I "KakaoTalk"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "카카오톡"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "NATEON"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "LINE"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "Telegram"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del Messeger_check.txt   

:PC-05-Messenger-END

chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 상용 메신저를 사용하지 않는 경우 양호                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-05 END





:: pc-06 HOT FIX 등 최신 보안패치 적용
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-06                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: HOT FIX 등 최신 보안패치 적용이 되어 있는지 확인필요                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic QFE Get HotFixID,InstalledOn,Description  > hotfix.txt
type hotfix.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del hotfix.txt
ver >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 서비스팩 및 Hotfix 적용 점검                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. HOTFIX 수량 및 최신 핫픽스 체크       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. HOT FIX 설치 및 자동 업데이트 설정이 되어 있는 경우 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-06 END






:: pc-07 최신 서비스팩 적용
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-07                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 최신서비스팩 적용되어 있는지 확인필요                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type systeminfo.txt | find /i "os name" 				    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    						   
type systeminfo.txt | find /i "version" | find /V "BIOS"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [PC-07] END  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [PC-07] 수동   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS 별 최신 서비스팩(빌드) 확인 후 진단                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. OS 별 서비스팩(빌드) 상이함                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 유효한 빌드 버전을 사용하는 경우 양호                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 2020.01.14 기준 Windows 7 지원 종료(취약)                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-07 END








chcp 949
:: pc-08 바이러스 백신 프로그램 설치 및 주기적 업데이트
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-08	    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 백신이 설치되어 있고 최신 업데이트로 적용되어 있는지 확인필요    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt     
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName, productState > antiviruslist.txt
type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [Check]:                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 백신 업데이트 여부                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. 아무값도 나오지 않으면 백신 설치여부 항목  및 인터뷰를 통해 진단             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 백신이 설치되어 있고, 최신 업데이트가 적용 되어 있는 경우 양호(설치된 백신, 정의 업데이트 날자로 판단)             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-08 END









:: pc-09 바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-09            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get productState | findstr /v /r /c:"^$" /c:"^\ *$" /c:"productState" > RTProtect_check.txt

chcp 437
type RTProtect_check.txt | find "266240"
IF NOT ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
type RTProtect_check.txt | find "266240"

IF NOT ERRORLEVEL 1 echo [Commnet]: 실시간 감시가 활성화 되어 있으므로 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Commnet]: 실시간 감시가 비활성화 되어 있으므로 취약함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del antiviruslist.txt
del RTProtect_check.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 수동점검으로 백신 프로그램이 설치되어 있는지 확인하고 실시간 감시 기능이 활성화 되어 있는지 확인  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-09 END













REM PC-10번 분기점 ############################



type systeminfo.txt | find /i "OS Name" | find /i "windows xp" 

IF NOT ERRORLEVEL 1 goto 32-bit-xp-10-check 

type systeminfo.txt | find /i "OS Name" | findstr /i "7 10"

IF NOT ERRORLEVEL 1 goto 32-bit-win7-10-check




:32-bit-xp-10-check


:: pc-10 OS에서 제공하는 침입차단 기능 활성화
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Comment]: OS 에서 제공하는 방화벽이 활성화 되어있어 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: OS 에서 제공하는 방화벽이 비활성화 되어있어 취약함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del firewall.txt
										   
goto 32-bit-10-end


:32-bit-win7-10-check

echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

reg query "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" | find /i "EnableFirewall" > firewall2.txt

type firewall.txt | find "x1" 

if ERRORLEVEL 1 goto 32-bit-win7-10-fail

type firewall2.txt | find "x1" 

if ERRORLEVEL 1 goto 32-bit-win7-10-fail


echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS 에서 제공하는 방화벽이 활성화 되어있어 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 홈 또는 회사(개인)네트워크 방화벽체크                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 공용 네트워크 방화벽체크                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 32-bit-10-end

:32-bit-win7-10-fail
echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS 에서 제공하는 방화벽이 비활성화 되어있어 취약함     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 홈 또는 회사(개인)네트워크 방화벽체크    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 공용 네트워크 방화벽체크               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:32-bit-10-end						   

del firewall.txt
del firewall2.txt
		
		
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS에서 제공하는 침입차단 기능 활성화                                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. EnableFirewall = x0 - (방화벽 미사용)취약      										 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. EnableFirewall = x1 - (방화벽 사용)양호       									     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
:: pc-10 END
















:: pc-11 화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-11                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveActive"                             >  logoff1.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaverIsSecure"                          >  logoff2.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveTimeOut"                            >  logoff3.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                             >  logoff1.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                          >  logoff2.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                            >  logoff3.txt

echo [Result] : Info>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment] :>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- Edit group policy 확인 ----                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- 화면보호기 설정 확인 ----                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 32-bit-logoff-end
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

:32-bit-logoff-end

del logoff1.txt
del logoff2.txt
del logoff3.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 화면보호기 설정                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ScreenSaveActive    = 화면보호기 작동유무                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ScreenSaverIsSecure = 데이터 값이 0, 1에 상관없이 무조건 다시시작할때 암호로 보호        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. ScreenSaveTimeOut   = 대기 시간 설정 초 단위                                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ScreenSaveActive, ScreenSaverIsSecure 값은 1 이 양호                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ScreenSaveTimeOut값은 600이하 양호                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Edit group policy의 값이 출력되지 않으면 '구성되지 않음' 상태                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. Edit group policy가 상위 설정이므로 값이 하나라도 출력될 경우 해당 위치에서 정책 확인                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-11 END








:: pc-12 CD, DVD, USB메모리 등과 같은 미디어의 자동실행 방지 등 이동식 미디어에 대한 보안대책 수립
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-12   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 미디어 사용 시 자동 실행되는지 확인필요   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 가. Autorun.inf 파일 설정 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 나. Shell Hardware Detection 서비스 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Shell Hardware Detection"                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 다. 레지스트리 설정 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 라. Windows 10 자동실행 방지 레지스트리 값(DisableAutoplay) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
REM echo Windows 10 자동실행 방지 레지스트리 값(DisableAutoplay) >> WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" | find /i "DisableAutoplay" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt



chcp 437
echo [Check]:                                                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. CD, DVD, USB메모리 등과 같은 미디어의 자동실행 방지 등 이동식 미디어에 대한 보안대책 수립                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Autorun.inf의 기본값 : @SYS:DoesNotExist 또는 @SYS:NoWhere 값이 들어가있으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Autorun.inf의 기본값 : 아무값도 없으면 취약                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Autorun.inf의 기본값 : 아무값도 없으면 취약                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Shell Hardware Detection 서비스가 확인되지 않으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. 레지스트리 NoDriveTypeAutoRun 값이 Windows 2000: 95, Windows XP: 91, Windows Server 2003: 95, Windows Vista, Server 2008 and 7: 91 으로 되어 있을 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. DisableAutoplay 값이 1인 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-12 END





:: pc-13 비인가 무선랜 사용제한
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-13   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 비인가 무선랜을 사용하고 있지 않은지 확인필요  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 무선랜 접속 이력 확인 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show profile >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 네트워크 별 접속 시간 확인                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 무선 자동 구성 시스템(wlansvc)이 실행중이지 않으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. 비인가 된 무선랜 접속 이력이 있을 시 무선랜 접속 시간 확인 후 판단                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. DateCreated: 최초 연결한 날짜                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. DateLastConnected: 마지막으로 연결한 날짜                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. 리틀엔디언으로 되어 있으므로 치환 하여 확인                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ex) e1 07 09 00 02 00 13 00 0f 00 18 00 33 00 dd 03                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. 년도: e1 07 - 07 e1 으로 변환 후 10진수로 변환 - 2017년                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. 월: 09 00 - 00 09 - 09월 							>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 9. 요일: 02 00 - 00 02 - 화요일( 00 부터 06까지 일 ~ 토) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 10. 날짜: 13 00 - 00 13 - 13일						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 11. 시간: 0f 00 - 00 0f - 15시						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 12. 분: 18 00 - 00 18 - 18분					      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 13. 초: 33 00 - 00 33 - 33초						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 14. Thousandths: dd 03 - 03 dd - 989               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


goto end-pc-check



:x64-based

echo ############################################################################################# >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ###################																			>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo  ###################           windows 64bit   check                      						>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################																			>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo #############################################################################################  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949

echo 64비트를 체크해봅시다.    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:: pc-01 패스워드의 주기적 변경
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-01 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 최대 암호 사용 기간을 확인하고 활성 계정에도 적용되어 있는지 확인필요 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "최대 암호"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "최소 암호 사용"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "암호 기록 개수"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net user   > user.txt
type user.txt | find /V "--" | find /V "실행했습니다." | find /V "사용자 계정" > usercheck.txt 
REM FOR /F "tokens=1" %%a in (user2.txt) do SET KISATEMP=%%a



net accounts | find "Maximum password"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                         

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Minimum password age"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Length of password history maintained"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


FOR /F "tokens=1" %%a IN (usercheck.txt) DO net user %%a | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=2" %%b IN (usercheck.txt) DO net user %%b | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=3" %%c IN (usercheck.txt) DO net user %%c | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=4" %%d IN (usercheck.txt) DO net user %%d | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=5" %%e IN (usercheck.txt) DO net user %%e | find /V "전체 이름" | find /V "설명" | find /V "사용자 설명" | find /V "국가 코드" | find /V "워크스테이션" | find /V "스크립트" | find /V "프로필" | find /V "디렉터리" | find /V "실행했습니다" | find /V "구성원" | find /V "허용된"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    

chcp 437

del usercheck.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 최대 암호 사용 기간이 90일 이하로 설정되어 있고 활성계정에 설정되어 있는 경우 양호        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-01 END




:: pc-02 패스워드 정책이 해당기관의 보안정책에 적합하게 설정
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-02 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts > net-accounts.txt  
type net-accounts.txt | find "length"						     > length.txt
FOR /F "tokens=4" %%k in (length.txt) do SET KISATEMP=%%k
secedit /export /cfg LocalSecurityPolicy.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity" | find "1" > nul

if "%ERRORLEVEL%" EQU "0" (
	if "%KISATEMP%" GEQ "8" (
		goto 64-length-SETTING-OK
		)
)

echo [Result]: Weak                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 패스워드 정책이 적합하게 설정되어 있지 않으므로 취약함                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length" 						                                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-length-end

:64-length-SETTING-OK
     
echo [Result]: Good   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 패스워드 정책이 적합하게 설정되어 있으므로 양호함                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-length-end

:64-length-end
set KISATEMP=
del length.txt
del net-accounts.txt
del LocalSecurityPolicy.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 최소 암호 길이가 8자리 이상으로 되어 있고 암호 복잡도가 정책에 맞게 설정되어 있는 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ※ Minimum password length 값이 8 이상이고 PasswordComplexity 값이 1이면 양호  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ※ 정책 설정 이전에 생성된 계정에 대한 복잡도 정책이 적절하게 설정되어 있는지 인터뷰 필요 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-02 END











:: pc-03 공유폴더 제거
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-03                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info                                                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 불필요한 공유폴더가 있는지 확인필요                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. 불필요한 공유폴더 확인                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
setlocal enabledelayedexpansion
echo # net share >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net share >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo # cacls [Share Directory] >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type systeminfo.txt | findstr /i /C:"os name" | findstr "7 8 10"
if !ERRORLEVEL! EQU 0 (
	reg query "HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Shares" /SE "|" > share_registry.txt
	for /f "tokens=4 delims=|" %%i in ('type share_registry.txt ^| findstr /i ^"^Path^"') do (
		set share_path=%%i
		cacls "!share_path:~5!" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
	)
) else (
	reg query "HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Shares" /SE "|" > share_registry.txt
	for /f "tokens=3 delims=|" %%i in ('type share_registry.txt ^| findstr /i ^"^Path^"') do (
		set share_path=%%i
		cacls !%share_path:~5!" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt 
	)
)
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. 레지스트리 확인                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareWks"	>> harddisk-reg.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareServer"	>> harddisk-reg.txt
Type harddisk-reg.txt | Find /I "AutoShareWks"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareWks 레지스트리값이 존재하지 않음												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
Type harddisk-reg.txt | Find /I "AutoShareServer"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareServer 레지스트리값이 존재하지 않음												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del harddisk-reg.txt
del share_registry.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 공유폴더 제거                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. $표시된 기본 공유폴더가 존재하면 취약 그외 공유폴더 사용유무 및 공유폴더 권한 여부에 따라 판단            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 공유디렉토리에 Everyone 계정 권한 확인(Everyone 그룹이 존재한다면 모든사용자 접속가능) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 그외 불필요 사용자가 모든권한(F) 및 Write 권한이 있다면 판단후 취약          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. 양호 = Everyone 사용자 삭제, 사용자(Users그룹사용자)의 권한에 쓰기권한 거부                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. 취약 = Everyone 사용자 존재, 사용자(Users그룹사용자)의 권한에 쓰기권한 허용                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. 사용자 계정에 쓰기권한(F) 혹은 FILE_WRITE_DATA권한 존재한다면 취약             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-03 END




:: pc-04 불필요한 서비스 제거
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-04                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Alerter"                                          > Alerterservice.txt
find /I "Alerter" Alerterservice.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                      
net start | find /I "Computer Browser"                                          > ComputerBrowser.txt
find /I "Computer Browser" ComputerBrowser.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                        
net start | find /I "Fast User Switching Compatibility"                                          > Switching.txt
find /I "Fast User Switching Compatibility" switching.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Messenger"                                          > Messenger.txt
find /I "Messenger" Messenger.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Netmeeting Remote Desktop Sharing"        > Netmeeting.txt
find /I "Netmeeting Remote Desktop Sharing" Netmeeting.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         
net start | find /I "Telnet"                                          > Telnet.txt
find /I "Telnet" Telnet.txt > NUL 
IF NOT ERRORLEVEL 1 goto PC-04-SERVICE-fail                                                         

echo [Result]: Good                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드에서 지정한 불필요한 서비스가 존재하지 않으므로 양호함                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Alerter 서비스 미구동       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Computer Browser 서비스 미구동       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Fast User Switching Compatibility 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Messenger 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Netmeeting Remote Desktop Sharing 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Telnet 서비스 미구동  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-04-SERVICE-END


:PC-04-SERVICE-fail

echo [Result]: Weak                                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드에서 지정한 불필요한 서비스가 존재함으로 취약함                                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo -----불필요 규정 서비스 구동중인 항목-------                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Alerter"                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Computer Browser"                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Fast User Switching Compatibility"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Messenger"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Netmeeting Remote Desktop Sharing"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find "Telnet"                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

:PC-04-SERVICE-END

del Alerterservice.txt
del ComputerBrowser.txt
del Switching.txt
del Messenger.txt
del Netmeeting.txt
del Telnet.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 불필요한 서비스 제거                                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Alerter(xp만존재) = 서버에서 클라이언트로 경고메세지를 보냄                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Computer Browser(모든OS 존재) = 네트워크에 있는 모든 컴퓨터 목록을 갱신하고 관리하며 이 목록을 브라우저로 지정된 컴퓨터에 제공하는 서비스                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Fast User Switching Compatibility(xp만존재) = 여러 사람이 공동으로 사용하는 컴퓨터에서 컴퓨터를 이용하던 이용자가 로그오프하지 않은 채 다른 사용자가 로그온하여 컴퓨터를 사용할 수 있게 한다.      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Messenger(xp만존재) = 네트워크상에서 메시지를 전달하는 기능을 하는 서비스로써, 성인광고 등의 스팸메시지가 이 서비스를 통해 보내어진다.                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. Netmeeting Remote Desktop Sharing(xp만 존재) = 자신의 컴퓨터에 원격으로 접근할 수 있도록 허용하고 다른 컴퓨터와 바탕 화면 원격 공유를 사용할 수 있게 하는 서비스                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Telnet(모든OS 존재) = 원격 사용자가 접속하여 파일검색, 삭제 등 각종 명령어를 실행시킬 수 있게 하는 서비스        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. 유의사항 = 검색어에 해당 단어를 포함하는 서비스가 있을경우 오탐가능성있으니 확인 요망 .                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-04 END




:: pc-05 Windows Messenger(MSN, .NET 메신저 등)와 같은 상용 메신저의 사용 금지
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-05  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >> Messeger_check.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >>  Messeger_check.txt

::type Messagner_check.txt | find /i "KakaoTalk" 
findstr /I "Kakao" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "카카오톡" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "NATEON" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /L "LINE" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "Telegram" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Good       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 상용메신저가 설치되어 있지 않으므로 양호함          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-05-Messenger-END

:PC-05-Messenger-fail

ECHO [Result]: Weak                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ECHO [Comment]: 상용메신저가 설치되어 있으므로 취약함         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type Messeger_check.txt | findstr /I "KakaoTalk"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "카카오톡"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "NATEON"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "LINE"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "Telegram"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del Messeger_check.txt   

:PC-05-Messenger-END

chcp 437

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 상용 메신저를 사용하지 않는 경우 양호                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-05 END




:: pc-06 HOT FIX 등 최신 보안패치 적용
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-06                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: HOT FIX 등 최신 보안패치 적용이 되어 있는지 확인필요                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                          
wmic QFE Get HotFixID,InstalledOn,Description  > hotfix.txt
type hotfix.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ver
del hotfix.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 서비스팩 및 Hotfix 적용 점검                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. HOTFIX 수량 및 최신 핫픽스 체크       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. HOT FIX 설치 및 자동 업데이트 설정이 되어 있는 경우 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-06 END




:: pc-07 최신 서비스팩 적용
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-07                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 최신서비스팩 적용되어 있는지 확인필요                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type systeminfo.txt | find /i "os name" 				    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    						   
type systeminfo.txt | find /i "version" | find /V "BIOS"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS 별 최신 서비스팩(빌드) 확인 후 진단                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. OS 별 서비스팩(빌드) 상이함                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 유효한 빌드 버전을 사용하는 경우 양호                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 2020.01.14 기준 Windows 7 지원 종료(취약)                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-07 END




chcp 949
:: pc-08 바이러스 백신 프로그램 설치 및 주기적 업데이트
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-08	    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 백신이 설치되어 있고 최신 업데이트로 적용되어 있는지 확인필요    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt     
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName, productState > antiviruslist.txt
type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [Check]:                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 백신 업데이트 여부                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. 아무값도 나오지 않으면 백신 설치여부 항목  및 인터뷰를 통해 진단             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. 백신이 설치되어 있고, 최신 업데이트가 적용 되어 있는 경우 양호(설치된 백신, 정의 업데이트 날자로 판단)             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-08 END





:: pc-09 바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-09            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get productState | findstr /v /r /c:"^$" /c:"^\ *$" /c:"productState" > RTProtect_check.txt

chcp 437
type RTProtect_check.txt | find "266240"
IF NOT ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
type RTProtect_check.txt | find "266240"

IF NOT ERRORLEVEL 1 echo [Commnet]: 실시간 감시가 활성화 되어 있으므로 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Commnet]: 실시간 감시가 비활성화 되어 있으므로 취약함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del antiviruslist.txt
del RTProtect_check.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: 수동점검으로 백신 프로그램이 설치되어 있는지 확인하고 실시간 감시 기능이 활성화 되어 있는지 확인  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-09 END







REM PC-10번 분기점 ############################
type systeminfo.txt | find /i "OS Name" | find /i "windows xp"

IF NOT ERRORLEVEL 1 goto 64-bit-xp-10-check 

type systeminfo.txt | find /i "OS Name" | findstr /i "7 10 11"

IF NOT ERRORLEVEL 1 goto 64-bit-win7-10-check



:64-bit-xp-10-check
:: pc-10 OS에서 제공하는 침입차단 기능 활성화
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Comment]: OS 에서 제공하는 방화벽이 비활성화 되어있어 취약함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: OS 에서 제공하는 방화벽이 활성화 되어있어 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del firewall.txt
										   
goto 64-bit-10-end

:64-bit-win7-10-check
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

reg query "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" | find /i "EnableFirewall" > firewall2.txt

type firewall.txt | find "x1" 

if ERRORLEVEL 1 goto 64-bit-win7-10-fail

type firewall2.txt | find "x1" 

if ERRORLEVEL 1 goto 64-bit-win7-10-fail

echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS 에서 제공하는 방화벽이 활성화 되어있어 양호함    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 홈 또는 회사(개인)네트워크 방화벽체크                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 공용 네트워크 방화벽체크                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-bit-10-end

:64-bit-win7-10-fail
echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS 에서 제공하는 방화벽이 비활성화 되어있어 취약함     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 홈 또는 회사(개인)네트워크 방화벽체크    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 공용 네트워크 방화벽체크               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:64-bit-10-end						   

del firewall.txt
del firewall2.txt
		
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS에서 제공하는 침입차단 기능 활성화                                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. EnableFirewall = x0 - (방화벽 미사용)취약      										 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. EnableFirewall = x1 - (방화벽 사용)양호       									     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-10 END




















:: pc-11 화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-11                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveActive"                             >  logoff1.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaverIsSecure"                          >  logoff2.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveTimeOut"                            >  logoff3.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                             >  logoff1.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                          >  logoff2.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                            >  logoff3.txt

echo [Result] : Info>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment] :>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- Edit group policy 확인 ----                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- 화면보호기 설정 확인 ----                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-bit-logoff-end

:64-bit-logoff-end

del logoff1.txt
del logoff2.txt
del logoff3.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 화면보호기 설정                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ScreenSaveActive    = 화면보호기 작동유무                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ScreenSaverIsSecure = 데이터 값이 0, 1에 상관없이 무조건 다시시작할때 암호로 보호        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. ScreenSaveTimeOut   = 대기 시간 설정 초 단위                                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ScreenSaveActive, ScreenSaverIsSecure 값은 1 이 양호                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ScreenSaveTimeOut값은 600이하 양호                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Edit group policy의 값이 출력되지 않으면 '구성되지 않음' 상태                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. Edit group policy가 상위 설정이므로 값이 하나라도 출력될 경우 해당 위치에서 정책 확인                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-11 END





:: pc-12 CD, DVD, USB메모리 등과 같은 미디어의 자동실행 방지 등 이동식 미디어에 대한 보안대책 수립
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-12   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 미디어 사용 시 자동 실행되는지 확인필요   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 가. Autorun.inf 파일 설정 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 나. Shell Hardware Detection 서비스 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Shell Hardware Detection"                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 다. 레지스트리 설정 확인                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 라. Windows 10 자동실행 방지 레지스트리 값(DisableAutoplay) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
REM echo Windows 10 자동실행 방지 레지스트리 값(DisableAutoplay) >> WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" | find /i "DisableAutoplay" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 437

echo [Check]:                                                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. CD, DVD, USB메모리 등과 같은 미디어의 자동실행 방지 등 이동식 미디어에 대한 보안대책 수립                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Autorun.inf의 기본값 : @SYS:DoesNotExist 또는 @SYS:NoWhere 값이 들어가있으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Autorun.inf의 기본값 : 아무값도 없으면 취약                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Autorun.inf의 기본값 : 아무값도 없으면 취약                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Shell Hardware Detection 서비스가 확인되지 않으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. 레지스트리 NoDriveTypeAutoRun 값이 Windows 2000: 95, Windows XP: 91, Windows Server 2003: 95, Windows Vista, Server 2008 and 7: 91 으로 되어 있을 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. DisableAutoplay 값이 1인 경우 양호 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-12 END




:: pc-13 비인가 무선랜 사용제한
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-13   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: 비인가 무선랜을 사용하고 있지 않은지 확인필요  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 무선랜 접속 이력 확인 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show profile >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 무선랜 필터 정책 확인 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show filter 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 네트워크 별 접속 시간 확인                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. 무선 자동 구성 시스템(wlansvc)이 실행중이지 않으면 양호       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. 비인가 된 무선랜 접속 이력이 있을 시 무선랜 접속 시간 확인 후 판단                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. DateCreated: 최초 연결한 날짜                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. DateLastConnected: 마지막으로 연결한 날짜                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. 리틀엔디언으로 되어 있으므로 치환 하여 확인                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ex) e1 07 09 00 02 00 13 00 0f 00 18 00 33 00 dd 03                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. 년도: e1 07 - 07 e1 으로 변환 후 10진수로 변환 - 2017년                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. 월: 09 00 - 00 09 - 09월 							>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 9. 요일: 02 00 - 00 02 - 화요일( 00 부터 06까지 일 ~ 토) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 10. 날짜: 13 00 - 00 13 - 13일						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 11. 시간: 0f 00 - 00 0f - 15시						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 12. 분: 18 00 - 00 18 - 18분					      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 13. 초: 33 00 - 00 33 - 33초						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 14. Thousandths: dd 03 - 03 dd - 989               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:end-pc-check


del systeminfo.txt

									            
:END
echo ####################################   END Time  ####################################   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
date /t                                                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
time /t                                                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ################################   APPLY SCRIPT CREATION  ###########################  
chcp 949



Echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del %COMPUTERNAME%-result.xml
del ..\set
del user.txt
del set
@echo off


echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo #################################################################
echo ###                                                           ###
echo ###        Windows Desktop Security Check is Finished         ###
echo ###                                                           ###
echo #################################################################
echo.
echo.
echo.
echo.
echo.
echo.
pause
EXIT