
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

echo ************������ �������� �������ּ���.************
echo �ش� �ý����� IP �ּҸ� �Է����ּ���.
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

:: pc-01 �н������� �ֱ��� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-01 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ִ� ��ȣ ��� �Ⱓ�� Ȯ���ϰ� Ȱ�� �������� ����Ǿ� �ִ��� Ȯ���ʿ� >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "�ִ� ��ȣ"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "�ּ� ��ȣ ���"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "��ȣ ��� ����"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net user   > user.txt
type user.txt | find /V "--" | find /V "�����߽��ϴ�." | find /V "����� ����" > usercheck.txt 
REM FOR /F "tokens=1" %%a in (user2.txt) do SET KISATEMP=%%a



net accounts | find "Maximum password"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                         

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Minimum password age"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Length of password history maintained"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


FOR /F "tokens=1" %%a IN (usercheck.txt) DO net user %%a | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=2" %%b IN (usercheck.txt) DO net user %%b | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=3" %%c IN (usercheck.txt) DO net user %%c | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=4" %%d IN (usercheck.txt) DO net user %%d | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=5" %%e IN (usercheck.txt) DO net user %%e | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    

chcp 437

del usercheck.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� �ְ� Ȱ�������� �����Ǿ� �ִ� ��� ��ȣ        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-01 END




:: pc-02 �н����� ��å�� �ش����� ������å�� �����ϰ� ����
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
echo [Comment]: �н����� ��å�� �����ϰ� �����Ǿ� ���� �����Ƿ� �����                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length" 						                                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
goto length-end


:length-SETTING-OK
     
echo [Result]: Good   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �н����� ��å�� �����ϰ� �����Ǿ� �����Ƿ� ��ȣ��                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo [Check]: �ּ� ��ȣ ���̰� 8�ڸ� �̻����� �Ǿ� �ְ� ��ȣ ���⵵�� ��å�� �°� �����Ǿ� �ִ� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo �� Minimum password length ���� 8 �̻��̰� PasswordComplexity ���� 1�̸� ��ȣ  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo �� ��å ���� ������ ������ ������ ���� ���⵵ ��å�� �����ϰ� �����Ǿ� �ִ��� ���ͺ� �ʿ� >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-02 END








:: pc-03 �������� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-03                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info                                                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���ʿ��� ���������� �ִ��� Ȯ���ʿ�                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. ���ʿ��� �������� Ȯ��                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo. ������Ʈ�� Ȯ��                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareWks"	>> harddisk-reg.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareServer"	>> harddisk-reg.txt
Type harddisk-reg.txt | Find /I "AutoShareWks"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareWks ������Ʈ������ �������� ����												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
Type harddisk-reg.txt | Find /I "AutoShareServer"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareServer ������Ʈ������ �������� ����												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del harddisk-reg.txt
del share_registry.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. �������� ����                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. $ǥ�õ� �⺻ ���������� �����ϸ� ��� �׿� �������� ������� �� �������� ���� ���ο� ���� �Ǵ�            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. �������丮�� Everyone ���� ���� Ȯ��(Everyone �׷��� �����Ѵٸ� ������� ���Ӱ���) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. �׿� ���ʿ� ����ڰ� ������(F) �� Write ������ �ִٸ� �Ǵ��� ���          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ��ȣ = Everyone ����� ����, �����(Users�׷�����)�� ���ѿ� ������� �ź�                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ��� = Everyone ����� ����, �����(Users�׷�����)�� ���ѿ� ������� ���                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. ����� ������ �������(F) Ȥ�� FILE_WRITE_DATA���� �����Ѵٸ� ���             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-03 END






:: pc-04 ���ʿ��� ���� ����
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
IF ERRORLEVEL 1 echo [Comment]: �ֿ�������ű�ݽü� ����� ����� �м� �� ��� �󼼰��̵忡�� ������ ���ʿ��� ���񽺰� �������� �����Ƿ� ��ȣ��                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Alerter ���� �̱���       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Computer Browser ���� �̱���       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Fast User Switching Compatibility ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Messenger ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Netmeeting Remote Desktop Sharing ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Telnet ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


goto PC-04-SERVICE-END


:PC-04-SERVICE-fail

echo [Result]: Weak                                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ֿ�������ű�ݽü� ����� ����� �м� �� ��� �󼼰��̵忡�� ������ ���ʿ��� ���񽺰� ���������� �����                                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ���ʿ� ���� ���� �������� �׸�                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo 1. ���ʿ��� ���� ����                                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Alerter(xp������) = �������� Ŭ���̾�Ʈ�� ���޼����� ����                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Computer Browser(���OS ����) = ��Ʈ��ũ�� �ִ� ��� ��ǻ�� ����� �����ϰ� �����ϸ� �� ����� �������� ������ ��ǻ�Ϳ� �����ϴ� ����                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Fast User Switching Compatibility(xp������) = ���� ����� �������� ����ϴ� ��ǻ�Ϳ��� ��ǻ�͸� �̿��ϴ� �̿��ڰ� �α׿������� ���� ä �ٸ� ����ڰ� �α׿��Ͽ� ��ǻ�͸� ����� �� �ְ� �Ѵ�.      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Messenger(xp������) = ��Ʈ��ũ�󿡼� �޽����� �����ϴ� ����� �ϴ� ���񽺷ν�, ���α��� ���� ���Ը޽����� �� ���񽺸� ���� ����������.                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. Netmeeting Remote Desktop Sharing(xp�� ����) = �ڽ��� ��ǻ�Ϳ� �������� ������ �� �ֵ��� ����ϰ� �ٸ� ��ǻ�Ϳ� ���� ȭ�� ���� ������ ����� �� �ְ� �ϴ� ����                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Telnet(���OS ����) = ���� ����ڰ� �����Ͽ� ���ϰ˻�, ���� �� ���� ��ɾ �����ų �� �ְ� �ϴ� ����        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. ���ǻ��� = �˻�� �ش� �ܾ �����ϴ� ���񽺰� ������� ��Ž���ɼ������� Ȯ�� ��� .                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-04 END





:: pc-05 Windows Messenger(MSN, .NET �޽��� ��)�� ���� ��� �޽����� ��� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-05  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >> Messeger_check.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >>  Messeger_check.txt

::type Messagner_check.txt | find /i "KakaoTalk" 
findstr /I "Kakao" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "īī����" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "NATEON" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /L "LINE" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "Telegram" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Good       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���޽����� ��ġ�Ǿ� ���� �����Ƿ� ��ȣ��          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-05-Messenger-END

:PC-05-Messenger-fail

ECHO [Result]: Weak                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ECHO [Comment]: ���޽����� ��ġ�Ǿ� �����Ƿ� �����         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type Messeger_check.txt | findstr /I "KakaoTalk"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "īī����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "NATEON"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "LINE"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "Telegram"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del Messeger_check.txt   

:PC-05-Messenger-END

chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: ��� �޽����� ������� �ʴ� ��� ��ȣ                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-05 END





:: pc-06 HOT FIX �� �ֽ� ������ġ ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-06                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: HOT FIX �� �ֽ� ������ġ ������ �Ǿ� �ִ��� Ȯ���ʿ�                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic QFE Get HotFixID,InstalledOn,Description  > hotfix.txt
type hotfix.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del hotfix.txt
ver >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ������ �� Hotfix ���� ����                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. HOTFIX ���� �� �ֽ� ���Ƚ� üũ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. HOT FIX ��ġ �� �ڵ� ������Ʈ ������ �Ǿ� �ִ� ��� ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-06 END






:: pc-07 �ֽ� ������ ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-07                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ֽż����� ����Ǿ� �ִ��� Ȯ���ʿ�                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type systeminfo.txt | find /i "os name" 				    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    						   
type systeminfo.txt | find /i "version" | find /V "BIOS"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [PC-07] END  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [PC-07] ����   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS �� �ֽ� ������(����) Ȯ�� �� ����                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. OS �� ������(����) ������                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ��ȿ�� ���� ������ ����ϴ� ��� ��ȣ                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 2020.01.14 ���� Windows 7 ���� ����(���)                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-07 END








chcp 949
:: pc-08 ���̷��� ��� ���α׷� ��ġ �� �ֱ��� ������Ʈ
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-08	    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ����� ��ġ�Ǿ� �ְ� �ֽ� ������Ʈ�� ����Ǿ� �ִ��� Ȯ���ʿ�    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt     
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName, productState > antiviruslist.txt
type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [Check]:                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ��� ������Ʈ ����                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. �ƹ����� ������ ������ ��� ��ġ���� �׸�  �� ���ͺ並 ���� ����             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ����� ��ġ�Ǿ� �ְ�, �ֽ� ������Ʈ�� ���� �Ǿ� �ִ� ��� ��ȣ(��ġ�� ���, ���� ������Ʈ ���ڷ� �Ǵ�)             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-08 END









:: pc-09 ���̷��� ��� ���α׷����� �����ϴ� �ǽð� ���� ��� Ȱ��ȭ
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

IF NOT ERRORLEVEL 1 echo [Commnet]: �ǽð� ���ð� Ȱ��ȭ �Ǿ� �����Ƿ� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Commnet]: �ǽð� ���ð� ��Ȱ��ȭ �Ǿ� �����Ƿ� �����    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del antiviruslist.txt
del RTProtect_check.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: ������������ ��� ���α׷��� ��ġ�Ǿ� �ִ��� Ȯ���ϰ� �ǽð� ���� ����� Ȱ��ȭ �Ǿ� �ִ��� Ȯ��  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-09 END













REM PC-10�� �б��� ############################



type systeminfo.txt | find /i "OS Name" | find /i "windows xp" 

IF NOT ERRORLEVEL 1 goto 32-bit-xp-10-check 

type systeminfo.txt | find /i "OS Name" | findstr /i "7 10"

IF NOT ERRORLEVEL 1 goto 32-bit-win7-10-check




:32-bit-xp-10-check


:: pc-10 OS���� �����ϴ� ħ������ ��� Ȱ��ȭ
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Comment]: OS ���� �����ϴ� ��ȭ���� Ȱ��ȭ �Ǿ��־� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: OS ���� �����ϴ� ��ȭ���� ��Ȱ��ȭ �Ǿ��־� �����    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo [Comment]: OS ���� �����ϴ� ��ȭ���� Ȱ��ȭ �Ǿ��־� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Ȩ �Ǵ� ȸ��(����)��Ʈ��ũ ��ȭ��üũ                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ���� ��Ʈ��ũ ��ȭ��üũ                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 32-bit-10-end

:32-bit-win7-10-fail
echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS ���� �����ϴ� ��ȭ���� ��Ȱ��ȭ �Ǿ��־� �����     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Ȩ �Ǵ� ȸ��(����)��Ʈ��ũ ��ȭ��üũ    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ���� ��Ʈ��ũ ��ȭ��üũ               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:32-bit-10-end						   

del firewall.txt
del firewall2.txt
		
		
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS���� �����ϴ� ħ������ ��� Ȱ��ȭ                                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. EnableFirewall = x0 - (��ȭ�� �̻��)���      										 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. EnableFirewall = x1 - (��ȭ�� ���)��ȣ       									     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
:: pc-10 END
















:: pc-11 ȭ�麸ȣ�� ��� �ð� ���� �� ����� �� ��ȣ ��ȣ ����
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
echo ---- Edit group policy Ȯ�� ----                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- ȭ�麸ȣ�� ���� Ȯ�� ----                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo 1. ȭ�麸ȣ�� ����                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ScreenSaveActive    = ȭ�麸ȣ�� �۵�����                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ScreenSaverIsSecure = ������ ���� 0, 1�� ������� ������ �ٽý����Ҷ� ��ȣ�� ��ȣ        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. ScreenSaveTimeOut   = ��� �ð� ���� �� ����                                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ScreenSaveActive, ScreenSaverIsSecure ���� 1 �� ��ȣ                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ScreenSaveTimeOut���� 600���� ��ȣ                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Edit group policy�� ���� ��µ��� ������ '�������� ����' ����                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. Edit group policy�� ���� �����̹Ƿ� ���� �ϳ��� ��µ� ��� �ش� ��ġ���� ��å Ȯ��                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-11 END








:: pc-12 CD, DVD, USB�޸� ��� ���� �̵���� �ڵ����� ���� �� �̵��� �̵� ���� ���ȴ�å ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-12   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �̵�� ��� �� �ڵ� ����Ǵ��� Ȯ���ʿ�   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Autorun.inf ���� ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Shell Hardware Detection ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Shell Hardware Detection"                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. ������Ʈ�� ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Windows 10 �ڵ����� ���� ������Ʈ�� ��(DisableAutoplay) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
REM echo Windows 10 �ڵ����� ���� ������Ʈ�� ��(DisableAutoplay) >> WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" | find /i "DisableAutoplay" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt



chcp 437
echo [Check]:                                                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. CD, DVD, USB�޸� ��� ���� �̵���� �ڵ����� ���� �� �̵��� �̵� ���� ���ȴ�å ����                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Autorun.inf�� �⺻�� : @SYS:DoesNotExist �Ǵ� @SYS:NoWhere ���� �������� ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Autorun.inf�� �⺻�� : �ƹ����� ������ ���                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Autorun.inf�� �⺻�� : �ƹ����� ������ ���                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Shell Hardware Detection ���񽺰� Ȯ�ε��� ������ ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ������Ʈ�� NoDriveTypeAutoRun ���� Windows 2000: 95, Windows XP: 91, Windows Server 2003: 95, Windows Vista, Server 2008 and 7: 91 ���� �Ǿ� ���� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. DisableAutoplay ���� 1�� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-12 END





:: pc-13 ���ΰ� ������ �������
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-13   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���ΰ� �������� ����ϰ� ���� ������ Ȯ���ʿ�  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ������ ���� �̷� Ȯ�� 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show profile >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��Ʈ��ũ �� ���� �ð� Ȯ��                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ���� �ڵ� ���� �ý���(wlansvc)�� ���������� ������ ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ���ΰ� �� ������ ���� �̷��� ���� �� ������ ���� �ð� Ȯ�� �� �Ǵ�                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. DateCreated: ���� ������ ��¥                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. DateLastConnected: ���������� ������ ��¥                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ��Ʋ��������� �Ǿ� �����Ƿ� ġȯ �Ͽ� Ȯ��                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ex) e1 07 09 00 02 00 13 00 0f 00 18 00 33 00 dd 03                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. �⵵: e1 07 - 07 e1 ���� ��ȯ �� 10������ ��ȯ - 2017��                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. ��: 09 00 - 00 09 - 09�� 							>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 9. ����: 02 00 - 00 02 - ȭ����( 00 ���� 06���� �� ~ ��) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 10. ��¥: 13 00 - 00 13 - 13��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 11. �ð�: 0f 00 - 00 0f - 15��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 12. ��: 18 00 - 00 18 - 18��					      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 13. ��: 33 00 - 00 33 - 33��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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

echo 64��Ʈ�� üũ�غ��ô�.    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:: pc-01 �н������� �ֱ��� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-01 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ִ� ��ȣ ��� �Ⱓ�� Ȯ���ϰ� Ȱ�� �������� ����Ǿ� �ִ��� Ȯ���ʿ� >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "�ִ� ��ȣ"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "�ּ� ��ȣ ���"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find /i "��ȣ ��� ����"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net user   > user.txt
type user.txt | find /V "--" | find /V "�����߽��ϴ�." | find /V "����� ����" > usercheck.txt 
REM FOR /F "tokens=1" %%a in (user2.txt) do SET KISATEMP=%%a



net accounts | find "Maximum password"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                         

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Minimum password age"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

net accounts | find /i "Length of password history maintained"							     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


FOR /F "tokens=1" %%a IN (usercheck.txt) DO net user %%a | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=2" %%b IN (usercheck.txt) DO net user %%b | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=3" %%c IN (usercheck.txt) DO net user %%c | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=4" %%d IN (usercheck.txt) DO net user %%d | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    
FOR /F "tokens=5" %%e IN (usercheck.txt) DO net user %%e | find /V "��ü �̸�" | find /V "����" | find /V "����� ����" | find /V "���� �ڵ�" | find /V "��ũ�����̼�" | find /V "��ũ��Ʈ" | find /V "������" | find /V "���͸�" | find /V "�����߽��ϴ�" | find /V "������" | find /V "����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    

chcp 437

del usercheck.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� �ְ� Ȱ�������� �����Ǿ� �ִ� ��� ��ȣ        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-01 END




:: pc-02 �н����� ��å�� �ش����� ������å�� �����ϰ� ����
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
echo [Comment]: �н����� ��å�� �����ϰ� �����Ǿ� ���� �����Ƿ� �����                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net accounts | find "length" 						                                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type LocalSecurityPolicy.txt | find /i "PasswordComplexity"								     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-length-end

:64-length-SETTING-OK
     
echo [Result]: Good   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �н����� ��å�� �����ϰ� �����Ǿ� �����Ƿ� ��ȣ��                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo [Check]: �ּ� ��ȣ ���̰� 8�ڸ� �̻����� �Ǿ� �ְ� ��ȣ ���⵵�� ��å�� �°� �����Ǿ� �ִ� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo �� Minimum password length ���� 8 �̻��̰� PasswordComplexity ���� 1�̸� ��ȣ  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo �� ��å ���� ������ ������ ������ ���� ���⵵ ��å�� �����ϰ� �����Ǿ� �ִ��� ���ͺ� �ʿ� >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-02 END











:: pc-03 �������� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-03                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info                                                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���ʿ��� ���������� �ִ��� Ȯ���ʿ�                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. ���ʿ��� �������� Ȯ��                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo. ������Ʈ�� Ȯ��                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareWks"	>> harddisk-reg.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" | Find /I "AutoShareServer"	>> harddisk-reg.txt
Type harddisk-reg.txt | Find /I "AutoShareWks"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareWks ������Ʈ������ �������� ����												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
Type harddisk-reg.txt | Find /I "AutoShareServer"                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
if ERRORLEVEL 1 echo AutoShareServer ������Ʈ������ �������� ����												>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del harddisk-reg.txt
del share_registry.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. �������� ����                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. $ǥ�õ� �⺻ ���������� �����ϸ� ��� �׿� �������� ������� �� �������� ���� ���ο� ���� �Ǵ�            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. �������丮�� Everyone ���� ���� Ȯ��(Everyone �׷��� �����Ѵٸ� ������� ���Ӱ���) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. �׿� ���ʿ� ����ڰ� ������(F) �� Write ������ �ִٸ� �Ǵ��� ���          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ��ȣ = Everyone ����� ����, �����(Users�׷�����)�� ���ѿ� ������� �ź�                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ��� = Everyone ����� ����, �����(Users�׷�����)�� ���ѿ� ������� ���                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. ����� ������ �������(F) Ȥ�� FILE_WRITE_DATA���� �����Ѵٸ� ���             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-03 END




:: pc-04 ���ʿ��� ���� ����
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
IF ERRORLEVEL 1 echo [Comment]: �ֿ�������ű�ݽü� ����� ����� �м� �� ��� �󼼰��̵忡�� ������ ���ʿ��� ���񽺰� �������� �����Ƿ� ��ȣ��                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Alerter ���� �̱���       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Computer Browser ���� �̱���       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Fast User Switching Compatibility ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Messenger ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Netmeeting Remote Desktop Sharing ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Telnet ���� �̱���  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-04-SERVICE-END


:PC-04-SERVICE-fail

echo [Result]: Weak                                                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ֿ�������ű�ݽü� ����� ����� �м� �� ��� �󼼰��̵忡�� ������ ���ʿ��� ���񽺰� ���������� �����                                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo -----���ʿ� ���� ���� �������� �׸�-------                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo 1. ���ʿ��� ���� ����                                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Alerter(xp������) = �������� Ŭ���̾�Ʈ�� ���޼����� ����                         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Computer Browser(���OS ����) = ��Ʈ��ũ�� �ִ� ��� ��ǻ�� ����� �����ϰ� �����ϸ� �� ����� �������� ������ ��ǻ�Ϳ� �����ϴ� ����                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Fast User Switching Compatibility(xp������) = ���� ����� �������� ����ϴ� ��ǻ�Ϳ��� ��ǻ�͸� �̿��ϴ� �̿��ڰ� �α׿������� ���� ä �ٸ� ����ڰ� �α׿��Ͽ� ��ǻ�͸� ����� �� �ְ� �Ѵ�.      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Messenger(xp������) = ��Ʈ��ũ�󿡼� �޽����� �����ϴ� ����� �ϴ� ���񽺷ν�, ���α��� ���� ���Ը޽����� �� ���񽺸� ���� ����������.                              >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. Netmeeting Remote Desktop Sharing(xp�� ����) = �ڽ��� ��ǻ�Ϳ� �������� ������ �� �ֵ��� ����ϰ� �ٸ� ��ǻ�Ϳ� ���� ȭ�� ���� ������ ����� �� �ְ� �ϴ� ����                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Telnet(���OS ����) = ���� ����ڰ� �����Ͽ� ���ϰ˻�, ���� �� ���� ��ɾ �����ų �� �ְ� �ϴ� ����        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. ���ǻ��� = �˻�� �ش� �ܾ �����ϴ� ���񽺰� ������� ��Ž���ɼ������� Ȯ�� ��� .                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-04 END




:: pc-05 Windows Messenger(MSN, .NET �޽��� ��)�� ���� ��� �޽����� ��� ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-05  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 949
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >> Messeger_check.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s | find /I "DisplayName" >>  Messeger_check.txt

::type Messagner_check.txt | find /i "KakaoTalk" 
findstr /I "Kakao" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "īī����" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "NATEON" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /L "LINE" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail
findstr /I "Telegram" Messeger_check.txt > NUL
IF NOT ERRORLEVEL 1 goto PC-05-Messenger-fail

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Good       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���޽����� ��ġ�Ǿ� ���� �����Ƿ� ��ȣ��          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto PC-05-Messenger-END

:PC-05-Messenger-fail

ECHO [Result]: Weak                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ECHO [Comment]: ���޽����� ��ġ�Ǿ� �����Ƿ� �����         >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type Messeger_check.txt | findstr /I "KakaoTalk"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "īī����"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "NATEON"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "LINE"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type Messeger_check.txt | findstr /I "Telegram"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del Messeger_check.txt   

:PC-05-Messenger-END

chcp 437

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: ��� �޽����� ������� �ʴ� ��� ��ȣ                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-05 END




:: pc-06 HOT FIX �� �ֽ� ������ġ ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-06                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: HOT FIX �� �ֽ� ������ġ ������ �Ǿ� �ִ��� Ȯ���ʿ�                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt                                          
wmic QFE Get HotFixID,InstalledOn,Description  > hotfix.txt
type hotfix.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
ver
del hotfix.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ������ �� Hotfix ���� ����                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. HOTFIX ���� �� �ֽ� ���Ƚ� üũ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. HOT FIX ��ġ �� �ڵ� ������Ʈ ������ �Ǿ� �ִ� ��� ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-06 END




:: pc-07 �ֽ� ������ ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-07                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �ֽż����� ����Ǿ� �ִ��� Ȯ���ʿ�                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type systeminfo.txt | find /i "os name" 				    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt    						   
type systeminfo.txt | find /i "version" | find /V "BIOS"  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS �� �ֽ� ������(����) Ȯ�� �� ����                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. OS �� ������(����) ������                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ��ȿ�� ���� ������ ����ϴ� ��� ��ȣ                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. 2020.01.14 ���� Windows 7 ���� ����(���)                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-07 END




chcp 949
:: pc-08 ���̷��� ��� ���α׷� ��ġ �� �ֱ��� ������Ʈ
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-08	    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ����� ��ġ�Ǿ� �ְ� �ֽ� ������Ʈ�� ����Ǿ� �ִ��� Ȯ���ʿ�    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt     
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName, productState > antiviruslist.txt
type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 437
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo [Check]:                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ��� ������Ʈ ����                                             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. �ƹ����� ������ ������ ��� ��ġ���� �׸�  �� ���ͺ並 ���� ����             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ����� ��ġ�Ǿ� �ְ�, �ֽ� ������Ʈ�� ���� �Ǿ� �ִ� ��� ��ȣ(��ġ�� ���, ���� ������Ʈ ���ڷ� �Ǵ�)             >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-08 END





:: pc-09 ���̷��� ��� ���α׷����� �����ϴ� �ǽð� ���� ��� Ȱ��ȭ
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

IF NOT ERRORLEVEL 1 echo [Commnet]: �ǽð� ���ð� Ȱ��ȭ �Ǿ� �����Ƿ� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Commnet]: �ǽð� ���ð� ��Ȱ��ȭ �Ǿ� �����Ƿ� �����    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type antiviruslist.txt >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

del antiviruslist.txt
del RTProtect_check.txt

echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]: ������������ ��� ���α׷��� ��ġ�Ǿ� �ִ��� Ȯ���ϰ� �ǽð� ���� ����� Ȱ��ȭ �Ǿ� �ִ��� Ȯ��  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-09 END







REM PC-10�� �б��� ############################
type systeminfo.txt | find /i "OS Name" | find /i "windows xp"

IF NOT ERRORLEVEL 1 goto 64-bit-xp-10-check 

type systeminfo.txt | find /i "OS Name" | findstr /i "7 10 11"

IF NOT ERRORLEVEL 1 goto 64-bit-win7-10-check



:64-bit-xp-10-check
:: pc-10 OS���� �����ϴ� ħ������ ��� Ȱ��ȭ
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-10            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | find /i "EnableFirewall" > firewall.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Result]: Good    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

type firewall.txt | find "x1" 
IF NOT ERRORLEVEL 1 echo [Comment]: OS ���� �����ϴ� ��ȭ���� ��Ȱ��ȭ �Ǿ��־� �����    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
IF ERRORLEVEL 1 echo [Comment]: OS ���� �����ϴ� ��ȭ���� Ȱ��ȭ �Ǿ��־� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo [Comment]: OS ���� �����ϴ� ��ȭ���� Ȱ��ȭ �Ǿ��־� ��ȣ��    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Ȩ �Ǵ� ȸ��(����)��Ʈ��ũ ��ȭ��üũ                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ���� ��Ʈ��ũ ��ȭ��üũ                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

goto 64-bit-10-end

:64-bit-win7-10-fail
echo [Result]: Weak    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: OS ���� �����ϴ� ��ȭ���� ��Ȱ��ȭ �Ǿ��־� �����     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo Ȩ �Ǵ� ȸ��(����)��Ʈ��ũ ��ȭ��üũ    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ���� ��Ʈ��ũ ��ȭ��üũ               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
type firewall2.txt  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt


:64-bit-10-end						   

del firewall.txt
del firewall2.txt
		
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                                                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. OS���� �����ϴ� ħ������ ��� Ȱ��ȭ                                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. EnableFirewall = x0 - (��ȭ�� �̻��)���      										 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. EnableFirewall = x1 - (��ȭ�� ���)��ȣ       									     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
del servicepack.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-10 END




















:: pc-11 ȭ�麸ȣ�� ��� �ð� ���� �� ����� �� ��ȣ ��ȣ ����
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
echo ---- Edit group policy Ȯ�� ----                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveActive"                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaverIsSecure"                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | find "ScreenSaveTimeOut"                                    >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ---- ȭ�麸ȣ�� ���� Ȯ�� ----                               >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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
echo 1. ȭ�麸ȣ�� ����                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ScreenSaveActive    = ȭ�麸ȣ�� �۵�����                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. ScreenSaverIsSecure = ������ ���� 0, 1�� ������� ������ �ٽý����Ҷ� ��ȣ�� ��ȣ        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. ScreenSaveTimeOut   = ��� �ð� ���� �� ����                                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ScreenSaveActive, ScreenSaverIsSecure ���� 1 �� ��ȣ                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ScreenSaveTimeOut���� 600���� ��ȣ                                                      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. Edit group policy�� ���� ��µ��� ������ '�������� ����' ����                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. Edit group policy�� ���� �����̹Ƿ� ���� �ϳ��� ��µ� ��� �ش� ��ġ���� ��å Ȯ��                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-11 END





:: pc-12 CD, DVD, USB�޸� ��� ���� �̵���� �ڵ����� ���� �� �̵��� �̵� ���� ���ȴ�å ����
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
chcp 949
echo [ID]: PC-12   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: �̵�� ��� �� �ڵ� ����Ǵ��� Ȯ���ʿ�   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Autorun.inf ���� ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Shell Hardware Detection ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
net start | find /I "Shell Hardware Detection"                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. ������Ʈ�� ���� Ȯ��                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoActiveDesktop"   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��. Windows 10 �ڵ����� ���� ������Ʈ�� ��(DisableAutoplay) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
REM echo Windows 10 �ڵ����� ���� ������Ʈ�� ��(DisableAutoplay) >> WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" | find /i "DisableAutoplay" >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo. >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt

chcp 437

echo [Check]:                                                                                   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. CD, DVD, USB�޸� ��� ���� �̵���� �ڵ����� ���� �� �̵��� �̵� ���� ���ȴ�å ����                                                                       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. Autorun.inf�� �⺻�� : @SYS:DoesNotExist �Ǵ� @SYS:NoWhere ���� �������� ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. Autorun.inf�� �⺻�� : �ƹ����� ������ ���                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. Autorun.inf�� �⺻�� : �ƹ����� ������ ���                                     >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. Shell Hardware Detection ���񽺰� Ȯ�ε��� ������ ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ������Ʈ�� NoDriveTypeAutoRun ���� Windows 2000: 95, Windows XP: 91, Windows Server 2003: 95, Windows Vista, Server 2008 and 7: 91 ���� �Ǿ� ���� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. DisableAutoplay ���� 1�� ��� ��ȣ >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: pc-12 END




:: pc-13 ���ΰ� ������ �������
echo ####################################################################################### >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [ID]: PC-13   >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Result]: Info  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Comment]: ���ΰ� �������� ����ϰ� ���� ������ Ȯ���ʿ�  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ������ ���� �̷� Ȯ�� 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show profile >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ������ ���� ��å Ȯ�� 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
netsh wlan show filter 				 >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo ��Ʈ��ũ �� ���� �ð� Ȯ��                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo --------------------------------------------------- >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
:: win7-64-reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo.                                                                                        >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo [Check]:                                          >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 1. ���� �ڵ� ���� �ý���(wlansvc)�� ���������� ������ ��ȣ       >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 2. ���ΰ� �� ������ ���� �̷��� ���� �� ������ ���� �ð� Ȯ�� �� �Ǵ�                            >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 3. DateCreated: ���� ������ ��¥                                                           >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 4. DateLastConnected: ���������� ������ ��¥                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 5. ��Ʋ��������� �Ǿ� �����Ƿ� ġȯ �Ͽ� Ȯ��                                                >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 6. ex) e1 07 09 00 02 00 13 00 0f 00 18 00 33 00 dd 03                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 7. �⵵: e1 07 - 07 e1 ���� ��ȯ �� 10������ ��ȯ - 2017��                                  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 8. ��: 09 00 - 00 09 - 09�� 							>> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 9. ����: 02 00 - 00 02 - ȭ����( 00 ���� 06���� �� ~ ��) >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 10. ��¥: 13 00 - 00 13 - 13��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 11. �ð�: 0f 00 - 00 0f - 15��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 12. ��: 18 00 - 00 18 - 18��					      >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
echo 13. ��: 33 00 - 00 33 - 33��						  >> ..\WinPC_%COMPUTERNAME%_%IPINFO%_%date%.txt
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