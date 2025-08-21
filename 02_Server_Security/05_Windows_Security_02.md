# 7강: 보안취약점(서버보안 Windows) 02

## 개요
Windows 서버 보안의 두 번째 강의로, 고급 계정 관리와 서비스 보안 설정을 중심으로 다룹니다. 관리자 그룹 관리, 패스워드 정책, 원격 접속 제한 등을 학습합니다.

## 주요 내용

### 1. 관리자 그룹에 최소한의 사용자 포함

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- 관리자와 일반 사용자 계정 분리 필요
- 시스템 관리자는 두 개의 계정 사용 권장 (관리용, 일반 업무용)
- 관리자 권한 계정으로 활성화된 바이러스는 시스템에 더 큰 피해

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > LUSRMGR.MSC > 그룹 > Administrators > 속성에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > LUSRMGR.MSC > 그룹 > Administrators > 속성
2. Administrators 그룹에서 불필요한 계정 제거 후 다른 그룹으로 변경

권장사항:
- Administrator 권한을 가지는 유저는 최소한의 숫자로 제한
- 패스워드는 최소 8자 이상으로 숫자+영어+특수문자 혼합 사용
- 관리용 계정과 일반 업무용 계정 분리
```

#### 기준
- **양호**: Administrators 그룹에 관리자 계정이 하나만 존재할 경우
- **취약**: 두 개 이상 존재할 경우

### 2. 최근 암호 기억

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 취약한 계정을 통해 계정 권한이 도용당할 수 있음

#### 보안 이슈
- 동일한 암호를 오래 사용할수록 공격자의 무작위 공격 성공 가능성 증가
- 암호 변경 시 이전 암호 재사용 방지 필요
- 좋은 암호 정책의 효과를 극대화하기 위한 설정

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호 정책에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호 정책
2. "최근 암호 기억"을 12번으로 설정
```

#### 기준
- **양호**: 최근 암호 기억이 12번인 경우
- **취약**: 최근 암호 기억이 12번이 아닌 경우

### 3. 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 서비스 거부 공격에 이용될 수 있음

#### 보안 이슈
- 빈 암호를 사용하는 로컬 계정의 원격 대화형 로그온 제한
- 터미널 서비스, Telnet, FTP 등의 네트워크 서비스를 통한 접근 차단
- 콘솔에서의 대화형 로그온이나 도메인 계정은 영향 없음

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" 정책을 "사용"으로 설정
```

#### 기준
- **양호**: "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" 정책이 "사용"으로 되어 있을 경우
- **취약**: "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" 정책이 "사용안함"으로 되어 있을 경우

### 4. 원격터미널 접속 가능한 사용자 그룹 제한

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 원격으로 서버에 접속하여 데이터 변경/손실 등 해킹할 가능성이 있음

#### 보안 이슈
- 원격터미널 그룹이나 계정을 제한하지 않으면 임의 사용자 접속 가능
- 해당 서버 정보를 임의로 변경하거나 정보 유출 위험
- 사용자 그룹과 계정 설정 및 제한 필요

#### 점검 방법
```
[Windows 2012]
제어판 > 시스템 > 원격설정 -> "원격 탭 메뉴에서 확인"
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 제어판 > 사용자 계정 -> "관리자 계정 이외의 계정 생성한 후"
2. 제어판 > 시스템 > 원격 탭 -> "원격 탭 메뉴에서 (사용자가 이 컴퓨터에 원격으로 연결할 수 있음)에 체크 후 확인
```

#### 기준
- **양호**: 관리자 계정과 이외의 계정을 생성, 권한을 제한 설정 시
- **취약**: 관리자 계정과 이외의 계정을 생성, 권한을 제한 미설정시

### 5. 공유 권한 및 사용자 그룹 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 악의적인 사용자에 의한 접근 제한

#### 보안 이슈
- 기본 공유(C$, D$, Admin$, IPC$) 제외한 공유폴더의 Everyone 그룹 공유 금지
- Everyone이 공유계정에 포함 시 익명 사용자 접근 가능
- 접근 제어를 통한 익명사용자 접근 차단 필요

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > FSMGMT.MSC > 공유에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > FSMGMT.MSC > 공유
2. 사용 권한에서 Everyone으로 된 공유를 제거하고 접근이 필요한 계정의 적절한 권한을 추가
```

#### 기준
- **양호**: 일반공유 디렉터리가 없거나 공유 디렉터리 접근 권한에 Everyone이 없을 경우
- **취약**: 일반공유 디렉터리의 접근 권한에 Everyone이 있을 경우

### 6. 하드디스크 기본 공유 제거

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- 시스템의 기본공유 항목이 제거되지 않으면 모든 시스템 자원 접근 위험
- Nimda 바이러스 등이 이러한 공유기능을 침투 경로로 이용
- IPC$, 일반공유는 예외

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > FSMGMT.MSC > 공유 > 기본공유 선택 > 공유에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > FSMGMT.MSC > 공유 > 기본공유 선택 > 공유 중지
   ("net share 공유이름 /delete"로 공유한 폴더를 공유해제)

2. 레지스트리 설정:
   시작 > 실행 > REGEDIT > 아래 레지스트리 값을 0으로 수정
   (키 값이 없을 경우 새로 생성 DWORD)
   "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer"
```

#### 기준
- **양호**: AutoShareServer가 0이며 기본 공유가 존재하지 않을 경우
- **취약**: AutoShareServer가 1이거나 기본 공유가 존재할 경우

### 7. 불필요한 서비스 제거

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- 시스템에 필요하지 않은 취약한 서비스들이 기본으로 설치되어 실행
- 이러한 서비스나 응용 프로그램은 공격 지점이 될 수 있음
- 사용자 환경에서 필요하지 않은 서비스 제거 필요

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SERVICES.MSC > "해당 서비스 선택" > 속성에서 확인
```

#### 제거 대상 서비스
- MSFtpsvr (FTP Publishing)
- TlntSvr (Telnet)
- W3SVC (World Wide Web Publishing)
- SMTPSVC (Simple Mail Transfer Protocol)

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SERVICES.MSC > "해당 서비스 선택" > 속성
2. 시작유형 -> 사용안함, 시작 상태 -> 중지 설정
```

#### 기준
- **양호**: 아래 서비스가 중지되어 있을 경우
- **취약**: 아래 서비스가 구동중일 경우

### 8. NetBIOS 바인딩 서비스 구동 점검

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 시스템의 주요 정보 유출

#### 보안 이슈
- NetBIOS는 IBM PC를 위한 네트워크 인터페이스 체계
- Windows NT 시스템이 인터넷에 직접 연결 시 공격자가 쉽게 파일시스템 사용 가능
- NetBIOS에 대한 접근 통제 필요

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > ncpa.cpl > 이더넷 > 속성 > TCP/IP > 속성 > [일반]탭 > [고급] > [WINS]탭 > NetBIOS 설정에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
시작 > 실행 > ncpa.cpl > 로컬 영역 연결 > 속성 > TCP/IP > 속성 > [일반]탭 > [고급] > [WINS]탭 > NetBIOS 설정 > TCP/IP에서 NetBIOS 사용 안 함 선택
```

#### 기준
- **양호**: TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우
- **취약**: TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있지 않은 경우

### 9. 원격터미널 접속 타임아웃 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 타인에 의하여 원격으로 정보 습득, 명령어 조작, 임의의 파일 조작

#### 보안 이슈
- 원격제어를 이용한 터미널 접속 후 비활성 상태 방치 위험
- 어떠한 이벤트나 Action이 발생하지 않을 때 자동 종료 필요
- 보안강화를 위한 Timeout 설정 필요

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > gpedit.msc > 컴퓨터구성 > 관리템플릿 > Windows 구성 요소 > 터미널서비스 > 원격 데스크톱 세션 호스트 > 세션시간 제한에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > gpedit.msc를 실행
2. 컴퓨터구성 > 관리템플릿 > Windows 구성 요소 > 터미널서비스 > 원격 데스크톱 세션 호스트 > 세션 시간 제한 확인
3. 활성 원격 데스크톱 서비스 세션에 대한 시간제한 설정에서 Idle session time 세션이 끊어지도록 원하는 시간을 삽입
```

#### 기준
- **양호**: 원격제어시 Timeout을 제어설정을 했을 시
- **취약**: 원격제어시 Timeout을 제어설정을 안했을 시

## 종합 점검 스크립트

```powershell
# Windows 서버 고급 보안 점검 스크립트
# PowerShell 관리자 권한으로 실행 필요

Write-Host "=== Windows 서버 고급 보안 점검 시작 ===" -ForegroundColor Green

# 1. Administrators 그룹 구성원 수 확인
Write-Host "`n1. Administrators 그룹 구성원 확인" -ForegroundColor Yellow
try {
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    Write-Host "  현재 Administrators 그룹 구성원 ($($adminMembers.Count)명):" -ForegroundColor Cyan
    foreach ($member in $adminMembers) {
        Write-Host "    - $($member.Name) ($($member.ObjectClass))" -ForegroundColor Gray
    }
    
    if ($adminMembers.Count -eq 1) {
        Write-Host "  결과: 양호 - 관리자 계정이 1개입니다." -ForegroundColor Green
    } elseif ($adminMembers.Count -eq 2) {
        Write-Host "  결과: 주의 - 관리자 계정이 2개입니다. 필요성을 검토하세요." -ForegroundColor Yellow
    } else {
        Write-Host "  결과: 취약 - 관리자 계정이 너무 많습니다. ($($adminMembers.Count)개)" -ForegroundColor Red
    }
} catch {
    Write-Host "  오류: Administrators 그룹 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 2. 기본 공유 확인
Write-Host "`n2. 기본 공유 확인 (관리자 공유)" -ForegroundColor Yellow
$adminShares = Get-SmbShare | Where-Object { $_.Name -like "*$" -and $_.Name -ne "IPC$" }
if ($adminShares) {
    Write-Host "  발견된 관리자 공유:" -ForegroundColor Cyan
    foreach ($share in $adminShares) {
        Write-Host "    - $($share.Name): $($share.Path)" -ForegroundColor Gray
    }
    Write-Host "  주의: 관리자 공유가 활성화되어 있습니다. 필요하지 않다면 제거를 고려하세요." -ForegroundColor Yellow
} else {
    Write-Host "  결과: 양호 - 관리자 공유가 비활성화되어 있습니다." -ForegroundColor Green
}

# 3. 일반 공유 확인
Write-Host "`n3. 일반 공유 확인" -ForegroundColor Yellow
$generalShares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }
if ($generalShares) {
    Write-Host "  발견된 일반 공유:" -ForegroundColor Cyan
    foreach ($share in $generalShares) {
        Write-Host "    - $($share.Name): $($share.Path)" -ForegroundColor Gray
        # 권한 확인
        try {
            $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $shareAccess | Where-Object { $_.AccountName -eq "Everyone" }
            if ($everyoneAccess) {
                Write-Host "      ⚠️  Everyone 권한이 설정되어 있습니다!" -ForegroundColor Red
            }
        } catch {
            Write-Host "      권한 정보를 확인할 수 없습니다." -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  결과: 양호 - 일반 공유 폴더가 없습니다." -ForegroundColor Green
}

# 4. 중요 서비스 상태 확인
Write-Host "`n4. 보안상 중요한 서비스 상태 확인" -ForegroundColor Yellow
$criticalServices = @("Telnet", "FTPSVC", "W3SVC", "SMTPSVC")
foreach ($serviceName in $criticalServices) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "  ⚠️  $serviceName: 실행 중 - 필요하지 않다면 중지를 고려하세요." -ForegroundColor Yellow
        } else {
            Write-Host "  ✅ $serviceName: 중지됨" -ForegroundColor Green
        }
    } else {
        Write-Host "  ℹ️  $serviceName: 설치되지 않음" -ForegroundColor Gray
    }
}

# 5. 원격 데스크톱 설정 확인
Write-Host "`n5. 원격 데스크톱 설정 확인" -ForegroundColor Yellow
try {
    $rdpEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdpEnabled -eq 0) {
        Write-Host "  원격 데스크톱: 활성화됨" -ForegroundColor Yellow
        Write-Host "  주의: 원격 데스크톱이 활성화되어 있습니다. 보안 설정을 확인하세요." -ForegroundColor Yellow
        
        # RDP 포트 확인
        $rdpPort = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue).PortNumber
        Write-Host "  RDP 포트: $rdpPort" -ForegroundColor Cyan
        
    } else {
        Write-Host "  결과: 양호 - 원격 데스크톱이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Write-Host "  원격 데스크톱 설정을 확인할 수 없습니다." -ForegroundColor Gray
}

# 6. NetBIOS 설정 확인
Write-Host "`n6. NetBIOS over TCP/IP 설정 확인" -ForegroundColor Yellow
try {
    $netAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $netAdapters) {
        $netbiosOption = $adapter.TcpipNetbiosOptions
        if ($netbiosOption -eq 2) {
            Write-Host "  ✅ $($adapter.Description): NetBIOS over TCP/IP 비활성화" -ForegroundColor Green
        } elseif ($netbiosOption -eq 1) {
            Write-Host "  ✅ $($adapter.Description): NetBIOS over TCP/IP 활성화" -ForegroundColor Yellow
        } else {
            Write-Host "  ℹ️  $($adapter.Description): 기본 설정 (DHCP에서 결정)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  NetBIOS 설정을 확인할 수 없습니다." -ForegroundColor Gray
}

Write-Host "`n=== Windows 서버 고급 보안 점검 완료 ===" -ForegroundColor Green
Write-Host "`n권장 사항:" -ForegroundColor Cyan
Write-Host "1. secpol.msc에서 패스워드 정책을 확인하세요." -ForegroundColor White
Write-Host "2. gpedit.msc에서 원격 데스크톱 타임아웃을 설정하세요." -ForegroundColor White
Write-Host "3. services.msc에서 불필요한 서비스를 중지하세요." -ForegroundColor White
Write-Host "4. fsmgmt.msc에서 공유 폴더 권한을 점검하세요." -ForegroundColor White
```

## 레지스트리 보안 설정 스크립트

```batch
@echo off
echo Windows 서버 보안 레지스트리 설정
echo 주의: 실행 전 시스템 백업을 권장합니다.
pause

REM 하드디스크 기본 공유 제거
echo 하드디스크 기본 공유 비활성화...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

REM 원격 레지스트리 서비스 비활성화 (다음 강의에서 다룰 예정)
echo 원격 레지스트리 서비스 비활성화...
sc config "RemoteRegistry" start= disabled
sc stop "RemoteRegistry"

echo 설정 완료. 시스템 재시작 후 적용됩니다.
pause
```

## 참고 자료

### Windows 서비스 관리
- **중지 권장 서비스**: Telnet, FTP, IIS(불필요시), SMTP
- **주의 서비스**: RemoteRegistry, NetBIOS
- **필수 서비스**: Windows Update, Windows Defender

### 원격 접속 보안
1. **RDP 보안 설정**
   - 기본 포트(3389) 변경
   - 네트워크 수준 인증 활성화
   - 세션 타임아웃 설정

2. **계정 정책**
   - 계정 잠금 임계값: 5회
   - 계정 잠금 기간: 30분
   - 암호 기억: 12개

### 공유 폴더 보안
- **기본 공유**: C$, D$, ADMIN$, IPC$ (필요시에만)
- **일반 공유**: Everyone 권한 제거
- **권한 설정**: 최소 권한 원칙 적용