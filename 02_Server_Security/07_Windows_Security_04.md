# 9강: 보안취약점(서버보안 Windows) 04

## 개요
Windows 서버 보안의 네 번째 강의로, 고급 보안 관리 및 시스템 보호 설정을 다룹니다. 레지스트리 보안, 백신 설치, 프린터 드라이버 제한, 세션 관리 등을 학습합니다.

## 주요 내용

### 1. 원격으로 액세스할 수 있는 레지스트리 경로

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 레지스트리 변조

#### 보안 이슈
- Windows의 모든 초기화와 환경설정 정보는 레지스트리에 저장
- 레지스트리 편집기는 원격접속으로도 키 변경 가능하여 매우 위험
- 네트워크를 통한 레지스트리 접근 차단 필요
- 원격 레지스트리 접근에는 관리자 권한 또는 특별한 계정 필요

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SERVICES.MSC > Remote Registry > 속성에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SERVICES.MSC > Remote Registry > 속성
2. "시작유형" -> 사용안함, 서비스 상태 -> 중지
```

**주의사항**: Remote Registry Service를 사용하는 다른 서비스가 있는지 확인 필요
- 서비스 > Remote Registry Service > 등록정보 > 종속성 참고

#### 기준
- **양호**: Remote Registry Service가 중지되어 있을 경우
- **취약**: Remote Registry Service가 사용중일 경우

### 2. 백신 프로그램 설치

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 바이러스로 인한 파일 감염을 예방할 수 있음

#### 보안 이슈
- 웜, 트로이목마 등의 악성 바이러스로 인한 피해규모 증가
- 피해를 최소화하기 위해 반드시 바이러스 백신 프로그램 설치 필요
- 바이러스 감염 여부 진단 및 치료, 파일 보호, 예방 기능 제공

#### 점검 방법
```
바이러스 백신 설치유무 확인
```

#### 대응 방안
```
바이러스 백신 프로그램을 반드시 설치

국내 백신 업체:
- 안철수연구소: http://www.ahnlab.com
- 하우리: http://www.hauri.co.kr

해외 백신 업체:
- 시만텍코리아: http://www.symantec.co.kr
- 한국트렌드마이크로: http://www.trendmicro.co.kr/
```

#### 기준
- **양호**: 바이러스 백신 프로그램이 설치되어 있는 경우
- **취약**: 바이러스 백신 프로그램이 설치되어 있지 않은 경우

### 3. 사용자가 프린터 드라이버를 설치할 수 없게 함

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 악의적인 사용자에 의한 악성코드 설치

#### 보안 이슈
- 모든 사용자가 프린터 드라이버를 설치할 수 있는지 결정하는 정책
- 악의적인 사용자가 고의적으로 잘못된 프린터 드라이버 설치하여 컴퓨터 손상
- 사용자가 프린터 드라이버로 위장한 악성 코드를 실수로 설치 가능

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "사용자가 프린터 드라이버를 설치할 수 없게 함" 정책을 "사용"으로 설정
```

#### 기준
- **양호**: "사용자가 프린터 드라이버를 설치할 수 없게 함" 정책이 "사용"으로 되어 있을 경우
- **취약**: "사용자가 프린터 드라이버를 설치할 수 없게 함" 정책이 "사용안함"으로 되어 있을 경우

### 4. 세션 연결을 중단하기 전에 필요한 유휴시간

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 서비스 거부공격이 가능

#### 보안 이슈
- SMB(서버 메시지 블록) 세션에서 보내야 하는 연속 유휴 시간 결정
- 각 SMB 세션은 서버 리소스를 사용하며, null 세션의 수가 많으면 서버 속도 저하
- 공격자는 SMB 세션을 반복 설정하여 서비스 거부 공격 실행 가능
- 클라이언트가 작업을 다시 시작하면 SMB 세션이 자동으로 다시 설정

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "로그온 시간이 만료되면 클라이언트 연결 끊기" "사용" 설정 
3. "세션 연결을 중단하기 전에 필요한 유휴 시간" 정책을 "15분" 설정
```

#### 설정 항목
- **Microsoft 네트워크 서버: 로그온 시간이 만료되면 클라이언트 연결 끊기** → 사용
- **Microsoft 네트워크 서버: 세션 연결을 중단하기 전에 필요한 유휴 시간** → 15분

#### 기준
- **양호**: "로그온 시간이 만료되면 클라이언트 연결 끊기" 정책을 "사용"으로 설정하고 "세션 연결을 중단하기 전에 필요한 유휴 시간" 정책이 "15분"으로 설정되어 있을 경우
- **취약**: "로그온 시간이 만료되면 클라이언트 연결 끊기" 정책이 "사용안함"으로 설정되어 있거나 "세션 연결을 중단하기 전에 필요한 유휴 시간" 정책이 "15분"으로 설정되어 있지 않을 경우

### 5. 경고 메시지 설정

#### 취약점 개요
- **위험도**: 낮음
- **위협 영향**: 시스템 침해 시도 감소

#### 보안 이슈
- 시스템에 로그온하려는 사용자들에게 불법적인 사용에 대한 경고 창 표시
- 로그온 이전에 사용자는 경고 메시지를 확인한 후 "확인" 버튼을 눌러야 패스워드 입력 창 표시
- 악의의 사용자로부터 시스템을 직접적으로 보호하지는 못함
- 관리자가 적절한 보안수준으로 시스템을 보호하고 있다는 인식 제공
- 공격자의 활동을 주시하고 있다는 생각을 들게 하여 간접적으로 공격 피해 감소

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션
2. "로그온 시도하는 사용자에 대한 메시지 제목", "로그온 시도하는 사용자에 대한 메시지 텍스트"에 적절한 값을 입력

예시:
- 로그온 시도하는 사용자에 대한 메시지 제목: Warning!!
- 로그온 시도하는 사용자에 대한 메시지 텍스트: This system is for the use of authorized users only.
```

#### 기준
- **양호**: 로그인 경고 메시지/제목이 설정되어 있을 경우
- **취약**: 로그인 경고 메시지/제목이 설정되어 있지 않을 경우

### 6. 사용자별 홈 디렉터리 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 홈디렉터리 파일 위/변조

#### 보안 이슈
- 사용자 계정별 홈 디렉터리의 권한이 제한되어 있지 않을 경우 문제 발생
- 임의의 사용자가 다른 사용자의 홈 디렉터리의 파일 및 디렉터리에 접근 가능
- 해당 사용자만의 접근 권한 설정 필요

#### 점검 방법
```
[Windows 2012]
C:\Documents and Settings\사용자 홈디렉터리 > 속성 > 보안에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. C:\Documents and Settings\사용자 홈디렉터리 > 속성 > 보안
2. Everyone 권한 제거 (All Users, Default User 디렉터리는 제외)
```

#### 기준
- **양호**: 홈디렉터리에 Everyone 권한이 없을 경우 (All Users, Default User 디렉터리는 제외)
- **취약**: 홈디렉터리에 Everyone 권한이 있을 경우

## 종합 보안 설정 스크립트

```powershell
# Windows 고급 보안 설정 점검 및 적용 스크립트
# PowerShell 관리자 권한으로 실행 필요

Write-Host "=== Windows 고급 보안 설정 점검 시작 ===" -ForegroundColor Green

# 1. 원격 레지스트리 서비스 상태 확인
Write-Host "`n1. 원격 레지스트리 서비스 상태 확인" -ForegroundColor Yellow
try {
    $remoteRegService = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
    Write-Host "  Remote Registry 서비스 상태: $($remoteRegService.Status)" -ForegroundColor Cyan
    Write-Host "  시작 유형: $($remoteRegService.StartType)" -ForegroundColor Cyan
    
    if ($remoteRegService.Status -eq "Running") {
        Write-Host "  ⚠️  원격 레지스트리 서비스가 실행 중입니다." -ForegroundColor Red
        Write-Host "  권장: 서비스를 중지하고 시작 유형을 '사용 안함'으로 설정하세요." -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ 원격 레지스트리 서비스가 중지되어 있습니다." -ForegroundColor Green
    }
} catch {
    Write-Host "  원격 레지스트리 서비스 정보를 확인할 수 없습니다." -ForegroundColor Red
}

# 2. 백신 프로그램 설치 확인 (Windows Defender 및 기타)
Write-Host "`n2. 백신 프로그램 설치 확인" -ForegroundColor Yellow
try {
    # Windows Defender 확인
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $defenderStatus = Get-MpComputerStatus
        Write-Host "  Windows Defender:" -ForegroundColor Cyan
        Write-Host "    실시간 보호: $($defenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Gray
        Write-Host "    안티바이러스: $($defenderStatus.AntivirusEnabled)" -ForegroundColor Gray
        Write-Host "    최근 업데이트: $($defenderStatus.AntivirusSignatureLastUpdated)" -ForegroundColor Gray
        
        if ($defenderStatus.RealTimeProtectionEnabled -eq $true) {
            Write-Host "  ✅ Windows Defender가 활성화되어 있습니다." -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Windows Defender가 비활성화되어 있습니다." -ForegroundColor Yellow
        }
    }
    
    # 기타 백신 프로그램 확인 (WMI를 통해)
    $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
    if ($antivirusProducts) {
        Write-Host "  설치된 백신 프로그램:" -ForegroundColor Cyan
        foreach ($av in $antivirusProducts) {
            $state = switch ($av.productState) {
                { $_ -band 0x1000 } { "활성화됨" }
                default { "비활성화됨" }
            }
            Write-Host "    - $($av.displayName): $state" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  백신 프로그램 정보를 확인할 수 없습니다." -ForegroundColor Red
}

# 3. 사용자 홈 디렉터리 권한 확인
Write-Host "`n3. 사용자 홈 디렉터리 권한 확인" -ForegroundColor Yellow
$userProfiles = @("C:\Users", "C:\Documents and Settings")
foreach ($profilePath in $userProfiles) {
    if (Test-Path $profilePath) {
        Write-Host "  프로필 경로: $profilePath" -ForegroundColor Cyan
        $userDirs = Get-ChildItem $profilePath -Directory -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Name -notin @("All Users", "Default User", "Default", "Public") }
        
        foreach ($userDir in $userDirs) {
            try {
                $acl = Get-Acl $userDir.FullName -ErrorAction SilentlyContinue
                $everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
                
                if ($everyoneAccess) {
                    Write-Host "    ⚠️  $($userDir.Name): Everyone 권한이 설정되어 있습니다." -ForegroundColor Red
                } else {
                    Write-Host "    ✅ $($userDir.Name): 적절한 권한으로 설정되어 있습니다." -ForegroundColor Green
                }
            } catch {
                Write-Host "    $($userDir.Name): 권한 정보를 확인할 수 없습니다." -ForegroundColor Gray
            }
        }
        break  # 첫 번째로 찾은 경로만 확인
    }
}

# 4. 중요 보안 정책 확인 (레지스트리를 통해 간접적으로)
Write-Host "`n4. 중요 보안 정책 확인" -ForegroundColor Yellow

# 마지막 사용자 이름 표시 안함 설정 확인
try {
    $dontDisplayLastUser = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    if ($dontDisplayLastUser -and $dontDisplayLastUser.DontDisplayLastUserName -eq 1) {
        Write-Host "  ✅ 마지막 사용자 이름 표시 안함: 설정됨" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  마지막 사용자 이름 표시 안함: 설정되지 않음" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  마지막 사용자 이름 표시 설정을 확인할 수 없습니다." -ForegroundColor Gray
}

# 로그온 경고 메시지 설정 확인
try {
    $legalCaption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
    $legalText = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue
    
    if ($legalCaption -and $legalCaption.LegalNoticeCaption -and $legalText -and $legalText.LegalNoticeText) {
        Write-Host "  ✅ 로그온 경고 메시지: 설정됨" -ForegroundColor Green
        Write-Host "    제목: $($legalCaption.LegalNoticeCaption)" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠️  로그온 경고 메시지: 설정되지 않음" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  로그온 경고 메시지 설정을 확인할 수 없습니다." -ForegroundColor Gray
}

Write-Host "`n=== Windows 고급 보안 설정 점검 완료 ===" -ForegroundColor Green
Write-Host "`n권장 작업:" -ForegroundColor Cyan
Write-Host "1. services.msc에서 불필요한 서비스를 중지하세요." -ForegroundColor White
Write-Host "2. secpol.msc에서 보안 정책을 세밀하게 조정하세요." -ForegroundColor White
Write-Host "3. 백신 프로그램이 최신 상태인지 확인하세요." -ForegroundColor White
Write-Host "4. 사용자 홈 디렉터리 권한을 정기적으로 점검하세요." -ForegroundColor White
```

## 보안 정책 자동 설정 스크립트

```batch
@echo off
echo Windows 보안 정책 자동 설정 스크립트
echo 주의: 관리자 권한으로 실행해야 합니다.
echo 실행 전 시스템 백업을 권장합니다.
pause

REM 원격 레지스트리 서비스 비활성화
echo 원격 레지스트리 서비스 비활성화...
sc config "RemoteRegistry" start= disabled
sc stop "RemoteRegistry"

REM 마지막 사용자 이름 표시 안함 설정
echo 마지막 사용자 이름 표시 안함 설정...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f

REM 로그온 경고 메시지 설정
echo 로그온 경고 메시지 설정...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeCaption /t REG_SZ /d "경고 - Authorized Users Only" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeText /t REG_SZ /d "이 시스템은 승인된 사용자만 사용할 수 있습니다. 무단 접근은 법적 처벌을 받을 수 있습니다." /f

REM 프린터 드라이버 설치 제한 설정
echo 프린터 드라이버 설치 제한 설정...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

REM SMB 세션 타임아웃 설정 (15분)
echo SMB 세션 타임아웃 설정...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v autodisconnect /t REG_DWORD /d 15 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

echo 설정이 완료되었습니다.
echo 일부 설정은 시스템 재시작 후 적용됩니다.
pause
```

## Windows 기본 사용자 및 그룹 정보

### 기본 사용자 계정
| 계정명 | 설명 | 권한 수준 |
|--------|------|-----------|
| Administrator | 관리자 권한의 계정 | 최고 권한 |
| SYSTEM | 시스템에서 최고 권한을 가진 계정 | 시스템 레벨 |
| GUEST | 매우 제한적인 권한을 가진 계정 | 제한됨 |

### 기본 그룹
| 그룹명 | 설명 |
|--------|------|
| Administrators | 도메인 자원이나 로컬 컴퓨터의 모든 권한 |
| Guests | 도메인 사용 권한이 제한된 그룹, 시스템 설정 변경 권한 없음 |
| Users | 도메인과 로컬 컴퓨터를 일반적으로 사용할 수 있는 권한 |

## Windows Server EOS 상황

| 운영체제 | 최신 서비스 팩 | 서비스 제공 여부 |
|----------|---------------|------------------|
| Windows NT | Service Pack 6a | 종료 |
| Windows Server 2000 | Service Pack 4 | 종료 |
| Windows Server 2003 | Service Pack 2 | 종료 |
| Windows Server 2008 | SP2 (R2: SP1) | 연장 지원 종료 |
| Windows Server 2012 | 없음 (R2: 없음) | 지원 중 |

## 참고 자료

### 보안 설정 관리 도구
- **SECPOL.MSC**: 로컬 보안 정책
- **GPEDIT.MSC**: 그룹 정책 편집기  
- **SERVICES.MSC**: 서비스 관리
- **REGEDIT**: 레지스트리 편집기

### 권장 보안 설정
1. **원격 레지스트리**: 비활성화
2. **로그온 메시지**: 설정
3. **SMB 타임아웃**: 15분
4. **프린터 드라이버**: 관리자만 설치
5. **백신 프로그램**: 필수 설치 및 업데이트