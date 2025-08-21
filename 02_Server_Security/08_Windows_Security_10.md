# 10강: 보안취약점(서버보안 Windows) 

## 개요
Windows 서버 보안의 다섯 번째 강의로, 최고 수준의 보안 관리 및 종합 보안 설정을 다룹니다. 시스템 종료 제한, 감사 설정, SAM 보안, LAN Manager 인증, 보안 채널, 이동식 미디어 관리 등을 학습합니다.

## 주요 내용

### 1. 원격 시스템에서 시스템 강제 종료 차단

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 임의의 사용자가 원격에서 시스템을 종료 가능

#### 보안 이슈
- 원격에서 네트워크를 사용하여 운영 체제를 종료할 수 있는 사용자 및 그룹 결정
- 해당 권한 부여가 부적절할 경우 서비스 거부 공격에 이용 가능
- 권한이 없는 사용자의 시스템 종료 방지 필요

#### 점검 방법
```
[Windows 2012]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 사용자 권한 할당
2. "원격 시스템에서 강제로 시스템 종료" 정책에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 사용자 권한 할당
2. "원격 시스템에서 강제로 시스템 종료" 정책에 "Administrators" 외 다른 계정 및 그룹 제거
```

#### 기준
- **양호**: "원격 시스템에서 강제로 시스템 종료" 정책에 "Administrators"만 존재할 경우
- **취약**: "원격 시스템에서 강제로 시스템 종료" 정책에 "Administrators" 외 다른 계정 및 그룹이 존재할 경우

### 2. 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 서비스 거부 공격에 이용될 수 있음

#### 보안 이슈
- 보안 이벤트를 기록할 수 없는 경우 컴퓨터를 종료할 것인지 여부 결정
- 이 정책을 사용할 경우 서비스 거부 공격으로 사용될 수 있음
- 비정상 종료로 인해 시스템 및 데이터에 손상을 입힐 수 있음

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책을 "사용안함"으로 설정
```

#### 기준
- **양호**: "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책이 "사용안함"으로 되어 있을 경우
- **취약**: "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책이 "사용"으로 되어 있을 경우

### 3. SAM 계정과 공유의 익명 열거 허용 안 함

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- SAM(보안 계정 관리자) 계정과 공유의 익명 열거가 허용될 경우 위험
- Windows에서는 익명 사용자가 도메인 계정과 네트워크 공유의 이름 열거 가능
- 악의적인 사용자가 계정 이름 목록을 익명으로 표시한 다음 이 정보를 사용하여 암호 추측
- 사회 공학적 기술 공격 수행 가능

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션
2. "SAM 계정과 공유의 익명 열거 허용 안 함", "SAM 계정의 익명 열거 허용 안 함"에 각각 "사용"을 선택

추가 보안 조치:
- 방화벽과 라우터에서 135~139(TCP, UDP) 포트의 차단을 통해 외부로부터의 위협 차단
- 네트워크 및 전화 접속 연결 > 로컬영역 > 등록정보 > 고급 > 고급설정 > Microsoft 네트워크 파일 및 프린트 공유를 해제
```

#### 기준
- **양호**: 해당 보안옵션 값이 설정되어 있을 경우
- **취약**: 해당 보안옵션 값이 설정되어 있지 않을 경우

**주의사항**: Active Directory, Clustered system에서는 적용 시 영향이 있을 수 있음

### 4. LAN Manager 인증 수준

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 암호 재생 공격에 취약함

#### 보안 이슈
- 네트워크 로그온에 사용할 Challenge/Response 인증 프로토콜 결정
- LAN Manager는 네트워크를 통한 파일 및 프린터 공유 등 작업 시 인증 담당
- 보다 안전한 인증을 위해 NTLMv2 사용 권장

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "LAN Manager 인증 수준" 정책에 "NTLMv2 응답만 보냄"을 설정
```

#### 기준
- **양호**: "LAN Manager 인증 수준" 정책에 "NTLMv2 응답만 보냄"이 설정되어 있을 경우
- **취약**: "LAN Manager 인증 수준" 정책에 "LM" 및 "NTLM" 인증이 설정되어 있을 경우

### 5. 보안 채널 데이터 디지털 암호화 또는 서명

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 암호 추측 공격이 쉬워짐

#### 보안 이슈
- 도메인 구성원이 시작하는 모든 보안 채널 트래픽을 서명하거나 암호화할지 여부 설정
- 인증 트래픽을 끼어들기 공격, 반복 공격 및 기타 유형의 네트워크 공격에서 보호
- Windows 기반 컴퓨터에서는 NetLogon을 통해 보안 채널이라는 통신 채널 생성
- 이 채널은 컴퓨터 계정을 인증하며 사용자 계정도 인증

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. 다음 3가지 정책을 모두 "사용"으로 설정:
   - 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상)
   - 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우)
   - 도메인 구성원: 보안 채널 데이터를 디지털 서명(가능한 경우)
```

#### 기준
- **양호**: 3가지 정책이 "사용"으로 되어 있을 경우
- **취약**: 3가지 정책이 "사용안함"으로 되어 있을 경우

**주의사항**: 도메인 구성원만 해당, Windows 98/NT와 파일 및 프린터 공유 등의 작업을 하지 않을 경우 일반적으로 영향 없음

### 6. 이동식 미디어 포맷 및 꺼내기 허용

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 중요 데이터 유출

#### 보안 이슈
- 이동식 NTFS 미디어 포맷 및 꺼내기가 허용되는 사용자 결정
- 사용자가 관리 권한을 가진 다른 컴퓨터로 이동식 디스크의 데이터 이동
- 파일에 대한 소유권을 얻고 자신에게 모든 권한을 부여하여 파일 보거나 수정 가능

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "이동식 미디어 포맷 및 꺼내기 허용" 정책을 "Administrator"로 설정
```

#### 기준
- **양호**: "이동식 미디어 포맷 및 꺼내기 허용" 정책이 "Administrator"으로 되어 있을 경우
- **취약**: "이동식 미디어 포맷 및 꺼내기 허용" 정책이 "Administrator"으로 되어 있지 않을 경우

### 7. 디스크볼륨 암호화 설정

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 데이터 유출

#### 보안 이슈
- 데이터 스토리지 분실 시 데이터 열람 가능
- 중요한 데이터가 포함된 디스크나 이동식 저장 장치 분실 시 데이터 보호 필요
- 암호화되지 않은 데이터는 누구나 쉽게 접근 가능

#### 점검 방법
```
[Windows 2012]
폴더선택 > 속성 > [일반]탭 > 고급 > 고급특성에서 "데이터 보호를 위해 내용을 암호화" 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
EFS(Encrypting File System) 활성화
1. 폴더선택 > 속성 > [일반]탭 > 고급 > 고급특성 > 데이터 보호를 위해 내용을 암호화 체크
```

#### 기준
- **양호**: "데이터 보호를 위해 내용을 암호화" 정책이 선택된 경우
- **취약**: "데이터 보호를 위해 내용을 암호화" 정책이 선택되어 있지 않은 경우

**주의사항**: 복호키 분실 시 데이터 복구가 어려움

### 8. 컴퓨터 계정 암호 최대 사용 기간

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 사용자 암호 해독 우려

#### 보안 이슈
- 도메인 구성원이 도메인 암호를 변경해야 하는 기간 결정
- 기본적으로 도메인 구성원의 도메인 암호는 자동으로 변경하도록 설정
- 정기적인 암호 변경으로 보안 강화

#### 점검 방법
```
[Windows 2012]
1. 관리도구 > 로컬 보안 정책 > 보안 옵션 > 도메인 구성원: 컴퓨터 계정 암호 최대 사용 기간에서 일수 확인
2. 관리도구 > 컴퓨터 관리 > 시스템 도구 > 로컬 사용자 및 그룹 > 사용자에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "컴퓨터 계정 암호 변경 사용 안 함" 정책 "사용안함" 설정 
3. "컴퓨터 계정 암호 최대 사용 기간" 정책을 "90일"로 설정
```

#### 기준
- **양호**: "컴퓨터 계정 암호 변경 사용 안 함" 정책 "사용안함" 설정 및 "컴퓨터 계정 암호 최대 사용 기간" 정책이 "90일"로 설정되어 있을 경우
- **취약**: "컴퓨터 계정 암호 변경 사용 안 함" 정책이 "사용"으로 설정되어 있거나 "컴퓨터 계정 암호 최대 사용 기간" 정책이 "90일"로 설정되어 있지 않을 경우

**주의사항**: 도메인 구성원만 해당

## Windows 보안설정 관리 핵심 정리

### Windows 보안설정 관리 도구
- **계정정책**: 암호의 복잡도, 이전 암호 기억, 계정의 잠김 등을 설정
- **로컬정책**: 로컬 시스템의 운영 정책, 감사 정책, 사용자 권한 할당 등을 설정

### Windows 운영체제 기본 보안
- **백신 프로그램 설치**: 필수
- **화면 보호기 설정**: 보안 강화
- **사용자 로그온 관리**: 접근 제어

### Windows 어플리케이션 설정
- **미사용 서비스 중지**: 디폴트 서비스 중지
- **인터넷 서비스 IIS 서비스 보안설정**: 디렉토리 리스팅, 상위디렉토리 접근 금지
- **FTP 서비스**: 평문 전송 시 보안 취약, anonymous FTP 사용 차단
- **DNS 서비스**: 도메인을 IP로 변환, DNS Zone Transfer의 허용 IP를 설정하여 비인가된 정보 전송 차단

### Windows 감사추적 관리
- **로그는 정기적 검토**: 분석하고 리포트하여 보고
- **이벤트 뷰어**: 응용프로그램, 보안, 설정, 시스템 등의 로그를 저장

### Windows 패치 관리
- **시스템 최신 상태 유지**: 보안 업데이트를 통하여 최신 버전으로 유지
- **EoS된 OS 사용 중지**: 지원이 종료된 운영체제 사용 금지
- **알려진 취약점 제거**: HotFix를 적용하며, 적용 전 충분한 테스트 진행

## 최종 보안 점검 스크립트

```powershell
# Windows 서버 최종 보안 점검 및 강화 스크립트
# PowerShell 관리자 권한으로 실행 필요

param(
    [switch]$ApplyFixes = $false,
    [string]$LogPath = "C:\Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

function Write-Log {
    param($Message, $Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry
}

Write-Log "=== Windows 서버 최종 보안 점검 시작 ===" "INFO"
Write-Log "로그 파일: $LogPath" "INFO"

$securityIssues = @()

# 1. 원격 시스템 강제 종료 권한 확인
Write-Log "`n1. 원격 시스템 강제 종료 권한 확인" "INFO"
try {
    $shutdownRight = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ShutdownWithoutLogon" -ErrorAction SilentlyContinue)
    Write-Log "원격 종료 설정 확인 완료" "INFO"
} catch {
    Write-Log "원격 종료 설정을 확인할 수 없습니다." "WARNING"
}

# 2. SAM 계정 익명 열거 확인
Write-Log "`n2. SAM 계정 익명 열거 설정 확인" "INFO"
try {
    $restrictAnonymousSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymousSAM -and $restrictAnonymousSAM.RestrictAnonymousSAM -eq 1) {
        Write-Log "✅ SAM 계정 익명 열거가 제한되어 있습니다." "INFO"
    } else {
        Write-Log "⚠️  SAM 계정 익명 열거가 허용되어 있습니다." "WARNING"
        $securityIssues += "SAM 계정 익명 열거 허용"
        
        if ($ApplyFixes) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
            Write-Log "자동 수정: SAM 계정 익명 열거를 제한했습니다." "INFO"
        }
    }
} catch {
    Write-Log "SAM 계정 설정을 확인할 수 없습니다." "ERROR"
}

# 3. LAN Manager 인증 수준 확인
Write-Log "`n3. LAN Manager 인증 수준 확인" "INFO"
try {
    $lmCompatLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
    if ($lmCompatLevel -and $lmCompatLevel.LmCompatibilityLevel -ge 3) {
        Write-Log "✅ LAN Manager 인증 수준이 안전하게 설정되어 있습니다. (레벨: $($lmCompatLevel.LmCompatibilityLevel))" "INFO"
    } else {
        Write-Log "⚠️  LAN Manager 인증 수준이 안전하지 않습니다." "WARNING"
        $securityIssues += "약한 LAN Manager 인증"
        
        if ($ApplyFixes) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
            Write-Log "자동 수정: LAN Manager 인증 수준을 5로 설정했습니다." "INFO"
        }
    }
} catch {
    Write-Log "LAN Manager 인증 설정을 확인할 수 없습니다." "ERROR"
}

# 4. 보안 채널 설정 확인
Write-Log "`n4. 보안 채널 디지털 서명/암호화 확인" "INFO"
$channelSettings = @(
    @{Name="RequireSignOrSeal"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Expected=1},
    @{Name="SealSecureChannel"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Expected=1},
    @{Name="SignSecureChannel"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Expected=1}
)

foreach ($setting in $channelSettings) {
    try {
        $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
        if ($value -and $value.($setting.Name) -eq $setting.Expected) {
            Write-Log "✅ $($setting.Name) 설정이 안전합니다." "INFO"
        } else {
            Write-Log "⚠️  $($setting.Name) 설정이 안전하지 않습니다." "WARNING"
            $securityIssues += "보안 채널 설정 미흡: $($setting.Name)"
            
            if ($ApplyFixes) {
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Expected
                Write-Log "자동 수정: $($setting.Name)을 $($setting.Expected)로 설정했습니다." "INFO"
            }
        }
    } catch {
        Write-Log "$($setting.Name) 설정을 확인할 수 없습니다." "ERROR"
    }
}

# 5. 이동식 미디어 설정 확인
Write-Log "`n5. 이동식 미디어 접근 제한 확인" "INFO"
try {
    $allocateDASD = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -ErrorAction SilentlyContinue
    if ($allocateDASD -and $allocateDASD.AllocateDASD -eq "0") {
        Write-Log "✅ 이동식 미디어가 관리자만 접근 가능하도록 설정되어 있습니다." "INFO"
    } else {
        Write-Log "⚠️  이동식 미디어 접근이 제한되지 않았습니다." "WARNING"
        $securityIssues += "이동식 미디어 접근 제한 없음"
        
        if ($ApplyFixes) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -Value "0"
            Write-Log "자동 수정: 이동식 미디어를 관리자만 접근 가능하도록 설정했습니다." "INFO"
        }
    }
} catch {
    Write-Log "이동식 미디어 설정을 확인할 수 없습니다." "ERROR"
}

# 6. EFS(암호화 파일 시스템) 확인
Write-Log "`n6. EFS(암호화 파일 시스템) 지원 확인" "INFO"
try {
    $efsDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableEncryption" -ErrorAction SilentlyContinue
    if ($efsDisabled -and $efsDisabled.NtfsDisableEncryption -eq 1) {
        Write-Log "⚠️  EFS(암호화 파일 시스템)가 비활성화되어 있습니다." "WARNING"
        $securityIssues += "EFS 비활성화"
    } else {
        Write-Log "✅ EFS(암호화 파일 시스템)가 활성화되어 있습니다." "INFO"
    }
} catch {
    Write-Log "EFS 설정을 확인할 수 없습니다." "ERROR"
}

# 7. 컴퓨터 계정 암호 정책 확인 (도메인 환경)
Write-Log "`n7. 컴퓨터 계정 암호 정책 확인" "INFO"
try {
    $disablePwdChange = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -ErrorAction SilentlyContinue
    $maxPwdAge = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
    
    if ($disablePwdChange -and $disablePwdChange.DisablePasswordChange -eq 0) {
        Write-Log "✅ 컴퓨터 계정 암호 변경이 활성화되어 있습니다." "INFO"
    } else {
        Write-Log "⚠️  컴퓨터 계정 암호 변경이 비활성화되어 있습니다." "WARNING"
        $securityIssues += "컴퓨터 계정 암호 변경 비활성화"
    }
    
    if ($maxPwdAge -and $maxPwdAge.MaximumPasswordAge -le 90) {
        Write-Log "✅ 컴퓨터 계정 암호 최대 사용 기간이 적절합니다. ($($maxPwdAge.MaximumPasswordAge)일)" "INFO"
    } else {
        Write-Log "⚠️  컴퓨터 계정 암호 최대 사용 기간이 너무 깁니다." "WARNING"
        $securityIssues += "컴퓨터 계정 암호 사용 기간 과다"
    }
} catch {
    Write-Log "컴퓨터 계정 암호 정책을 확인할 수 없습니다 (도메인 환경이 아닐 수 있음)." "INFO"
}

# 최종 보고서
Write-Log "`n=== 보안 점검 결과 요약 ===" "INFO"
Write-Log "총 발견된 보안 이슈 수: $($securityIssues.Count)" "INFO"

if ($securityIssues.Count -eq 0) {
    Write-Log "🎉 모든 보안 검사를 통과했습니다!" "INFO"
} else {
    Write-Log "발견된 보안 이슈:" "WARNING"
    foreach ($issue in $securityIssues) {
        Write-Log "  - $issue" "WARNING"
    }
    
    if (-not $ApplyFixes) {
        Write-Log "`n자동 수정을 원하시면 '-ApplyFixes' 매개변수를 사용하여 다시 실행하세요." "INFO"
        Write-Log "예: .\SecurityAudit.ps1 -ApplyFixes" "INFO"
    }
}

Write-Log "`n권장 추가 조치:" "INFO"
Write-Log "1. secpol.msc에서 모든 보안 정책을 재검토하세요." "INFO"
Write-Log "2. gpedit.msc에서 그룹 정책을 검토하세요." "INFO"
Write-Log "3. services.msc에서 불필요한 서비스를 중지하세요." "INFO"
Write-Log "4. 정기적인 보안 패치 적용 일정을 수립하세요." "INFO"
Write-Log "5. 백업 및 재해복구 계획을 수립하세요." "INFO"

Write-Log "`n=== Windows 서버 최종 보안 점검 완료 ===" "INFO"
Write-Log "상세한 로그는 다음에서 확인할 수 있습니다: $LogPath" "INFO"

# 결과 반환
if ($securityIssues.Count -eq 0) {
    exit 0  # 보안 이슈 없음
} else {
    exit 1  # 보안 이슈 발견됨
}
```

## 보안 강화 배치 스크립트

```batch
@echo off
echo Windows 서버 최종 보안 강화 스크립트
echo ==========================================
echo 주의: 관리자 권한으로 실행해야 합니다.
echo 실행 전 시스템 백업을 권장합니다.
echo.
pause

echo 1. SAM 계정 익명 열거 제한...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

echo 2. LAN Manager 인증 수준 강화...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

echo 3. 보안 채널 디지털 서명/암호화 활성화...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

echo 4. 이동식 미디어 접근 제한...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD /t REG_SZ /d "0" /f

echo 5. 시스템 강제 종료 권한 제한...
REM 이 설정은 secpol.msc에서 수동으로 설정해야 합니다.

echo 6. 보안 감사 시스템 종료 비활성화...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v CrashOnAuditFail /t REG_DWORD /d 0 /f

echo 7. 컴퓨터 계정 암호 정책 설정...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 90 /f

echo.
echo 보안 강화 설정이 완료되었습니다.
echo 시스템 재시작 후 모든 설정이 적용됩니다.
echo.
echo 추가로 다음 작업을 수행하세요:
echo - secpol.msc에서 "원격 시스템에서 강제로 시스템 종료" 권한 확인
echo - secpol.msc에서 감사 정책 설정
echo - 불필요한 서비스 중지
echo.
pause
```

## 참고 자료 및 체크리스트

### Windows 보안 설정 최종 체크리스트

#### 계정 관리 ✅
- [ ] Administrator 계정 이름 변경
- [ ] Guest 계정 비활성화
- [ ] 불필요한 계정 제거
- [ ] 관리자 그룹에 최소한의 사용자 포함
- [ ] 패스워드 복잡성 설정
- [ ] 최근 암호 12개 기억
- [ ] 빈 암호 사용 제한

#### 서비스 관리 ✅
- [ ] 불필요한 서비스 제거
- [ ] NetBIOS 바인딩 제거
- [ ] 하드디스크 기본 공유 제거
- [ ] Everyone 권한 제거
- [ ] 원격터미널 타임아웃 설정

#### 보안 관리 ✅
- [ ] 원격 레지스트리 서비스 중지
- [ ] 백신 프로그램 설치 및 업데이트
- [ ] 프린터 드라이버 설치 제한
- [ ] SAM 계정 익명 열거 차단
- [ ] LAN Manager 인증 수준 강화
- [ ] 보안 채널 암호화 설정
- [ ] 이동식 미디어 접근 제한
- [ ] EFS 암호화 활용
- [ ] 경고 메시지 설정

#### 로그 및 감사 ✅
- [ ] 시스템 로깅 설정
- [ ] 이벤트 로그 크기 10MB 이상
- [ ] 로그 파일 접근 권한 제한
- [ ] 정기적 로그 검토 체계
- [ ] 보안 감사 시스템 종료 비활성화

#### 패치 관리 ✅
- [ ] 최신 서비스팩 적용
- [ ] 최신 핫픽스 적용
- [ ] Windows Update 활성화
- [ ] EoS 운영체제 사용 금지

이상으로 Windows 서버 보안 취약점 분석 및 평가의 모든 내용을 완료했습니다. 각 항목을 체계적으로 점검하고 적용하여 안전한 서버 환경을 구축하시기 바랍니다.
