# 8강: 보안취약점(서버보안 Windows) 03

## 개요
Windows 서버 보안의 세 번째 강의로, 시스템 관리와 패치 관리, 로그 관리를 중심으로 다룹니다. 예약된 작업, 서비스팩, 백신, 로깅 설정 등을 학습합니다.

## 주요 내용

### 1. 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 트로이목마/백도어 공격에 취약, 해커들이 공격하기 용이함

#### 보안 이슈
- 일정 시간마다 미리 설정한 프로그램을 실행할 수 있는 예약 작업
- 해킹과 트로이목마, 백도어가 설치하여 공격하기 좋은 경로
- 시작 프로그램과 더불어 지속적인 모니터링 필요

#### 점검 방법

##### GUI 방법
```
[Windows 2012]
시작 > 실행 > Taskschd.msc > 작업 스케줄러 확인
```

##### CLI 방법
```cmd
C:\> schtasks.exe
```

#### 대응 방안

##### GUI 설정 방법
```
[Windows 2012]
1. 시작 > 실행 > Taskschd.msc > 작업 스케줄러 확인
2. 등록된 실행 중인 작업을 클릭하여 상세 내역 확인
3. 불필요한 파일이 있다면 삭제
```

##### CLI 설정 방법
```
[Windows 2012]
1. 시작 > 실행 > cmd 입력 후 엔터
2. cmd창에서 schtasks.exe 실행
3. C:\> schtasks.exe 명령어 실행하여 확인
```

#### 기준
- **양호**: 예약된 작업에 접속하여 불필요한 명령어나 파일이 있는지 확인했을 경우
- **취약**: 예약된 작업에 접속을 하지 않아 확인을 하지 않거나 방치했을 경우

### 2. 최신 서비스팩 적용

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- 서비스 팩은 Windows 출시 후 수정 파일들을 모아놓은 프로그램
- 보안 취약점 개선 내용 포함
- 최신 서비스팩 미적용 시 알려진 취약점에 노출

#### 점검 방법
```
[Windows 2012]
1. 시작 > 실행 > Winver에서 Service Pack 버전 확인
2. 최신 Hotfix 설치유무 확인
```

#### 대응 방안

##### 서비스팩 설치
```
[Windows 2012]
1. 시작 > 실행 > Winver
2. Service Pack 버전 확인 후 최신 버전이 아닐 경우 아래 사이트에서 다운로드하여 설치
   https://www.microsoft.com/ko-kr/download/servicepack.aspx
```

**주의사항**: 서비스팩 설치 시 네트워크와 분리된 상태에서 설치 권장
- 현재 많은 인터넷 웜(Worm)이 Windows 취약점을 이용하여 공격
- OS 설치 후 곧바로 네트워크 연결은 서버 피해 위험

##### 최신 Hotfix 설치 방법

**1. 수동 패치 설치**
```
아래의 패치 리스트를 조회하여 서버에 필요한 패치를 선별하여 수동 설치
https://technet.microsoft.com/ko-kr/security/bulletins
```

**2. Windows 자동 업데이트 기능**
```
Internet Explorer 도구 메뉴 > "Windows Update" 선택
또는 직접 URL 접속: http://windowsupdate.microsoft.com/?IE
```

**3. PMS (Patch Management System) Agent**
```
자동으로 업데이트되도록 PMS Agent 설치 및 설정
```

#### 기준
- **양호**: 최신 서비스팩이 설치되어 있을 경우, 최신 Hotfix 또는 PMS Agent가 설치되어 있을 경우
- **취약**: 최신 서비스팩이 설치되어 있지 않은 경우, 최신 Hotfix 또는 PMS Agent가 설치되어 있지 않은 경우

### 3. 최신 HOT FIX 적용

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: Brute force에 의한 지속적인 계정 공격의 위험

#### 보안 이슈
- Hot Fix는 즉시 교정되어야 하는 주요한 취약점 패치 프로그램
- 주로 보안과 관련된 취약점을 다룸
- 각각의 Service Pack 이후 필요시 별도로 발표
- Hot Fix보다 공격도구가 먼저 출현할 수 있어 신속한 적용 필요

#### 점검 방법
```
[Windows 2012]
최신 패치가 설치되었는지 사이트에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
최신 Hotfix 설치
아래의 패치 리스트 조회하여 서버에 필요한 패치 선별하여 수동 설치
http://www.microsoft.com/korea/technet/security/current.asp
```

**주의사항**:
- 보안 패치 및 Hot Fix 적용 후 시스템 재시작 필요
- 서비스에 지장이 없는 시간대에 적용 권장
- Application 프로그램에 영향을 줄 수 있음
- 패치 적용 전 Application 프로그램 확인 및 OS 벤더나 엔지니어 확인 필요

#### 기준
- **양호**: 최신 Hotfix 또는 PMS (Patch Management System) Agent가 설치되어 있을 경우
- **취약**: 최신 Hotfix 또는 PMS (Patch Management System) Agent가 설치되어 있지 않은 경우

### 4. 백신 프로그램 업데이트

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 새로운 바이러스에 파일 감염이 가능함

#### 보안 이슈
- 계속되는 신종 바이러스 출현으로 백신 프로그램 설치만으로는 효과 부족
- 바이러스 정보에 대한 주기적 업데이트 필요
- 최신 바이러스까지 치료할 수 있는 기능 필요

#### 점검 방법
```
바이러스 백신 프로그램 최신 엔진 업데이트 설치 유무 확인
```

#### 대응 방안
```
담당자를 통해 바이러스 백신 설치 후 엔진 업데이트를 설정하도록 권고

업데이트 특징:
- 백신사들마다 다소 차이는 있으나 매주 업데이트 진행
- 긴급한 경우 수시로 업데이트
- 정기적인 업데이트를 통해 검색엔진을 최신 버전으로 유지
- 백신사에서 발표하는 경보를 주시
- 자동 업데이트 기능을 이용하면 인터넷 연결 시 자동 업데이트
```

#### 기준
- **양호**: 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있을 경우
- **취약**: 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않은 경우

### 5. 정책에 따른 시스템 로깅 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 각종 침해 사실에 대한 확인과 대응책 및 법적 대응이 어려움

#### 보안 이슈
- 감사 설정이 구성되지 않거나 수준이 낮으면 보안 문제 원인 파악 어려움
- 법적 대응을 위한 충분한 증거로 사용 불가
- 감사 설정이 너무 높으면 불필요한 항목이 많이 기록되어 중요 항목과 혼동
- 컴퓨터 성능에 영향 가능

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬정책 > 감사정책에서 확인
```

#### 권장 감사 설정
- **로그온 이벤트**: 성공/실패 감사
- **계정 로그온 이벤트**: 성공/실패 감사
- **정책 변경**: 성공/실패 감사
- **계정 관리**: 실패 감사
- **디렉터리 서비스 액세스**: 실패 감사
- **권한 사용**: 실패 감사

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬정책 > 감사정책
2. 위에서 언급한 이벤트들에 대한 추가적인 감사 설정
```

#### 기준
- **양호**: 권장 이벤트에 대한 감사 설정이 되어 있는 경우
- **취약**: 권장 이벤트에 대한 감사 설정이 되어 있지 않은 경우

### 6. 이벤트 로그 관리 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 보안 로그의 크기를 유지하여 접근자 추적 및 불법 접근자 확인 자료로 이용

#### 보안 이슈
- 최대 로그 크기를 10MB 이상으로 설정 필요
- 이벤트 로그 관리를 '이벤트 겹쳐 쓰지 않음'으로 설정
- 시스템에 보안상 로그가 자동으로 덮어쓰지 않도록 설정

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > EVENTVWR.MSC에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > EVENTVWR.MSC > 해당 로그 > 속성 > 일반
2. "최대 로그 크기" -> 10240KB 이상 설정
3. "90일 이후 이벤트 덮어씀" 설정
```

#### 기준
- **양호**: 최대 로그 크기 10240KB 이상이고 "90일 이후 이벤트 덮어씀"으로 설정되어 있을 경우
- **취약**: 최대 로그 크기 10240KB 미만이거나 "이벤트 덮어쓰는 기간이 90일 이하일 경우"

### 7. 원격에서 이벤트 로그 파일 접근 차단

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 시스템 정보 변조/삭제/유출

#### 보안 이슈
- 익명으로 중요 '시스템로그' 파일 및 '어플리케이션 로그' 파일에 접근 가능
- 중요 보안 감사 정보의 변조/삭제/유출 위험 존재
- 원격 익명사용자의 시스템 로그 접근 방지 필요

#### 로그 저장 위치
- **시스템 로그 파일**: `C:\Windows\system32\config`
- **IIS 로그 파일**: `C:\Windows\system32\LogFiles`
- **어플리케이션 로그**: 각각의 어플리케이션마다 다름

#### 점검 방법
```
[Windows 2012]
탐색기 > 로그 디렉터리 > 속성 > 보안에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 탐색기 > 로그 디렉터리 > 속성 > 보안
2. Everyone을 제거

확인할 디렉터리:
- 시스템 로그 디렉터리: %systemroot%\system32\config
- IIS 로그 디렉터리: %systemroot%\system32\LogFiles
```

#### 기준
- **양호**: 로그 디렉터리의 권한에 Everyone이 없는 경우
- **취약**: 로그 디렉터리의 접근권한이 Everyone이 있는 경우

### 8. 로그의 정기적 검토 및 보고

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 로그 자료가 없을 시 공격자에 대한 방어대응 취약, 자산의 재산 손실 우려

#### 보안 이슈
- 컴퓨터 관련 작업은 로그 정보로 저장됨
- 로그는 컴퓨터 관련 범죄 발생 시 해킹 흔적을 찾기 위한 분석 자료
- 로그분석을 통해 공격기법 발견하여 시스템 취약점 제거 가능
- 공격 근원을 찾을 수 있다면 법적 책임을 물을 수 있음

#### 점검 방법
```
[Windows 2012]
1. 이벤트 뷰어 -> 시작 > 실행 > EVENTVWR.MSC
2. 로컬보안정책 -> 시작 > 설정 > 제어판 > 관리도구 > 로컬보안정책
```

#### Windows 로그 종류
- **응용 프로그램 로그**: 응용 프로그램 관련 이벤트
- **보안 로그**: 보안 감사 이벤트
- **시스템 로그**: 시스템 구성요소 이벤트
- **디렉터리 서비스 로그**: Domain Controller에서 추가
- **파일 복제 서비스 로그**: Domain Controller에서 추가
- **DNS 서버 로그**: DNS 서버에서 추가

#### 대응 방안

##### 이벤트 뷰어 사용
```
[Windows 2012]
1. 시작 > 제어판 > 관리도구 > 이벤트 뷰어
2. 응용 프로그램 로그, 보안 로그, 시스템 로그 확인
3. OS 구성에 따라 디렉토리 서비스 로그, 파일 복제 서비스 로그, DNS 서버 로그 추가
```

##### 감사 정책 구성
```
로컬보안정책을 이용하여 감사 정책 구성
- Administrators 그룹 구성원 또는 적절한 권한이 위임된 사용자여야 함
1. 시작 > 설정 > 제어판 > 관리도구 > 로컬보안정책
2. 보안 템플릿을 이용한 감사 정책 구성
```

#### 기준
- **양호**: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고 등의 조치가 되어 있을 경우
- **취약**: 로그기록에 대해 미 검사, 미 검토되었을 경우

## 종합 점검 및 관리 스크립트

```powershell
# Windows 서버 시스템 관리 및 패치 상태 점검 스크립트
# PowerShell 관리자 권한으로 실행 필요

Write-Host "=== Windows 서버 시스템 관리 점검 시작 ===" -ForegroundColor Green

# 1. Windows 버전 및 패치 레벨 확인
Write-Host "`n1. Windows 버전 및 패치 정보 확인" -ForegroundColor Yellow
try {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $buildNumber = [System.Environment]::OSVersion.Version.Build
    
    Write-Host "  OS: $($osInfo.Caption)" -ForegroundColor Cyan
    Write-Host "  버전: $($osInfo.Version)" -ForegroundColor Cyan
    Write-Host "  빌드 번호: $buildNumber" -ForegroundColor Cyan
    Write-Host "  마지막 부팅: $($osInfo.ConvertToDateTime($osInfo.LastBootUpTime))" -ForegroundColor Cyan
    
    # 설치된 핫픽스 확인 (최근 10개)
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
    Write-Host "`n  최근 설치된 핫픽스 (상위 10개):" -ForegroundColor Cyan
    foreach ($hf in $hotfixes) {
        Write-Host "    $($hf.HotFixID): $($hf.Description) - $($hf.InstalledOn)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  오류: OS 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 2. 예약된 작업 확인
Write-Host "`n2. 예약된 작업 확인" -ForegroundColor Yellow
try {
    $scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notlike "\Microsoft\*" }
    
    if ($scheduledTasks) {
        Write-Host "  사용자 정의 예약 작업:" -ForegroundColor Cyan
        foreach ($task in $scheduledTasks) {
            Write-Host "    - $($task.TaskName) ($($task.TaskPath))" -ForegroundColor Gray
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            if ($taskInfo) {
                Write-Host "      마지막 실행: $($taskInfo.LastRunTime)" -ForegroundColor Gray
                Write-Host "      다음 실행: $($taskInfo.NextRunTime)" -ForegroundColor Gray
            }
        }
        Write-Host "  주의: 의심스러운 작업이 있는지 확인하세요." -ForegroundColor Yellow
    } else {
        Write-Host "  사용자 정의 예약 작업이 없습니다." -ForegroundColor Green
    }
} catch {
    Write-Host "  오류: 예약된 작업 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 3. 백신 상태 확인 (Windows Defender)
Write-Host "`n3. Windows Defender 상태 확인" -ForegroundColor Yellow
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $defenderStatus = Get-MpComputerStatus
        Write-Host "  실시간 보호: $($defenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Cyan
        Write-Host "  안티바이러스 활성화: $($defenderStatus.AntivirusEnabled)" -ForegroundColor Cyan
        Write-Host "  안티스파이웨어 활성화: $($defenderStatus.AntispywareEnabled)" -ForegroundColor Cyan
        Write-Host "  마지막 빠른 검사: $($defenderStatus.QuickScanStartTime)" -ForegroundColor Cyan
        Write-Host "  마지막 전체 검사: $($defenderStatus.FullScanStartTime)" -ForegroundColor Cyan
        
        # 정의 파일 버전
        $signatureVersion = Get-MpComputerStatus | Select-Object AntivirusSignatureVersion
        Write-Host "  시그니처 버전: $($signatureVersion.AntivirusSignatureVersion)" -ForegroundColor Cyan
    } else {
        Write-Host "  Windows Defender가 설치되어 있지 않거나 PowerShell 모듈을 사용할 수 없습니다." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Windows Defender 정보를 확인할 수 없습니다." -ForegroundColor Gray
}

# 4. 이벤트 로그 설정 확인
Write-Host "`n4. 이벤트 로그 설정 확인" -ForegroundColor Yellow
$logNames = @("Application", "Security", "System")
foreach ($logName in $logNames) {
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $maxSizeKB = [math]::Round($log.MaximumSizeInBytes / 1KB, 0)
        
        Write-Host "  $logName 로그:" -ForegroundColor Cyan
        Write-Host "    최대 크기: $maxSizeKB KB" -ForegroundColor Gray
        Write-Host "    현재 크기: $([math]::Round($log.FileSize / 1KB, 0)) KB" -ForegroundColor Gray
        Write-Host "    레코드 수: $($log.RecordCount)" -ForegroundColor Gray
        
        if ($maxSizeKB -lt 10240) {
            Write-Host "    ⚠️  권장 최소 크기(10240KB)보다 작습니다." -ForegroundColor Yellow
        } else {
            Write-Host "    ✅ 적절한 크기로 설정되어 있습니다." -ForegroundColor Green
        }
    } catch {
        Write-Host "  $logName 로그 정보를 확인할 수 없습니다." -ForegroundColor Red
    }
}

# 5. Windows Update 설정 확인
Write-Host "`n5. Windows Update 설정 확인" -ForegroundColor Yellow
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    
    # 보류 중인 업데이트 검색 (시간이 오래 걸릴 수 있음)
    Write-Host "  Windows Update 서비스 상태 확인 중..." -ForegroundColor Gray
    $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuauserv) {
        Write-Host "  Windows Update 서비스: $($wuauserv.Status)" -ForegroundColor Cyan
        if ($wuauserv.Status -eq "Running") {
            Write-Host "  ✅ Windows Update 서비스가 실행 중입니다." -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Windows Update 서비스가 중지되어 있습니다." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  Windows Update 정보를 확인할 수 없습니다." -ForegroundColor Gray
}

Write-Host "`n=== Windows 서버 시스템 관리 점검 완료 ===" -ForegroundColor Green
Write-Host "`n권장 사항:" -ForegroundColor Cyan
Write-Host "1. taskschd.msc에서 예약된 작업을 정기적으로 점검하세요." -ForegroundColor White
Write-Host "2. Windows Update를 통해 최신 보안 패치를 적용하세요." -ForegroundColor White
Write-Host "3. eventvwr.msc에서 이벤트 로그를 정기적으로 검토하세요." -ForegroundColor White
Write-Host "4. 백신 프로그램의 정의 파일을 최신으로 유지하세요." -ForegroundColor White
Write-Host "5. secpol.msc에서 감사 정책을 적절히 설정하세요." -ForegroundColor White
```

## 로그 분석 스크립트

```powershell
# Windows 보안 이벤트 로그 분석 스크립트

param(
    [int]$Days = 7,  # 분석할 기간 (일)
    [string]$OutputPath = "C:\Logs\SecurityAnalysis.txt"
)

Write-Host "=== Windows 보안 로그 분석 ($Days일간) ===" -ForegroundColor Green

$startTime = (Get-Date).AddDays(-$Days)
$analysisResults = @()

# 1. 로그인 실패 이벤트 분석 (Event ID 4625)
Write-Host "`n1. 로그인 실패 이벤트 분석" -ForegroundColor Yellow
try {
    $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$startTime} -ErrorAction SilentlyContinue
    if ($failedLogins) {
        Write-Host "  로그인 실패 건수: $($failedLogins.Count)" -ForegroundColor Red
        
        # IP별 실패 횟수 집계
        $failuresByIP = $failedLogins | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            $account = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            [PSCustomObject]@{IP=$ip; Account=$account; Time=$_.TimeCreated}
        } | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10
        
        Write-Host "  상위 공격 IP:" -ForegroundColor Cyan
        foreach ($item in $failuresByIP) {
            Write-Host "    $($item.Name): $($item.Count)회" -ForegroundColor Gray
        }
        
        $analysisResults += "로그인 실패: $($failedLogins.Count)건"
    } else {
        Write-Host "  로그인 실패 이벤트가 없습니다." -ForegroundColor Green
    }
} catch {
    Write-Host "  로그인 실패 이벤트를 분석할 수 없습니다." -ForegroundColor Red
}

# 2. 성공적인 로그인 이벤트 분석 (Event ID 4624)
Write-Host "`n2. 성공적인 로그인 이벤트 분석" -ForegroundColor Yellow
try {
    $successLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startTime} -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Message -notlike "*SYSTEM*" -and $_.Message -notlike "*ANONYMOUS*" }
    
    if ($successLogins) {
        Write-Host "  성공적인 로그인: $($successLogins.Count)건" -ForegroundColor Green
        $analysisResults += "성공적인 로그인: $($successLogins.Count)건"
    }
} catch {
    Write-Host "  성공적인 로그인 이벤트를 분석할 수 없습니다." -ForegroundColor Red
}

# 3. 계정 잠금 이벤트 분석 (Event ID 4740)
Write-Host "`n3. 계정 잠금 이벤트 분석" -ForegroundColor Yellow
try {
    $lockouts = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740; StartTime=$startTime} -ErrorAction SilentlyContinue
    if ($lockouts) {
        Write-Host "  계정 잠금: $($lockouts.Count)건" -ForegroundColor Red
        $analysisResults += "계정 잠금: $($lockouts.Count)건"
    } else {
        Write-Host "  계정 잠금 이벤트가 없습니다." -ForegroundColor Green
    }
} catch {
    Write-Host "  계정 잠금 이벤트를 분석할 수 없습니다." -ForegroundColor Red
}

# 결과 저장
if ($analysisResults) {
    $header = "Windows 보안 로그 분석 결과 - $(Get-Date)"
    $separator = "=" * 50
    $content = @($header, $separator) + $analysisResults + @("", "분석 완료 시간: $(Get-Date)")
    
    # 디렉터리 생성
    $dir = Split-Path $OutputPath
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    $content | Out-File -FilePath $OutputPath -Append -Encoding UTF8
    Write-Host "`n분석 결과가 저장되었습니다: $OutputPath" -ForegroundColor Cyan
}

Write-Host "`n=== 보안 로그 분석 완료 ===" -ForegroundColor Green
```

## 참고 자료

### Windows 서비스팩 및 패치 관리
- **Windows Server EOS 상황 확인 필수**
- **정기적인 보안 패치 적용**
- **패치 적용 전 충분한 테스트**

### 이벤트 ID 참고
- **4624**: 성공적인 로그온
- **4625**: 로그온 실패
- **4740**: 계정 잠금
- **4672**: 특별 권한으로 로그온
- **4648**: 명시적 자격 증명을 사용한 로그온 시도

### 로그 관리 모범 사례
1. **로그 크기**: 최소 10MB 이상
2. **보존 기간**: 최소 90일
3. **정기적 검토**: 주 단위로 보안 로그 검토
4. **자동 분석**: 스크립트를 통한 자동 분석 및 보고