# 6강: 보안취약점(서버보안 Windows) 

## 개요
Windows 서버의 기본적인 보안 취약점과 대응 방안을 다루는 첫 번째 강의입니다. Windows 계정 관리와 기본 보안 정책 설정을 중심으로 학습합니다.

## 주요 내용

### 1. Administrator 계정 이름 바꾸기

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- Administrator 계정은 로그온 실패 시에도 절대 접속 차단되지 않음
- 공격자가 패스워드 유추를 계속 시도할 수 있음
- Brute force 공격이나 사전 공격에 매우 취약

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > LUSRMGR.MSC > 그룹 > Administrators > 속성에서 확인
```

#### 대응 방안
- Administrator 계정 이름 변경
- 강력한 패스워드 설정 (최소 8자 이상, 숫자+영문+특수문자 조합)
- Administrators 그룹 구성원을 최소한으로 제한

```
[Windows 2012 설정 방법]
1. 시작 > 실행 > LUSRMGR.MSC > 그룹 > Administrators > 속성
2. Administrators 그룹에서 불필요한 계정 제거 후 다른 그룹으로 변경
```

#### 기준
- **양호**: Administrators 그룹에 관리자 계정이 하나만 존재할 경우
- **취약**: 두 개 이상 존재할 경우

### 2. Guest 계정 상태

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득

#### 보안 이슈
- 대부분의 시스템에서 Guest 계정 사용 불필요
- 불특정 다수의 접근 가능 시 보안 위험
- 익명 사용자의 시스템 접근 경로 제공

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > LUSRMGR.MSC > 사용자 > Guest에서 상태 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > LUSRMGR.MSC > 사용자 > Guest > 속성
2. "계정 사용 안함"에 체크
```

#### 기준
- **양호**: Guest 계정 비활성화
- **취약**: Guest 계정 활성화

### 3. 불필요한 계정 제거

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 시스템 접속을 통한 파일 삭제, 유출 및 관련 피해

#### 보안 이슈
- 퇴직, 전직, 휴직으로 더 이상 사용하지 않는 계정
- 테스트 목적으로 생성된 임시 계정
- 의심스러운 계정들의 존재

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > LUSRMGR.MSC > 사용자에서 불필요한 계정 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > LUSRMGR.MSC > 사용자 > "불필요한 사용자 선택" > 속성
2. "계정 사용 안함"에 체크하거나 계정 삭제
```

#### 기준
- **양호**: 불필요한 계정이 존재하지 않을 경우
- **취약**: 불필요한 계정이 존재할 경우

### 4. Everyone 사용 권한을 익명 사용자에게 적용

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 악의적인 사용자에 의한 접근

#### 보안 이슈
- Everyone 그룹은 익명 사용자 포함
- 공유 폴더를 Everyone 그룹으로 설정 시 익명 접근 가능
- 기본 공유(C$, D$, Admin$, IPC$)를 제외한 공유에서 위험

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > FSMGMT.MSC > 공유에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > FSMGMT.MSC > 공유
2. 사용 권한에서 Everyone으로 된 공유를 제거하고 필요한 계정의 적절한 권한 추가
```

#### 기준
- **양호**: 일반공유 디렉터리가 없거나 공유 디렉터리 접근 권한에 Everyone이 없을 경우
- **취약**: 일반공유 디렉터리의 접근 권한에 Everyone이 있을 경우

### 5. 패스워드 복잡성 설정

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 공격자가 암호를 쉽게 해독하여 임의의 명령어 실행, 임의의 파일 수정, 시스템 관리자 권한 획득 가능

#### 보안 이슈
- 영숫자만으로 구성된 암호는 쉽게 해독 가능
- 광범위한 문자 조합으로 보안성 강화 필요
- 패스워드 공격 도구에 대한 방어

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호정책에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호정책
2. "암호는 복잡성을 만족해야 함"을 "사용"으로 설정
```

#### 복잡성 요구사항
- 영문, 숫자, 특수문자 중 2종류 이상을 조합하여 최소 10자 이상
- 또는 3종류 이상을 조합하여 최소 8자 이상
- 연속적인 숫자나 개인정보 사용 금지
- 12345678과 같은 일련번호 사용 금지
- love, happy와 같은 잘 알려진 단어 사용 금지

#### 기준
- **양호**: "암호는 복잡성을 만족해야 함" 정책이 "사용"으로 되어 있을 경우
- **취약**: "암호는 복잡성을 만족해야 함" 정책이 "사용안함"으로 되어 있을 경우

### 6. 해독 가능한 암호화를 사용하여 암호 저장

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 공격자가 암호를 쉽게 해독할 수 있음

#### 보안 이슈
- 해독 가능한 방식으로 저장된 암호는 복호화 가능
- 공격자가 이를 악용하여 네트워크 리소스에 로그온 가능
- 인증 프로토콜에서만 필요한 기능

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호정책에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 계정 정책 > 암호정책
2. "해독 가능한 암호화를 사용하여 암호 저장"을 "사용안함"으로 설정
```

#### 기준
- **양호**: "해독 가능한 암호화를 사용하여 암호 저장" 정책이 "사용안함"으로 되어 있을 경우
- **취약**: "해독 가능한 암호화를 사용하여 암호 저장" 정책이 "사용"으로 되어 있을 경우

### 7. 마지막 사용자 이름 표시 안함

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: Login ID를 공격자가 알 수 있으므로 공격 가능

#### 보안 이슈
- Windows 로그온 대화 상자에 마지막 로그온한 사용자 이름 표시
- 공격자가 콘솔 접근 시 사용자 이름 확인 가능
- 사용자명을 알고 있으면 패스워드만 추측하면 됨

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬정책 > 보안옵션
2. "마지막 사용자 이름 표시 안 함"을 "사용"으로 설정
```

#### 기준
- **양호**: "마지막 사용자 이름 표시 안 함"이 "사용"으로 설정되어 있을 경우
- **취약**: "마지막 사용자 이름 표시 안 함"이 "사용안함"으로 설정되어 있을 경우

### 8. 로컬 로그온 허용

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 임의의 사용자가 로컬로 로그온할 수 있음

#### 보안 이슈
- 권한이 없는 사용자의 콘솔 로그온 가능
- 악의적인 코드 다운로드 및 실행 위험
- 사용 권한 향상 시도 가능

#### 점검 방법
```
[Windows 2012]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 사용자 권한 할당
2. "로컬 로그온 허용" 정책에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 사용자 권한 할당
2. "로컬 로그온 허용" 정책에 "Administrators", "IUSR_" 외 다른 계정 및 그룹 제거
```

#### 기준
- **양호**: "로컬 로그온 허용" 정책에 "Administrators", "IUSR_"만 존재할 경우
- **취약**: "로컬 로그온 허용" 정책에 "Administrators", "IUSR_" 외 다른 계정 및 그룹이 존재할 경우

### 9. 익명 SID/이름 변환 허용

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 암호 추측 공격이 쉬워짐

#### 보안 이슈
- 익명 사용자가 다른 사용자의 SID 특성 요청 가능
- Administrator SID를 통해 실제 이름 확인 가능
- 이름 확인 후 패스워드 추측 공격 실행

#### 점검 방법
```
[Windows 2012]
시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션에서 확인
```

#### 대응 방안
```
[Windows 2012 설정 방법]
1. 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안옵션
2. "익명 SID/이름 변환 허용" 정책을 "사용안함"으로 설정
```

#### 기준
- **양호**: "익명SID/이름 변환 허용" 정책이 "사용안함"으로 되어 있을 경우
- **취약**: "익명SID/이름 변환 허용" 정책이 "사용"으로 되어 있을 경우

## 종합 점검 스크립트

```powershell
# Windows 서버 기본 보안 점검 스크립트
# PowerShell 관리자 권한으로 실행 필요

Write-Host "=== Windows 서버 기본 보안 점검 시작 ===" -ForegroundColor Green

# 1. Guest 계정 상태 확인
Write-Host "`n1. Guest 계정 상태 확인" -ForegroundColor Yellow
$guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guestAccount) {
    if ($guestAccount.Enabled) {
        Write-Host "  결과: 취약 - Guest 계정이 활성화되어 있습니다." -ForegroundColor Red
    } else {
        Write-Host "  결과: 양호 - Guest 계정이 비활성화되어 있습니다." -ForegroundColor Green
    }
} else {
    Write-Host "  Guest 계정을 찾을 수 없습니다." -ForegroundColor Gray
}

# 2. Administrators 그룹 구성원 확인
Write-Host "`n2. Administrators 그룹 구성원 확인" -ForegroundColor Yellow
$adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
if ($adminMembers) {
    Write-Host "  현재 Administrators 그룹 구성원:"
    foreach ($member in $adminMembers) {
        Write-Host "    - $($member.Name)" -ForegroundColor Cyan
    }
    if ($adminMembers.Count -gt 2) {
        Write-Host "  결과: 주의 - 관리자 그룹에 여러 계정이 있습니다." -ForegroundColor Yellow
    } else {
        Write-Host "  결과: 양호" -ForegroundColor Green
    }
}

# 3. 패스워드 정책 확인 (보안 정책 확인)
Write-Host "`n3. 패스워드 정책 확인" -ForegroundColor Yellow
try {
    $secPolicy = Get-LocalSecurityPolicy -Area SECURITYPOLICY -ErrorAction SilentlyContinue
    Write-Host "  주의: 패스워드 정책은 secpol.msc에서 수동 확인이 필요합니다." -ForegroundColor Yellow
} catch {
    Write-Host "  주의: 패스워드 정책 자동 확인 불가. secpol.msc에서 수동 확인하세요." -ForegroundColor Yellow
}

# 4. 공유 폴더 Everyone 권한 확인
Write-Host "`n4. 공유 폴더 확인" -ForegroundColor Yellow
$shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }
if ($shares) {
    Write-Host "  발견된 일반 공유:"
    foreach ($share in $shares) {
        Write-Host "    - $($share.Name): $($share.Path)" -ForegroundColor Cyan
        # Everyone 권한 확인은 별도 도구 필요
    }
    Write-Host "  주의: Everyone 권한은 fsmgmt.msc에서 수동 확인이 필요합니다." -ForegroundColor Yellow
} else {
    Write-Host "  결과: 양호 - 일반 공유 폴더가 없습니다." -ForegroundColor Green
}

Write-Host "`n=== Windows 서버 기본 보안 점검 완료 ===" -ForegroundColor Green
Write-Host "추가적인 보안 정책 확인은 secpol.msc를 사용하세요." -ForegroundColor Cyan
```

## 주요 관리 도구

### Windows 2012 관리 콘솔
- **LUSRMGR.MSC**: 로컬 사용자 및 그룹 관리
- **SECPOL.MSC**: 로컬 보안 정책
- **FSMGMT.MSC**: 공유 폴더 관리
- **EVENTVWR.MSC**: 이벤트 뷰어

### 보안 정책 경로
- **계정 정책** → **암호 정책**: 패스워드 관련 설정
- **로컬 정책** → **보안 옵션**: 기타 보안 설정
- **로컬 정책** → **사용자 권한 할당**: 사용자 권한 관리

## 참고 자료

### 강력한 패스워드 가이드라인
1. **길이**: 최소 8자 이상 (권장 12자 이상)
2. **복잡성**: 영문 대소문자, 숫자, 특수문자 조합
3. **금지사항**: 개인정보, 연속된 숫자, 키보드 패턴, 일반적인 단어
4. **변경주기**: 90일마다 변경 권장

### 계정 관리 모범 사례
1. **최소 권한 원칙**: 필요한 최소한의 권한만 부여
2. **계정 분리**: 관리용과 일반용 계정 분리
3. **정기 검토**: 계정 사용 현황 정기적 점검
4. **로그 모니터링**: 로그인 실패 및 성공 로그 모니터링
