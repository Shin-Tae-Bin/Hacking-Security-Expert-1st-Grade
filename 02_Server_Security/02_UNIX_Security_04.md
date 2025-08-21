# 4강: 보안취약점(서버보안 UNIX) 

## 개요
UNIX 서버 보안의 두 번째 강의로, 계정 관리의 고급 기능과 파일 시스템 보안을 다룹니다. GID/UID 관리, 계정 잠금, 패스워드 파일 보호 등을 중점적으로 학습합니다.

## 주요 내용

### 1. 계정이 존재하지 않는 GID 금지

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 관리되지 않는 그룹을 통한 시스템 접속

#### 보안 이슈
- 구성원이 존재하지 않는 빈 그룹의 관리 소홀
- 해당 그룹 소유의 파일이 비인가자에게 노출될 위험
- 그룹 관리가 정상적으로 이루어지지 않을 가능성

#### 점검 방법
```bash
# 그룹 정보 확인
cat /etc/group

# 구성원이 없는 그룹 확인
for group in $(cut -d: -f1 /etc/group); do
    if ! getent group $group | grep -q ":.*:"; then
        echo "Empty group: $group"
    fi
done
```

#### 대응 방안
```bash
# 불필요한 그룹 삭제
groupdel [그룹명]
```

### 2. 동일한 UID 금지

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 중복된 UID를 통한 잘못된 권한부여

#### 보안 이슈
- 시스템은 로그인 ID가 달라도 동일한 UID를 같은 사용자로 인식
- 중복된 UID 존재 시 보안상 문제 발생 가능
- 권한 혼동으로 인한 보안 취약점 발생

#### 점검 방법
```bash
# 동일한 UID 확인
cat /etc/passwd | cut -d: -f3 | sort | uniq -d

# 상세 확인
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read uid; do
    echo "Duplicate UID $uid:"
    awk -F: -v uid=$uid '$3==uid {print $1}' /etc/passwd
done
```

#### 대응 방안
```bash
# 새로운 UID로 변경
usermod -u [새로운UID] [사용자명]

# AIX의 경우
chuser -id=[새로운UID] [사용자명]
```

### 3. 계정 잠금 임계값 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 미설정 시 패스워드 노출 위협

#### 보안 이슈
- 패스워드 무작위 공격(Brute Force) 대응
- 패스워드 추측(Guessing) 공격 시간 지연
- 자동 공격 도구에 대한 방어

#### 시스템별 설정 방법

##### SunOS
```bash
# /etc/default/login 설정
RETRIES=5

# SunOS 5.9 이상 - policy.conf 설정
echo "LOCK_AFTER_RETRIES=YES" >> /etc/security/policy.conf
```

##### Linux
```bash
# /etc/pam.d/system-auth 설정
auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root
account required /lib/security/pam_tally.so no_magic_root reset

# 옵션 설명:
# no_magic_root: root에는 패스워드 잠금 설정하지 않음
# deny=n: n회 입력 실패시 패스워드 잠금
# unlock_time=n: n초 후 자동 계정 잠김 해제
# reset: 접속 성공시 실패 횟수 초기화
```

##### AIX
```bash
# /etc/security/user 설정
loginretries=5
```

##### HP-UX
```bash
# /tcb/files/auth/system/default 설정
u_maxtries#5

# Trusted Mode 전환 (필요시)
/etc/tsconvert
# UnTrusted Mode로 전환: /etc/tsconvert -r
```

### 4. 사용자 Shell 점검

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 명령어를 해석하여 침입 위협

#### 보안 이슈
- Shell은 사용자 명령을 해석하는 프로그램
- 공격자가 Shell 기능을 악용할 수 있음
- 로그인이 필요 없는 시스템 계정에 Shell 부여는 위험

#### 점검 방법
```bash
# 시스템 계정의 Shell 확인
cat /etc/passwd | grep -E "bin|daemon|adm|sys|nobody"
```

#### 대응 방안
```bash
# 시스템 계정의 Shell 제한
usermod -s /bin/false gopher
usermod -s /bin/false adm
usermod -s /bin/false daemon
usermod -s /bin/false bin
usermod -s /bin/false sys
usermod -s /bin/false listen
usermod -s /bin/false nobody
usermod -s /bin/false nobody4
usermod -s /bin/false noaccess
usermod -s /bin/false diag
usermod -s /bin/false operator
usermod -s /bin/false games
```

### 5. 패스워드 파일 보호 (Shadow 패스워드)

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 패스워드 노출

#### 보안 이슈
- `/etc/passwd` 파일의 패스워드 정보는 모든 사용자가 읽기 가능
- Shadow 패스워드는 암호화된 패스워드를 별도 파일에 저장
- 특별 권한이 있는 사용자만 읽기 가능

#### 점검 방법
```bash
# Shadow 패스워드 사용 확인
cat /etc/passwd | head -5

# /etc/passwd의 두 번째 필드가 'x'로 표시되는지 확인
grep "^[^:]*:x:" /etc/passwd

# Shadow 파일 확인 (root만 가능)
ls -l /etc/shadow
```

#### 대응 방안

##### SunOS, Linux
```bash
# Shadow 패스워드 정책 적용
pwconv

# 일반 패스워드 정책으로 되돌리기 (필요시)
pwunconv

# 새 계정 생성 시 자동으로 Shadow 적용
useradd test
passwd test
```

##### AIX
```bash
# 기본적으로 패스워드를 암호화하여 저장 관리됨
# 별도 설정 불필요
```

##### HP-UX
```bash
# Trusted Mode로 전환
# 패스워드를 암호화하여 /tcb/files/auth에 계정별로 저장
```

### 6. Session Timeout 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 비인가자의 시스템 접속 위험

#### 보안 이슈
- 사용자 부주의로 계정 접속 상태 방치
- 권한 없는 사용자의 악의적 사용 가능
- 일정 시간 후 자동 연결 종료 필요

#### 시스템별 설정 방법

##### SunOS
```bash
# /etc/default/login 설정
TIMEOUT=600
export TMOUT
```

##### Linux, AIX, HP-UX
```bash
# /etc/profile 설정 (sh, ksh, bash 사용시)
TMOUT=600
export TMOUT

# /etc/csh.login 또는 /etc/csh.cshrc 설정 (csh 사용시)
set autologout=10  # 단위: 분
```

### 7. 파일 및 디렉터리 소유자 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 삭제된 소유자의 UID와 동일한 사용자가 해당 파일, 디렉터리 접근 가능

#### 보안 이슈
- 소유자가 존재하지 않는 파일/디렉터리는 보안 위험
- 퇴직자나 관리 소홀로 인해 생성된 파일일 가능성
- 중요 파일일 경우 심각한 문제 발생 가능

#### 점검 방법

##### SunOS, AIX
```bash
find / -nouser -o -nogroup -xdev -ls 2>/dev/null
```

##### HP-UX
```bash
find / \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2>/dev/null
```

##### Linux
```bash
find / -nouser -print
find / -nogroup -print
```

#### 대응 방안
```bash
# 1. 불필요한 파일/디렉터리 삭제
rm [파일명]
rm -rf [디렉터리명]

# 2. 적절한 소유자 및 그룹 변경
chown [사용자명] [파일명]
chown [사용자명]:[그룹명] [파일명]
```

## 점검 스크립트 예시

```bash
#!/bin/bash
# UNIX 서버 고급 보안 점검 스크립트

echo "=== UNIX 서버 고급 보안 점검 시작 ==="

# 1. 중복 UID 확인
echo "1. 중복 UID 확인"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read uid; do
    if [ ! -z "$uid" ]; then
        echo "Duplicate UID found: $uid"
        awk -F: -v uid=$uid '$3==uid {print "  User: " $1}' /etc/passwd
    fi
done

# 2. Shadow 패스워드 사용 확인
echo "2. Shadow 패스워드 사용 확인"
if [ -f /etc/shadow ]; then
    echo "Shadow password is enabled"
    # 일반 패스워드 사용 계정 확인
    awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print "Non-shadow account: " $1}' /etc/passwd
else
    echo "Shadow password is NOT enabled"
fi

# 3. 시스템 계정 Shell 확인
echo "3. 시스템 계정 Shell 확인"
for user in bin daemon adm sys nobody; do
    shell=$(getent passwd $user 2>/dev/null | cut -d: -f7)
    if [ ! -z "$shell" ] && [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
        echo "System account $user has shell: $shell"
    fi
done

# 4. 소유자 없는 파일 확인 (최대 10개만 표시)
echo "4. 소유자 없는 파일 확인 (상위 10개)"
find / -nouser -o -nogroup 2>/dev/null | head -10

# 5. Session Timeout 설정 확인
echo "5. Session Timeout 설정 확인"
if grep -q "TMOUT" /etc/profile; then
    grep "TMOUT" /etc/profile
else
    echo "Session timeout not configured"
fi

echo "=== UNIX 서버 고급 보안 점검 완료 ==="
```

## 참고 자료

### 주요 설정 파일
- `/etc/group`: 그룹 정보
- `/etc/shadow`: 암호화된 패스워드 (Shadow 패스워드)
- `/etc/login.defs`: 로그인 관련 설정
- `/etc/pam.d/`: PAM 인증 설정
- `/etc/profile`: 전역 Shell 환경 설정

### Shell 환경 설정 파일 참조 순서
- `/bin/sh` → `/etc/profile`, `$HOME/.profile`
- `/bin/csh` → `$HOME/.cshrc`, `$HOME/.login`, `/etc/.login`
- `/bin/ksh` → `/etc/profile`, `$HOME/.profile`, `$HOME/.kshrc`
- `/bin/bash` → `/etc/profile`, `$HOME/.bash_profile`

### 주요 명령어
- `pwconv` / `pwunconv`: Shadow 패스워드 설정/해제
- `chage`: 계정 만료 설정
- `find`: 파일 검색
- `getent`: 시스템 데이터베이스 조회
