# 5강: 보안취약점(서버보안 UNIX) 03

## 개요
UNIX 서버 보안의 세 번째 강의로, 주요 시스템 파일의 권한 설정과 관리를 중심으로 다룹니다. 시스템 보안에 핵심적인 파일들의 적절한 권한 설정 방법을 학습합니다.

## 주요 내용

### 1. /etc/passwd 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 임의적인 파일 정보 습득, 파일 변경

#### 보안 이슈
- 사용자 ID, 패스워드, UID, GID, 홈 디렉터리, shell 정보 포함
- 이 파일이 노출되면 보안상 심각한 문제 발생
- 관리자 이외의 사용자 접근 제한 필요

#### 점검 방법
```bash
# 파일 권한 및 소유자 확인
ls -l /etc/passwd
```

#### 대응 방안
```bash
# 적절한 권한 설정
chmod 644 /etc/passwd
chown root:root /etc/passwd

# HP-UX의 경우
chmod 400 /etc/passwd
chown root:sys /etc/passwd
```

#### 기준
- **양호**: 파일 퍼미션 644, 소유자 root
- **취약**: root 외의 사용자 퍼미션이 644 이상이거나 소유자가 root가 아닌 경우

### 2. /etc/shadow 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 매우 높음
- **위협 영향**: 임의적인 파일 정보 습득, 파일 변경

#### 보안 이슈
- 암호화된 패스워드 정보를 담고 있는 핵심 파일
- root 외 사용자 접근 시 패스워드 유추 공격 가능
- 일반 사용자에게는 접근이 절대 허용되면 안 됨

#### 점검 방법

##### SunOS, Linux
```bash
ls -l /etc/shadow
```

##### AIX
```bash
ls -ld /etc/security/passwd
```

##### HP-UX
```bash
ls -ld /tcb/files/auth
```

#### 대응 방안

##### SunOS, Linux
```bash
chmod 400 /etc/shadow
chown root:root /etc/shadow
```

##### AIX
```bash
# /etc/security/passwd 파일 권한 설정
chown root /etc/security/passwd
chmod 400 /etc/security/passwd
```

##### HP-UX
```bash
# /tcb/files/auth 디렉터리 권한 설정
chown root /tcb/files/auth
chmod 400 /tcb/files/auth
```

#### 기준
- **양호**: 파일 퍼미션 400, 소유자 root
- **취약**: 위와 동일한 퍼미션과 소유자가 아닌 경우

### 3. /etc/hosts 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 외부에서 IP 스푸핑 공격 위험

#### 보안 이슈
- 호스트명과 IP 주소 매핑 정보 포함
- 일반 사용자 접근 허용 시 스푸핑 공격에 활용 가능
- 네트워크 보안에 중요한 파일

#### 점검 방법
```bash
ls -l /etc/hosts
```

#### 대응 방안
```bash
chmod 600 /etc/hosts
chown root:root /etc/hosts
```

#### 기준
- **양호**: 파일 퍼미션 600, 소유자 root
- **취약**: 위와 동일한 퍼미션과 소유자가 아닌 경우

### 4. /etc/(x)inetd.conf 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 임의적인 파일 정보 습득, 파일 변경

#### 보안 이슈
- inetd 서비스 설정 파일
- 네트워크 서비스 관리에 필요한 설정 정보 포함
- 권한 설정 부적절 시 서비스 설정 변조 가능

#### 점검 방법
```bash
ls -l /etc/inetd.conf
# 또는 xinetd 사용하는 경우
ls -l /etc/xinetd.conf
ls -ld /etc/xinetd.d/
```

#### 대응 방안

##### SunOS, Linux, AIX, HP-UX
```bash
chown root /etc/inetd.conf
chmod 600 /etc/inetd.conf
```

##### Linux (xinetd 사용 시)
```bash
chown root /etc/xinetd.conf
chmod 600 /etc/xinetd.conf

# /etc/xinetd.d/ 하위 파일들도 동일하게 설정
chown root /etc/xinetd.d/*
chmod 600 /etc/xinetd.d/*
```

#### 기준
- **양호**: 파일 퍼미션 600, 소유자 root
- **취약**: 위와 동일한 퍼미션과 소유자가 아닌 경우

### 5. /etc/syslog.conf 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 일반 사용자가 syslog 파일에 접근할 수 있음

#### 보안 이슈
- 시스템 로그 설정 파일
- 일반 사용자가 접근하여 로그 설정을 변경할 위험
- 로그 정보 조작으로 보안 사고 은폐 가능

#### 점검 방법
```bash
ls -l /etc/syslog.conf
# 또는 rsyslog 사용하는 경우
ls -l /etc/rsyslog.conf
```

#### 대응 방안
```bash
chmod 644 /etc/syslog.conf
chown root:root /etc/syslog.conf
```

#### 기준
- **양호**: 퍼미션 644, 소유자 root
- **취약**: 위와 동일한 설정이 아닌 경우

### 6. /etc/services 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 일반 사용자가 services 파일에 접근할 수 있음

#### 보안 이슈
- 포트와 서비스 매핑 정보 포함
- 일반 사용자 접근 허용 시 네트워크 서비스 정보 노출
- 서비스 설정 정보 조작 가능성

#### 점검 방법
```bash
ls -l /etc/services
```

#### 대응 방안
```bash
chmod 644 /etc/services
chown root:root /etc/services
```

#### 기준
- **양호**: 퍼미션 644, 소유자 root
- **취약**: 위와 동일한 설정이 아닌 경우

### 7. /etc/hosts.lpd 파일 소유자 및 권한 설정

#### 취약점 개요
- **위험도**: 중간
- **위협 영향**: 외부에서 IP 스푸핑 공격 위험

#### 보안 이슈
- 로컬 프린트 서비스 허가 사용자 정보 저장
- hostname, IP 주소 정보 포함
- 일반 사용자 접근 허용 시 스푸핑 공격에 활용 가능

#### 점검 방법
```bash
ls -l /etc/hosts.lpd
```

#### 대응 방안
```bash
chmod 600 /etc/hosts.lpd
chown root:root /etc/hosts.lpd
```

#### 기준
- **양호**: 파일 퍼미션 600, 소유자 root
- **취약**: 위와 동일한 퍼미션과 소유자가 아닌 경우

### 8. Root 홈, 패스 디렉터리 권한 및 패스 설정

#### 취약점 개요
- **위험도**: 높음
- **위협 영향**: 환경변수를 통한 root 권한 노출

#### 보안 이슈
- root의 PATH 환경변수에 "." 또는 "::" 포함 시 위험
- 현재 디렉터리 또는 빈 경로를 통한 악성 명령어 실행 가능
- 침입자가 root 권한을 획득할 수 있는 경로 제공

#### 점검 방법
```bash
# PATH 변수 확인
echo $PATH

# 환경변수 전체 확인
env | grep PATH
```

#### 대응 방안
```bash
# /etc/profile 수정
vi /etc/profile

# PATH에서 "." 및 "::" 제거
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
```

#### Shell별 환경설정 파일
- `/bin/sh` → `/etc/profile`, `$HOME/.profile`
- `/bin/csh` → `$HOME/.cshrc`, `$HOME/.login`, `/etc/.login`
- `/bin/ksh` → `/etc/profile`, `$HOME/.profile`, `$HOME/.kshrc`
- `/bin/bash` → `/etc/profile`, `$HOME/.bash_profile`

#### 기준
- **양호**: Root 검색경로에 "." 이나 "::" 항목이 제거된 경우
- **취약**: Root 검색경로에 "." 이나 "::" 항목이 포함된 경우

## 종합 점검 스크립트

```bash
#!/bin/bash
# UNIX 파일 권한 종합 점검 스크립트

echo "=== UNIX 시스템 파일 권한 점검 시작 ==="

# 점검할 파일들과 기준값 정의
declare -A files_perms=(
    ["/etc/passwd"]="644:root"
    ["/etc/shadow"]="400:root"
    ["/etc/hosts"]="600:root"
    ["/etc/inetd.conf"]="600:root"
    ["/etc/xinetd.conf"]="600:root"
    ["/etc/syslog.conf"]="644:root"
    ["/etc/rsyslog.conf"]="644:root"
    ["/etc/services"]="644:root"
    ["/etc/hosts.lpd"]="600:root"
)

# 파일별 권한 점검
for file in "${!files_perms[@]}"; do
    if [ -f "$file" ]; then
        expected_perm=$(echo ${files_perms[$file]} | cut -d: -f1)
        expected_owner=$(echo ${files_perms[$file]} | cut -d: -f2)
        
        # 현재 권한과 소유자 확인
        current_perm=$(stat -c "%a" "$file" 2>/dev/null)
        current_owner=$(stat -c "%U" "$file" 2>/dev/null)
        
        echo "점검 파일: $file"
        echo "  기준: $expected_perm / $expected_owner"
        echo "  현재: $current_perm / $current_owner"
        
        if [ "$current_perm" = "$expected_perm" ] && [ "$current_owner" = "$expected_owner" ]; then
            echo "  결과: 양호"
        else
            echo "  결과: 취약 - 권한 수정 필요"
            echo "  수정 명령: chmod $expected_perm $file && chown $expected_owner $file"
        fi
        echo ""
    else
        echo "$file: 파일이 존재하지 않음"
        echo ""
    fi
done

# PATH 환경변수 점검
echo "PATH 환경변수 점검:"
echo "현재 PATH: $PATH"
if echo "$PATH" | grep -E "\.|::" >/dev/null; then
    echo "결과: 취약 - PATH에 '.' 또는 '::' 포함됨"
    echo "수정: PATH에서 '.' 및 '::' 제거 필요"
else
    echo "결과: 양호"
fi

echo ""
echo "=== UNIX 시스템 파일 권한 점검 완료 ==="
```

## 자동 수정 스크립트

```bash
#!/bin/bash
# UNIX 파일 권한 자동 수정 스크립트 (주의: 실행 전 백업 필요)

echo "=== UNIX 시스템 파일 권한 자동 수정 시작 ==="
echo "주의: 실행 전 중요 파일들을 백업하세요!"
read -p "계속하시겠습니까? (y/N): " answer

if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
    echo "작업이 취소되었습니다."
    exit 1
fi

# 백업 디렉터리 생성
backup_dir="/tmp/unix_security_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"

# 파일 권한 수정
fix_file_permission() {
    local file=$1
    local perm=$2
    local owner=$3
    
    if [ -f "$file" ]; then
        echo "백업: $file -> $backup_dir/"
        cp "$file" "$backup_dir/"
        
        echo "수정: $file ($perm, $owner)"
        chmod "$perm" "$file"
        chown "$owner" "$file"
        echo "완료: $file"
    else
        echo "파일 없음: $file"
    fi
    echo ""
}

# 각 파일 권한 수정
fix_file_permission "/etc/passwd" "644" "root:root"
fix_file_permission "/etc/shadow" "400" "root:root"
fix_file_permission "/etc/hosts" "600" "root:root"
fix_file_permission "/etc/inetd.conf" "600" "root:root"
fix_file_permission "/etc/xinetd.conf" "600" "root:root"
fix_file_permission "/etc/syslog.conf" "644" "root:root"
fix_file_permission "/etc/rsyslog.conf" "644" "root:root"
fix_file_permission "/etc/services" "644" "root:root"
fix_file_permission "/etc/hosts.lpd" "600" "root:root"

echo "백업 위치: $backup_dir"
echo "=== 파일 권한 수정 완료 ==="
```

## 참고 자료

### 중요 시스템 파일 권한 요약표

| 파일명 | 권한 | 소유자 | 용도 |
|--------|------|--------|------|
| /etc/passwd | 644 | root:root | 사용자 계정 정보 |
| /etc/shadow | 400 | root:root | 암호화된 패스워드 |
| /etc/hosts | 600 | root:root | 호스트명-IP 매핑 |
| /etc/inetd.conf | 600 | root:root | inetd 서비스 설정 |
| /etc/xinetd.conf | 600 | root:root | xinetd 서비스 설정 |
| /etc/syslog.conf | 644 | root:root | 시스템 로그 설정 |
| /etc/services | 644 | root:root | 포트-서비스 매핑 |
| /etc/hosts.lpd | 600 | root:root | 프린트 서비스 허가 |

### 권한 표기법
- **644**: 소유자 읽기/쓰기, 그룹/기타 읽기만
- **600**: 소유자 읽기/쓰기, 그룹/기타 접근 금지
- **400**: 소유자 읽기만, 그룹/기타 접근 금지

### 주요 명령어
- `chmod`: 파일 권한 변경
- `chown`: 파일 소유자 변경
- `stat`: 파일 상태 정보 확인
- `ls -l`: 파일 권한 및 소유자 확인