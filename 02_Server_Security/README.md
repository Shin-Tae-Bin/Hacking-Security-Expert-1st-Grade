# 02_Server_Security - 서버 보안

## 📋 개요
해킹보안전문가 1급 과정의 서버 보안 파트입니다. UNIX와 Windows 시스템의 보안 취약점 분석과 대응 방안을 학습합니다.

## 📚 강의 구성

### 🐧 UNIX 시스템 보안 (3-5강)
#### [3강: 보안취약점(서버보안 UNIX) 01](./01_UNIX_Security_01.md)
- 계정 관리 기초
  - root 계정 원격 접속 제한
  - root 계정 su 제한  
  - 패스워드 최소 길이 설정
  - 패스워드 최대/최소 사용 기간 설정
  - 패스워드 복잡성 설정
- 계정 정책
  - 불필요한 계정 제거
  - 관리자 그룹에 최소한의 계정 포함

#### [4강: 보안취약점(서버보안 UNIX) 02](./02_UNIX_Security_02.md)
- 고급 계정 관리
  - 계정이 존재하지 않는 GID 금지
  - 동일한 UID 금지
  - 계정 잠금 임계값 설정
  - 사용자 Shell 점검
- 인증 보안
  - 패스워드 파일 보호 (shadow 패스워드)
  - Session Timeout 설정

#### [5강: 보안취약점(서버보안 UNIX) 03](./03_UNIX_Security_03.md)
- 파일 및 디렉터리 관리
  - root 홈, 패스 디렉터리 권한 및 패스 설정
  - 파일 및 디렉터리 소유자 설정
  - 중요 시스템 파일 권한 설정
    - /etc/passwd 파일 소유자 및 권한
    - /etc/shadow 파일 소유자 및 권한  
    - /etc/hosts 파일 소유자 및 권한
    - /etc/(x)inetd.conf 파일 소유자 및 권한
    - /etc/syslog.conf 파일 소유자 및 권한
    - /etc/services 파일 소유자 및 권한
    - hosts.lpd 파일 소유자 및 권한

### 🪟 Windows 시스템 보안 (6-10강)
#### [6강: 보안취약점(서버보안 Windows) 01](./04_Windows_Security_01.md)
- 계정 관리
  - Administrator 계정 이름 바꾸기
  - Guest 계정 상태 관리
  - 불필요한 계정 제거
  - Everyone 사용 권한을 익명 사용자에게 적용 제한
- 암호 정책
  - 패스워드 복잡성 설정
  - 해독 가능한 암호화를 사용하여 암호 저장 금지
  - 마지막 사용자 이름 표시 안함
- 접근 제어
  - 로컬 로그온 허용 제한
  - 익명 SID/이름 변환 허용 안함

#### [7강: 보안취약점(서버보안 Windows) 02](./05_Windows_Security_02.md)
- 고급 계정 관리
  - 관리자 그룹에 최소한의 사용자 포함
  - 최근 암호 기억 설정
  - 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
  - 원격터미널 접속 가능한 사용자 그룹 제한
- 서비스 관리
  - 공유 권한 및 사용자 그룹 설정
  - 하드디스크 기본 공유 제거
  - 불필요한 서비스 제거
  - NetBIOS 바인딩 서비스 구동 점검
  - 원격터미널 접속 타임아웃 설정

#### [8강: 보안취약점(서버보안 Windows) 03](./06_Windows_Security_03.md)  
- 시스템 관리
  - 예약된 작업에 의심스러운 명령 등록 점검
- 패치 관리
  - 최신 서비스팩 적용
  - 최신 HOT FIX 적용  
  - 백신 프로그램 업데이트
- 로그 관리
  - 정책에 따른 시스템 로깅 설정
  - 이벤트 로그 관리 설정
  - 원격에서 이벤트 로그 파일 접근 차단
  - 로그의 정기적 검토 및 보고

#### [9강: 보안취약점(서버보안 Windows) 04](./07_Windows_Security_04.md)
- 보안 관리
  - 원격으로 액세스할 수 있는 레지스트리 경로 차단
  - 백신 프로그램 설치
  - 사용자가 프린터 드라이버를 설치할 수 없게 함
  - 세션 연결을 중단하기 전에 필요한 유휴시간 설정
  - 경고 메시지 설정
  - 사용자별 홈 디렉터리 권한 설정

#### [10강: 보안취약점(서버보안 Windows) 05](./08_Windows_Security_05.md)
- 최고 수준 보안 설정
  - 원격 시스템에서 시스템 강제 종료 차단
  - 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 설정
  - SAM 계정과 공유의 익명 열거 허용 안 함
  - LAN Manager 인증 수준 강화
  - 보안 채널 데이터 디지털 암호화 또는 서명
  - 이동식 미디어 포맷 및 꺼내기 허용 제한
  - 디스크볼륨 암호화 설정
  - 컴퓨터 계정 암호 최대 사용 기간 설정

## 🔧 실습 도구 및 환경

### UNIX/Linux 환경
- **배포판**: CentOS, RHEL, Ubuntu Server
- **주요 명령어**: 
  - `useradd`, `usermod`, `userdel`
  - `passwd`, `chage`
  - `chmod`, `chown`, `chgrp`
  - `find`, `grep`, `awk`
  - `service`, `systemctl`

### Windows 환境  
- **운영체제**: Windows Server 2012/2016/2019/2022
- **주요 도구**:
  - `SECPOL.MSC` (로컬 보안 정책)
  - `GPEDIT.MSC` (그룹 정책 편집기)
  - `LUSRMGR.MSC` (로컬 사용자 및 그룹)
  - `SERVICES.MSC` (서비스 관리)
  - `EVENTVWR.MSC` (이벤트 뷰어)
  - `FSMGMT.MSC` (공유 폴더)

## 📊 보안 점검 체크리스트

### ✅ UNIX/Linux 보안 체크리스트
#### 계정 관리
- [ ] root 계정 원격 접속 차단
- [ ] 불필요한 계정 삭제
- [ ] 패스워드 정책 설정 (길이, 복잡성, 만료)
- [ ] Shadow 패스워드 사용
- [ ] 동일한 UID/GID 제거

#### 파일 시스템
- [ ] 중요 파일 권한 설정 (644/400)
- [ ] 소유자 없는 파일 정리
- [ ] PATH 환경변수 점검
- [ ] SetUID/SetGID 파일 점검

#### 네트워크 서비스
- [ ] 불필요한 서비스 중지
- [ ] xinetd/inetd 서비스 최소화
- [ ] Session Timeout 설정

### ✅ Windows 보안 체크리스트  
#### 계정 관리
- [ ] Administrator 계정명 변경
- [ ] Guest 계정 비활성화
- [ ] 패스워드 복잡성 활성화
- [ ] 계정 잠금 정책 설정
- [ ] 로그온 경고 메시지 설정

#### 서비스 관리
- [ ] 불필요한 서비스 중지
- [ ] 기본 공유(C$, D$, Admin$) 보안 설정
- [ ] NetBIOS over TCP/IP 비활성화
- [ ] 원격 레지스트리 서비스 중지

#### 네트워크 보안
- [ ] SAM 계정 익명 열거 차단
- [ ] LAN Manager 인증 수준 강화
- [ ] 보안 채널 암호화 활성화

#### 감사 및 로깅
- [ ] 감사 정책 활성화
- [ ] 이벤트 로그 크기 10MB 이상
- [ ] 로그 파일 접근 권한 제한

## 🚨 주요 보안 위험도 분류

### 🔴 높음 (Critical)
- root/Administrator 권한 탈취
- 원격 코드 실행
- 시스템 파일 변조
- SAM 데이터베이스 노출

### 🟡 중간 (Medium)  
- 권한 상승
- 서비스 거부 공격
- 정보 노출
- 세션 하이재킹

### 🟢 낮음 (Low)
- 정보 수집
- 사회공학 공격 소재 제공
- 계정 존재 여부 확인

## 📖 추가 학습 자료

### 보안 가이드라인
- **NIST Cybersecurity Framework**
- **CIS Controls (Center for Internet Security)**
- **OWASP Server Security Guidelines**
- **Korean National Information Security Agency (KISA) Guidelines**

### 실습 환경 구축
- **가상화**: VMware, VirtualBox, Hyper-V
- **컨테이너**: Docker, LXC
- **클라우드**: AWS, Azure, GCP

### 보안 도구
#### UNIX/Linux
- **Lynis**: 시스템 감사 도구
- **ClamAV**: 오픈소스 안티바이러스
- **AIDE**: 파일 무결성 검사
- **fail2ban**: 침입 탐지 및 방지

#### Windows
- **Microsoft Baseline Security Analyzer (MBSA)**
- **Windows Security Compliance Toolkit**
- **Sysinternals Suite**
- **Event Log Explorer**

## 💡 실무 적용 팁

### 정기 점검 주기
- **일일**: 로그 모니터링, 실패한 로그인 시도 확인
- **주간**: 계정 상태 점검, 불필요한 프로세스 확인
- **월간**: 패치 적용, 보안 정책 검토
- **분기**: 전체 보안 감사, 취약점 스캔

### 자동화 스크립트 활용
- 각 강의별로 제공된 PowerShell/Bash 스크립트 활용
- 정기적인 보안 점검 자동화
- 보안 설정 표준화 및 일괄 적용

### 인시던트 대응
1. **탐지**: 로그 분석, 이상 징후 포착
2. **분석**: 공격 벡터 파악, 영향 범위 확인  
3. **억제**: 추가 피해 방지, 시스템 격리
4. **복구**: 시스템 복원, 보안 강화
5. **학습**: 사후 분석, 재발 방지 대책

---

## 📞 문의 및 기여

이 자료에 대한 문의나 개선사항은 GitHub Issues를 통해 제안해 주세요.

**작성자**: [Shin-Tae-Bin](https://github.com/Shin-Tae-Bin)  
**프로젝트**: [Hacking-Security-Expert-1st-Grade](https://github.com/Shin-Tae-Bin/Hacking-Security-Expert-1st-Grade)

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*