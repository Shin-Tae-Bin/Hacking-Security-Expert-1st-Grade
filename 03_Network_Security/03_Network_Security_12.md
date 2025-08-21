# 12강: 접근 관리 및 로그 관리 보안 취약점

## 개요
해킹보안전문가 1급 과정의 12강으로, 보안·네트워크 장비의 접근 관리와 로그 관리 취약점을 다룹니다. 로그인 실패횟수 제한, 원격 관리 접근 통제, 보안 접속, Session timeout, 로그 설정 및 백업 등 실무에서 반드시 적용해야 할 보안 설정들을 학습합니다.

## 주요 학습 내용

### 1. 계정 관리 - 로그인 실패횟수 제한 (S-17)

#### 취약점 설명
**암호 공격에서는 자동화된 방법을 통해 모든 사용자 계정에 대해 수천 또는 수백만 개의 암호 조합을 시도**하기 때문에 가능한 로그온 실패 수를 제한하여야 합니다.

- **위협 영향**: Brute Force에 의한 지속적인 계정 공격의 위험

#### Brute Force 공격 패턴
```mermaid
graph LR
    A[공격자] --> B[자동화 도구]
    B --> C[사전 공격]
    B --> D[무차별 공격]
    B --> E[하이브리드 공격]
    
    C --> F[일반 패스워드 목록]
    D --> G[모든 조합 시도]
    E --> H[사전 + 변형]
    
    F --> I[로그인 시도]
    G --> I
    H --> I
    
    I --> J{성공?}
    J -->|Yes| K[계정 침해]
    J -->|No| L[계속 시도]
```

#### 일반적인 공격 도구 및 기법
```bash
# 대표적인 Brute Force 도구들

1. Hydra
   hydra -l admin -P passwords.txt ssh://192.168.1.1

2. Medusa  
   medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh

3. John the Ripper
   john --wordlist=rockyou.txt hashes.txt

4. Hashcat
   hashcat -m 0 -a 0 hashes.txt wordlist.txt
```

#### 점검 방법
```bash
# 보안장비에서 제공하고 있는 계정 메뉴에서 로그인 임계값 확인

# Cisco IOS 예시
Router# show running-config | include login
! login block-for 300 attempts 3 within 60

# 점검 사항
1. 로그인 실패 임계값이 설정되어 있는가?
2. 계정 잠금 시간이 적절한가?
3. 잠금 해제 방법이 정의되어 있는가?
```

#### 조치 방안

##### Cisco 장비 설정
```bash
# Cisco IOS 로그인 실패 제한 설정

# 1. 기본 로그인 실패 제한
Router(config)# login block-for 600 attempts 3 within 60
# 60초 내 3회 실패 시 600초(10분) 동안 차단

# 2. 특정 사용자에 대한 제한
Router(config)# username admin password cisco123
Router(config)# username admin login attempts 5
# 특정 사용자의 로그인 시도 횟수 제한

# 3. 로그인 실패 로깅
Router(config)# login on-failure log
Router(config)# login on-success log

# 4. 화이트리스트 설정 (관리 네트워크 제외)
Router(config)# access-list 10 permit 192.168.100.0 0.0.0.255
Router(config)# login quiet-mode access-class 10
```

##### 방화벽 설정 예시
```bash
# FortiGate 설정
config system admin
    edit "admin"
        set login-max-failed-attempts 3
        set login-block-time 600
    next
end

# Palo Alto 설정
set deviceconfig system login-block-time 10
set deviceconfig system login-failed-attempts 3

# SonicWall 설정
# System > Administration > Admin Accounts
# Failed Login Lockout: 3 attempts, 10 minutes
```

#### 권장 설정값
| 설정 항목 | 권장값 | 설명 |
|-----------|---------|------|
| **실패 허용 횟수** | 3-5회 | 너무 낮으면 정당한 사용자 불편 |
| **잠금 시간** | 10-30분 | 보안과 가용성의 균형 |
| **재시도 간격** | 60초 | 빠른 연속 공격 방지 |
| **로그 기록** | 필수 | 공격 패턴 분석용 |

### 2. 접근 관리 - 원격 관리 접근 통제 (S-5)

#### 취약점 설명
**원격 접속 IP나 계정을 제한하지 않는다면** 임의의 사용자가 원격으로 접속하여 해당 보안장비의 정보를 임의로 변경하거나 훔쳐 갈 가능성이 있으므로 접속 IP와 계정을 제한해야 합니다.

- **위협 영향**: 비인가 사용자가 접속하여 데이터 변경, 손실, 해킹할 가능성

#### 원격 접근 위험 요소
```mermaid
graph TD
    A[원격 관리 인터페이스] --> B[Web GUI]
    A --> C[SSH/Telnet]
    A --> D[SNMP]
    A --> E[API]
    
    B --> F[HTTP/HTTPS 포트]
    C --> G[22/23 포트]
    D --> H[161 UDP 포트]
    E --> I[REST/XML API]
    
    F --> J[브라우저 기반 공격]
    G --> K[프로토콜 취약점]
    H --> L[Community String 공격]
    I --> M[API 키 탈취]
```

#### 점검 방법
```bash
# 원격 접근 제한 설정 확인

# 1. Cisco 장비
Router# show running-config | section line vty
Router# show access-lists

# 2. 방화벽 웹 관리
- 관리자 인터페이스 접속
- System > Administration > Admin Access
- Trusted Hosts 설정 확인

# 3. 네트워크 스캔으로 확인
nmap -sS -O 192.168.1.1
nmap -p 22,23,80,443,161 192.168.1.1
```

#### 조치 방안

##### IP 기반 접근 제한
```bash
# Cisco VTY 접근 제한
Router(config)# access-list 10 permit 192.168.100.10
Router(config)# access-list 10 permit 192.168.100.20
Router(config)# access-list 10 deny any log
Router(config)# line vty 0 4
Router(config-line)# access-class 10 in

# 확장 ACL을 이용한 세밀한 제어
Router(config)# ip access-list extended MGMT_ACCESS
Router(config-ext-nacl)# permit tcp 192.168.100.0 0.0.0.255 any eq 22
Router(config-ext-nacl)# permit tcp 192.168.100.0 0.0.0.255 any eq 443
Router(config-ext-nacl)# deny ip any any log
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip access-group MGMT_ACCESS in
```

##### 시간 기반 접근 제어
```bash
# Cisco 시간 기반 ACL
Router(config)# time-range BUSINESS_HOURS
Router(config-time-range)# periodic weekdays 09:00 to 18:00
Router(config)# ip access-list extended TIME_MGMT
Router(config-ext-nacl)# permit tcp any any eq 22 time-range BUSINESS_HOURS
Router(config-ext-nacl)# deny ip any any
```

##### 다중 인증 팩터
```bash
# FortiGate 2FA 설정
config system admin
    edit "admin"
        set two-factor fortitoken
        set fortitoken "FTKMOB1234567890"
    next
end

# Palo Alto 2FA 설정
set mgt-config users admin authentication-profile 2fa-profile
```

### 3. 접근 관리 - 보안 접속 (S-6)

#### 취약점 설명
**기존의 TCP/IP가 데이터 암호화를 위한 어떠한 방법도 제공해주지 않기** 때문에 Sniffing 등을 통한 네트워크 내에서의 메시지 전송을 도청당할 수 있습니다.

- **위협 영향**: 암호화되지 않은 패킷을 전달하기 때문에 각종 위험에 노출될 가능성이 높음

#### 비보안 프로토콜의 위험성
```mermaid
graph LR
    A[관리자] --> B[평문 프로토콜]
    B --> C[네트워크]
    C --> D[보안장비]
    
    E[공격자] --> F[패킷 스니핑]
    F --> C
    
    B --> G[Telnet]
    B --> H[HTTP]
    B --> I[FTP]
    B --> J[SNMP v1/v2]
    
    G --> K[포트 23]
    H --> L[포트 80]
    I --> M[포트 21]
    J --> N[포트 161]
```

#### 프로토콜별 보안 위험도
| 프로토콜 | 포트 | 암호화 | 위험도 | 대안 |
|----------|------|--------|---------|------|
| **Telnet** | 23/TCP | 없음 | 높음 | SSH |
| **HTTP** | 80/TCP | 없음 | 높음 | HTTPS |
| **FTP** | 21/TCP | 없음 | 높음 | SFTP/SCP |
| **SNMP v1/v2** | 161/UDP | 없음 | 높음 | SNMP v3 |
| **rlogin** | 513/TCP | 없음 | 높음 | SSH |

#### 점검 방법
```bash
# 1. HTTPS를 통한 접속 확인
curl -k https://192.168.1.1
wget --no-check-certificate https://192.168.1.1

# 2. SSH를 통한 접속 확인
ssh admin@192.168.1.1
ssh -v admin@192.168.1.1  # 상세 정보 확인

# 3. 비보안 서비스 포트 스캔
nmap -sS 192.168.1.1 -p 21,23,80,513

# 4. SSL/TLS 인증서 확인
openssl s_client -connect 192.168.1.1:443 -servername 192.168.1.1
```

#### 조치 방안

##### SSH 서비스 활성화
```bash
# Cisco IOS SSH 설정
Router(config)# hostname R1
Router(config)# ip domain-name company.com
Router(config)# crypto key generate rsa general-keys modulus 2048
Router(config)# ip ssh version 2
Router(config)# ip ssh time-out 60
Router(config)# ip ssh authentication-retries 3
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
Router(config-line)# login local
Router(config)# username admin privilege 15 secret cisco123
```

##### HTTPS 활성화
```bash
# Cisco HTTPS 설정
Router(config)# ip http secure-server
Router(config)# ip http secure-port 443
Router(config)# ip http authentication local
Router(config)# no ip http server  # HTTP 비활성화

# 인증서 설정
Router(config)# crypto pki trustpoint HTTPS_CERT
Router(config-ca-trustpoint)# enrollment selfsigned
Router(config-ca-trustpoint)# subject-name cn=R1.company.com
Router(config-ca-trustpoint)# crypto pki enroll HTTPS_CERT
```

##### SNMP v3 설정
```bash
# Cisco SNMP v3 설정
Router(config)# snmp-server group ADMIN v3 auth
Router(config)# snmp-server user admin_user ADMIN v3 auth sha auth_pass priv aes 128 priv_pass
Router(config)# snmp-server host 192.168.1.100 version 3 auth admin_user
Router(config)# no snmp-server community public
Router(config)# no snmp-server community private
```

### 4. 접근 관리 - Session Timeout 설정 (S-7)

#### 취약점 설명
**관리자가 장비에 접속하고 무의식적으로 장시간 접속 터미널을 떠났을 때** 자동으로 접속을 종료하거나 로그아웃이 되도록 설정하는 것이 좋은데, 이는 실수로 로그아웃을 하지 않고 자리를 뜨는 경우에 대비하기 위함입니다.

- **위협 영향**: 비인가자 접속으로 인한 악의적인 행위 발생

#### Session Hijacking 위험
```mermaid
sequenceDiagram
    participant A as 관리자
    participant S as 보안장비
    participant H as 공격자
    
    A->>S: 정상 로그인
    S->>A: 세션 생성
    Note over A,S: 관리자가 자리를 비움
    H->>S: 동일 터미널 접근
    S->>H: 기존 세션 유지
    H->>S: 악의적 명령 실행
    S->>H: 명령 실행 완료
```

#### 점검 방법
```bash
# Cisco 장비 Session Timeout 확인
Router# show running-config | include exec-timeout
Router# show users  # 현재 접속 세션 확인

# 방화벽 웹 인터페이스 확인
# System > Administration > Idle Timeout 설정 확인

# SSH 클라이언트 테스트
ssh admin@192.168.1.1
# 설정된 시간만큼 대기 후 자동 연결 종료 확인
```

#### 조치 방안

##### Console/VTY Timeout 설정
```bash
# Cisco IOS 설정
Router(config)# line console 0
Router(config-line)# exec-timeout 10 0  # 10분 0초
Router(config-line)# login local

Router(config)# line vty 0 4
Router(config-line)# exec-timeout 5 0   # 5분 0초
Router(config-line)# transport input ssh
```

##### 방화벽 웹 Timeout 설정
```bash
# FortiGate 설정
config system global
    set admin-idle-timeout 10
    set admin-login-max 5
end

# Palo Alto 설정
set deviceconfig system idle-timeout 10
set deviceconfig system login-banner "Authorized Users Only"

# SonicWall 설정
# Network > NAT Policies > Advanced > Session Inactivity Timeout: 600 seconds
```

#### 권장 Timeout 값
| 접속 방법 | 권장값 | 비고 |
|-----------|--------|------|
| **Console** | 10-15분 | 물리적 접근 필요 |
| **VTY (SSH)** | 5-10분 | 원격 접근 |
| **Web GUI** | 10-30분 | 작업 편의성 고려 |
| **API** | 1-5분 | 자동화 스크립트용 |

### 5. 패치 관리 - 최신 업데이트 적용 (S-8)

#### 취약점 설명
**많은 취약점들 중 어떤 취약점은 반드시 패치를 적용해야만** 장비의 안정성을 보장할 수 있기 때문에 심각한 버그에 대해서는 신속한 패치 적용을 고려해야 합니다.

- **위협 영향**: 패치 미적용으로 인한 취약점 노출

#### 패치 관리 프로세스
```mermaid
graph TD
    A[취약점 발표] --> B[영향 분석]
    B --> C[위험도 평가]
    C --> D{긴급도}
    
    D -->|높음| E[즉시 패치]
    D -->|중간| F[계획된 패치]
    D -->|낮음| G[정기 패치]
    
    E --> H[백업 생성]
    F --> H
    G --> H
    
    H --> I[테스트 환경 적용]
    I --> J[검증 완료]
    J --> K[운영 환경 적용]
    K --> L[적용 후 모니터링]
```

#### 점검 방법
```bash
# 1. 자동 업데이트 기능 확인
# 벤더사에 문의하여 현재 버전과 최신 버전 비교

# Cisco IOS 버전 확인
Router# show version
Router# show inventory
Router# show license

# 2. CVE 데이터베이스 확인
curl -s "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=cisco+ios"

# 3. 벤더 보안 공지 확인
# Cisco Security Advisories
# Juniper Security Advisories
# Fortinet Security Advisories
```

#### 조치 방안

##### 패치 관리 정책 수립
```bash
# 패치 관리 정책 예시

1. 위험도별 패치 일정
   - Critical: 24시간 내
   - High: 72시간 내
   - Medium: 1주일 내
   - Low: 정기 점검 시

2. 패치 적용 절차
   - 현재 설정 백업
   - 테스트 환경 검증
   - 변경 관리 승인
   - 운영 환경 적용
   - 적용 후 검증

3. 롤백 계획
   - 백업 설정 준비
   - 롤백 조건 정의
   - 롤백 절차 문서화
```

##### 자동 업데이트 설정
```bash
# FortiGate 자동 업데이트
config system fortiguard
    set update-server-location usa
    set antivirus-license-mobile-timeout 30
end

config system autoupdate schedule
    set status enable
    set frequency daily
    set time 02:00
end

# Palo Alto 자동 업데이트
set deviceconfig system update-schedule threats recurring daily at 02:00
set deviceconfig system update-schedule anti-virus recurring daily at 02:30
```

### 6. 로그 관리 - 보안장비 로그 설정 (S-18)

#### 취약점 설명
**로그 정보를 사용함으로써** 관리자는 보안장비의 작동과 손상 여부를 파악할 수 있습니다. 또한, 어떤 종류의 침입이나 공격이 진행되고 있는지 알 수도 있습니다.

- **위협 영향**: 보안사고의 징후가 발견되었을 때 원인 규명을 할 수 없음

#### 로그의 중요성
```mermaid
graph TD
    A[보안 이벤트] --> B[로그 생성]
    B --> C[로그 수집]
    C --> D[로그 분석]
    D --> E[위협 탐지]
    E --> F[대응 조치]
    
    G[공격 시도] --> H[접근 로그]
    I[정책 위반] --> J[차단 로그]
    K[시스템 오류] --> L[시스템 로그]
    
    H --> C
    J --> C
    L --> C
```

#### 로그 유형별 분류
| 로그 유형 | 설명 | 예시 |
|-----------|------|------|
| **Access Log** | 접근 시도 기록 | 로그인/로그아웃, 인증 실패 |
| **Traffic Log** | 트래픽 처리 기록 | 허용/차단된 통신 |
| **System Log** | 시스템 이벤트 | 서비스 시작/중단, 오류 |
| **Configuration Log** | 설정 변경 기록 | 정책 수정, 계정 변경 |
| **Security Log** | 보안 이벤트 | IPS 탐지, 멀웨어 차단 |

#### 조치 방안

##### 포괄적인 로그 설정
```bash
# Cisco IOS 로그 설정
Router(config)# logging on
Router(config)# logging buffered 32768
Router(config)# logging console warnings
Router(config)# logging monitor informational
Router(config)# logging trap notifications
Router(config)# logging facility local0
Router(config)# logging source-interface GigabitEthernet0/1
Router(config)# logging 192.168.1.100

# 상세 로그 활성화
Router(config)# logging discriminator DETAILED mnemonics drops SYS-5-CONFIG_I
Router(config)# logging buffered discriminator DETAILED
```

##### 방화벽 로그 설정
```bash
# FortiGate 로그 설정
config log syslogd setting
    set status enable
    set server "192.168.1.100"
    set mode udp
    set port 514
    set facility local0
    set source-ip 192.168.1.1
    set format default
end

config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic enable
    set sniffer-traffic enable
end
```

### 7. 로그 관리 - 로그 정기적 검토 (S-19)

#### 취약점 설명
**로깅에 관해 기억해야 할 사항 중 중요한 것은 로그를 정기적으로 조사해야 한다**는 것입니다. 로그를 정기적으로 검사함으로써, 해당 장비와 네트워크 상태의 동향을 파악할 수 있습니다. 정상적 운영상태 및 그 상태가 로그에 반영되어 있음을 확인함으로써 비정상적인 상태 또는 공격 상태를 식별할 수 있습니다.

- **위협 영향**: 공격, 방화벽 규칙의 문제 파악, 그리고 네트워크 상의 비정상적인 행동을 파악하여 사고를 방지할 수 없음

#### 로그 분석 프로세스
```mermaid
graph LR
    A[로그 수집] --> B[정규화]
    B --> C[상관관계 분석]
    C --> D[이상 탐지]
    D --> E[경고 생성]
    E --> F[대응 조치]
    
    G[자동화 도구] --> H[SIEM]
    H --> I[대시보드]
    I --> J[리포트]
```

#### 조치 방안

##### 자동화된 로그 분석
```bash
# ELK Stack 구성 예시
version: '3'
services:
  elasticsearch:
    image: elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
    ports:
      - "9200:9200"

  logstash:
    image: logstash:7.15.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: kibana:7.15.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
```

##### 로그 분석 스크립트
```bash
#!/bin/bash
# 보안장비 로그 일일 분석 스크립트

LOG_FILE="/var/log/security/firewall.log"
REPORT_FILE="/var/log/security/daily_report_$(date +%Y%m%d).txt"

echo "=== 보안장비 일일 로그 분석 보고서 ===" > $REPORT_FILE
echo "분석 일시: $(date)" >> $REPORT_FILE
echo >> $REPORT_FILE

# 1. 로그인 실패 횟수
echo "1. 로그인 실패 현황" >> $REPORT_FILE
grep "login failed" $LOG_FILE | wc -l >> $REPORT_FILE

# 2. 차단된 트래픽 Top 10
echo "2. 차단된 소스 IP Top 10" >> $REPORT_FILE
grep "DENY" $LOG_FILE | awk '{print $5}' | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE

# 3. 정책 변경 이력
echo "3. 정책 변경 이력" >> $REPORT_FILE
grep "config" $LOG_FILE | tail -10 >> $REPORT_FILE

# 4. 시스템 오류
echo "4. 시스템 오류" >> $REPORT_FILE
grep -i "error\|critical" $LOG_FILE | tail -5 >> $REPORT_FILE

# 이메일 발송
mail -s "보안장비 일일 분석 보고서" admin@company.com < $REPORT_FILE
```

### 8. 로그 관리 - 로그 보관 정책 (S-20)

#### 취약점 설명
**보안장비 로그를 법규 기준에 따라 보관하고**, 효율적이고 경제적으로 저장 관리하는 정책을 수립하지 않으면, 추후 필요한 용도에 따라 제출할 수 없게 됩니다.

- **위협 영향**: 보안사고 발생 시 원인 분석 및 원인을 찾을 수 없음

#### 로그 보관 정책 수립
```mermaid
graph TD
    A[로그 생성] --> B[실시간 저장]
    B --> C[일일 백업]
    C --> D[월별 아카이브]
    D --> E[연별 장기보관]
    
    F[법적 요구사항] --> G[최소 보관기간]
    H[업무 요구사항] --> I[분석 기간]
    J[저장 용량] --> K[압축/삭제 정책]
    
    G --> L[보관 정책 수립]
    I --> L
    K --> L
```

#### 조치 방안

##### 보관 정책 예시
```bash
# 로그 보관 정책 설정

1. 보관 기간 정의
   - 실시간 로그: 30일
   - 압축 보관: 1년
   - 장기 보관: 3년 (법적 요구사항)
   - 중요 사건: 5년

2. 저장 매체별 정책
   - SSD/HDD: 실시간~6개월
   - NAS/SAN: 6개월~2년
   - 테이프/클라우드: 2년 이상

3. 압축 및 삭제 정책
   - 30일 후 압축 (gzip)
   - 1년 후 아카이브
   - 3년 후 법적 검토 후 삭제
```

##### 자동화된 로그 로테이션
```bash
# logrotate 설정 (/etc/logrotate.d/security)
/var/log/security/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    create 644 syslog syslog
    postrotate
        /usr/bin/killall -HUP rsyslogd
    endscript
}

# 월별 아카이브 스크립트
#!/bin/bash
ARCHIVE_DIR="/backup/logs/monthly"
SOURCE_DIR="/var/log/security"
MONTH=$(date -d "last month" +%Y%m)

mkdir -p $ARCHIVE_DIR
tar -czf $ARCHIVE_DIR/security_logs_$MONTH.tar.gz $SOURCE_DIR/*.log.1
```

### 9. 로그 관리 - 정책 백업 설정 (S-21)

#### 취약점 설명
보안장비의 정책은 조직의 요구에 맞게 작성되어 운영되고 있습니다. 그러한 **정책들도 중요한 자산**이며, 분실 시 조직의 서비스 운영에 큰 차질이 생길 수 있습니다. 정책이 복잡하면 할수록, 새로 정책을 수립하는 데 시간과 경제적인 손실이 늘어나게 됩니다.

- **위협 영향**: 보안장비 장애 시, 정책 복구가 힘들어 정상적인 서비스 구현 안됨

#### 백업 전략
```mermaid
graph TD
    A[설정 변경] --> B[자동 백업 트리거]
    B --> C[로컬 백업]
    C --> D[원격 백업]
    D --> E[백업 검증]
    
    F[정기 백업] --> G[일일 백업]
    G --> H[주간 백업]
    H --> I[월간 백업]
    
    J[백업 저장소] --> K[FTP/SFTP]
    J --> L[클라우드]
    J --> M[네트워크 스토리지]
```

#### 조치 방안

##### Cisco 자동 백업 설정
```bash
# Cisco Archive 기능 설정
Router(config)# archive
Router(config-archive)# path ftp://backup:password@192.168.1.200/configs/router-$h-$t
Router(config-archive)# write-memory
Router(config-archive)# time-period 1440  # 24시간마다
Router(config-archive)# maximum 10

# 수동 백업 명령어
Router# copy running-config ftp://192.168.1.200/router-backup.cfg

# 백업 복원
Router# copy ftp://192.168.1.200/router-backup.cfg running-config
```

##### 스크립트 기반 백업
```bash
#!/bin/bash
# 보안장비 설정 자동 백업 스크립트

BACKUP_DIR="/backup/configs"
DATE=$(date +%Y%m%d_%H%M%S)
DEVICES_FILE="/etc/network_devices.txt"

mkdir -p $BACKUP_DIR/$DATE

# 장비별 백업 실행
while read device ip username password; do
    echo "Backing up $device ($ip)..."
    
    case $device in
        "cisco")
            expect -c "
                spawn ssh $username@$ip
                expect \"Password:\"
                send \"$password\r\"
                expect \"#\"
                send \"terminal length 0\r\"
                expect \"#\"
                send \"show running-config\r\"
                expect \"#\"
                send \"exit\r\"
            " > $BACKUP_DIR/$DATE/${device}_${ip}.cfg
            ;;
        "fortinet")
            curl -k -X POST "https://$ip/logincheck" \
                -d "username=$username&secretkey=$password" \
                -c /tmp/cookies.txt
            curl -k -X GET "https://$ip/api/v2/cmdb/system/global" \
                -b /tmp/cookies.txt > $BACKUP_DIR/$DATE/${device}_${ip}.json
            ;;
    esac
done < $DEVICES_FILE

# 백업 압축
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz $BACKUP_DIR/$DATE/

# 원격지 전송
scp $BACKUP_DIR/config_backup_$DATE.tar.gz backup-server:/backup/network/

# 30일 이전 백업 삭제
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### 10. 로그 관리 - 원격 로그 서버 사용 (S-22)

#### 취약점 설명
로그에는 장비의 이상이나 침입흔적이 남아 있을 수 있기 때문에 **별도의 로그 분석 시스템에서** 장비의 로그를 모으고 분석해야 합니다. Syslog 로깅을 활용하면 이런 기능을 사용할 수 있습니다. 일반적으로 각 장비의 로그를 개별적으로 저장하지 않고 **별도의 로그 서버로 한 곳에서 통합 관리**할 것을 권장합니다.

- **위협 영향**: 타인의 내부 침입으로 인해 로그가 분석 및 훼손될 우려가 있음

#### 중앙집중식 로그 관리 아키텍처
```mermaid
graph TD
    A[방화벽] --> E[로그 서버]
    B[라우터] --> E
    C[스위치] --> E
    D[IPS/IDS] --> E
    
    E --> F[로그 저장소]
    E --> G[SIEM 솔루션]
    E --> H[분석 도구]
    
    F --> I[단기 저장]
    F --> J[장기 보관]
    
    G --> K[실시간 분석]
    G --> L[경고 시스템]
    
    H --> M[리포팅]
    H --> N[대시보드]
```

#### 조치 방안

##### Syslog 서버 구축
```bash
# Ubuntu Syslog 서버 설정
sudo apt-get install rsyslog

# /etc/rsyslog.conf 설정
$ModLoad imudp
$UDPServerRun 514
$UDPServerAddress 0.0.0.0

# 네트워크 장비별 로그 분리
$template NetworkLog,"/var/log/network/%HOSTNAME%-%$YEAR%-%$MONTH%-%$DAY%.log"
:fromhost-ip, startswith, "192.168.1." ?NetworkLog
& stop

# 서비스 재시작
sudo systemctl restart rsyslog
sudo systemctl enable rsyslog
```

##### 보안장비 Syslog 설정
```bash
# Cisco Syslog 클라이언트 설정
Router(config)# logging 192.168.1.100
Router(config)# logging facility local0
Router(config)# logging trap informational
Router(config)# logging source-interface GigabitEthernet0/1

# FortiGate Syslog 설정
config log syslogd setting
    set status enable
    set server "192.168.1.100"
    set mode udp
    set port 514
    set facility local1
end

# Juniper Syslog 설정
set system syslog host 192.168.1.100 any any
set system syslog host 192.168.1.100 facility-override local2
```

##### 로그 서버 보안 강화
```bash
# 로그 서버 보안 설정

1. 접근 제어
   - iptables -A INPUT -p udp --dport 514 -s 192.168.1.0/24 -j ACCEPT
   - iptables -A INPUT -p udp --dport 514 -j DROP

2. 로그 무결성 보장
   - 디지털 서명 적용
   - 파일 권한 제한 (644)
   - 일반 사용자 접근 금지

3. 백업 및 이중화
   - RAID 구성
   - 실시간 복제
   - 정기 백업

4. 모니터링
   - 디스크 용량 감시
   - 로그 수신 상태 확인
   - 서비스 상태 모니터링
```

## 실습 예제

### 종합 보안 점검 스크립트
```bash
#!/bin/bash
# 네트워크 보안장비 종합 점검 스크립트

echo "=== 네트워크 보안장비 종합 점검 ===" 
echo "점검 일시: $(date)"
echo

# 환경 설정
DEVICE_IP="192.168.1.1"
LOG_FILE="/var/log/security_audit.log"

# 1. 로그인 보안 점검
echo "1. 로그인 보안 점검"
echo "==================="

# Brute Force 공격 테스트 (주의: 실제 환경에서는 사용 금지)
echo "□ 로그인 실패 제한 테스트"
for i in {1..5}; do
    sshpass -p "wrong_password" ssh -o ConnectTimeout=5 admin@$DEVICE_IP exit 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "  시도 $i: 실패"
    fi
done

# 2. 접근 통제 점검
echo "□ 원격 접근 통제 점검"
nmap -sS -p 22,23,80,443,161 $DEVICE_IP 2>/dev/null | grep "open"

# 3. 암호화 접속 점검
echo "□ 보안 프로토콜 사용 점검"
openssl s_client -connect $DEVICE_IP:443 -verify_return_error 2>/dev/null | head -20

# 4. Session Timeout 테스트
echo "□ Session Timeout 설정 확인"
timeout 300 ssh admin@$DEVICE_IP "sleep 600" 2>/dev/null
if [ $? -eq 124 ]; then
    echo "  ✓ Session Timeout 정상 작동"
else
    echo "  ✗ Session Timeout 미설정 또는 오작동"
fi

# 5. 로그 설정 확인
echo "□ 로그 설정 점검"
if ss -ln | grep -q ":514"; then
    echo "  ✓ Syslog 서버 실행 중"
else
    echo "  ✗ Syslog 서버 실행되지 않음"
fi

echo
echo "점검 완료. 상세 내용은 $LOG_FILE 참조"
```

### 로그 분석 대시보드
```python
#!/usr/bin/env python3
# 실시간 보안 로그 모니터링 대시보드

import re
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class SecurityLogMonitor:
    def __init__(self, log_file="/var/log/security.log"):
        self.log_file = log_file
        self.stats = defaultdict(int)
        self.alerts = []
        
    def parse_log_line(self, line):
        """로그 라인 파싱"""
        patterns = {
            'failed_login': r'authentication failure.*user=(\w+)',
            'blocked_ip': r'DROP.*SRC=(\d+\.\d+\.\d+\.\d+)',
            'policy_change': r'CONFIG.*changed by (\w+)',
            'system_error': r'ERROR.*(\w+)',
        }
        
        for event_type, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                return event_type, match.group(1)
        return None, None
        
    def analyze_logs(self):
        """로그 분석 및 통계 생성"""
        failed_logins = Counter()
        blocked_ips = Counter()
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    event_type, data = self.parse_log_line(line)
                    
                    if event_type == 'failed_login':
                        failed_logins[data] += 1
                        if failed_logins[data] > 5:
                            self.alerts.append(f"Multiple login failures: {data}")
                    
                    elif event_type == 'blocked_ip':
                        blocked_ips[data] += 1
                        if blocked_ips[data] > 100:
                            self.alerts.append(f"High traffic from: {data}")
                    
                    self.stats[event_type] += 1
                            
        except FileNotFoundError:
            print(f"로그 파일을 찾을 수 없습니다: {self.log_file}")
            
        return {
            'failed_logins': failed_logins.most_common(10),
            'blocked_ips': blocked_ips.most_common(10),
            'stats': dict(self.stats),
            'alerts': self.alerts[-10:]  # 최근 10개 알림
        }
    
    def generate_report(self):
        """보고서 생성"""
        results = self.analyze_logs()
        
        print("=" * 50)
        print(f"보안 로그 분석 보고서 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        print("\n📊 이벤트 통계:")
        for event, count in results['stats'].items():
            print(f"  {event}: {count}")
        
        print("\n🚨 최근 알림:")
        for alert in results['alerts']:
            print(f"  ⚠️  {alert}")
        
        print("\n🔒 로그인 실패 Top 10:")
        for user, count in results['failed_logins']:
            print(f"  {user}: {count}회")
        
        print("\n🛡️ 차단된 IP Top 10:")
        for ip, count in results['blocked_ips']:
            print(f"  {ip}: {count}회")

if __name__ == "__main__":
    monitor = SecurityLogMonitor()
    monitor.generate_report()
```

## 참고 자료

### 보안 표준 및 가이드라인
- **NIST SP 800-53**: Security and Privacy Controls for Federal Information Systems
- **ISO/IEC 27001**: Information Security Management Systems
- **CIS Controls**: Center for Internet Security Critical Security Controls
- **SANS Top 25**: Most Dangerous Software Errors

### 벤더별 보안 가이드
- **Cisco Security Configuration Guide**: https://www.cisco.com/c/en/us/support/docs/security/
- **Juniper Security Hardening Guide**: https://www.juniper.net/documentation/
- **Fortinet Security Best Practices**: https://docs.fortinet.com/
- **Palo Alto Best Practices**: https://docs.paloaltonetworks.com/

### 도구 및 솔루션
- **OSSEC**: Host-based Intrusion Detection System
- **Splunk**: Log Analysis and SIEM Platform  
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Graylog**: Centralized Log Management

## 마무리

이번 강의에서는 보안·네트워크 장비의 **접근 관리와 로그 관리**에 대한 핵심적인 취약점들을 학습했습니다. 이러한 설정들은 **일회성이 아닌 지속적인 관리**가 필요하며, 정기적인 점검과 개선이 이루어져야 합니다.

다음 강의에서는 **기능 관리**에 대한 취약점들, 즉 **정책 관리**, **NAT 설정**, **DMZ 설정**, **유해 트래픽 차단** 등에 대해 자세히 학습하겠습니다.

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*