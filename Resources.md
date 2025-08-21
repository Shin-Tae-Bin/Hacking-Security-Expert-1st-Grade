# 학습 자료 및 참고 리소스

## 📚 공식 자료 및 표준

### 국내 기관
| 기관 | 자료 | 설명 | 링크 |
|------|------|------|------|
| **한국인터넷진흥원(KISA)** | 인터넷 보안 가이드라인 | 국내 인터넷 보안 정책 및 가이드라인 | [kisa.or.kr](https://www.kisa.or.kr) |
| **개인정보보호위원회** | 개인정보보호 가이드라인 | 개인정보보호법 해석 및 적용 가이드 | [pipc.go.kr](https://www.pipc.go.kr) |
| **국가정보원** | 국가사이버안전관리체계 | 국가 차원의 사이버보안 체계 | [nis.go.kr](https://www.nis.go.kr) |
| **한국정보보호학회** | 학술 논문 및 연구 자료 | 정보보안 관련 최신 연구 동향 | [kiisc.or.kr](https://www.kiisc.or.kr) |

### 국제 표준 기관
| 기관 | 표준/프레임워크 | 설명 | 활용도 |
|------|-----------------|------|---------|
| **NIST** | Cybersecurity Framework | 미국 사이버보안 프레임워크 | ⭐⭐⭐⭐⭐ |
| **ISO/IEC** | 27001/27002 시리즈 | 정보보안 관리시스템 국제표준 | ⭐⭐⭐⭐⭐ |
| **OWASP** | Top 10, Testing Guide | 웹애플리케이션 보안 표준 | ⭐⭐⭐⭐⭐ |
| **SANS** | 보안 교육 및 인증 | 정보보안 교육 콘텐츠 | ⭐⭐⭐⭐ |
| **ENISA** | EU 사이버보안 가이드라인 | 유럽 사이버보안 정책 | ⭐⭐⭐ |

## 🔧 필수 보안 도구

### 취약점 분석 도구
```bash
# 네트워크 스캐닝
nmap -sS -sV -O target_ip              # 포트 스캔 및 OS 탐지
masscan -p1-65535 target_ip --rate=1000  # 고속 포트 스캔

# 취약점 스캐너
openvas-setup                          # OpenVAS 설정
nuclei -t vulnerabilities/ -u target   # Nuclei 템플릿 스캔
```

**추천 도구**:
- **Nessus**: 상용 취약점 스캐너 (개인용 무료)
- **OpenVAS**: 오픈소스 취약점 스캐너
- **Nuclei**: 빠른 취약점 탐지 도구
- **Nikto**: 웹서버 취약점 스캐너

### 네트워크 분석 도구
```bash
# 패킷 캡처 및 분석
tcpdump -i eth0 -w capture.pcap        # 패킷 캡처
wireshark capture.pcap                  # GUI 패킷 분석
tshark -r capture.pcap -T fields -e ip.src  # 명령줄 분석
```

**추천 도구**:
- **Wireshark**: GUI 패킷 분석기
- **TShark**: 명령줄 패킷 분석기  
- **tcpdump**: 경량 패킷 캡처 도구
- **NetworkMiner**: 네트워크 포렌식 도구

### 웹 애플리케이션 보안 도구
```bash
# 웹 애플리케이션 스캐닝
nikto -h target_url                     # 웹서버 취약점 스캔
sqlmap -u "target_url?id=1" --dbs      # SQL Injection 테스트
dirb target_url wordlist.txt           # 디렉터리 브루트포스
```

**추천 도구**:
- **Burp Suite**: 웹 애플리케이션 보안 테스트 플랫폼
- **OWASP ZAP**: 오픈소스 웹 애플리케이션 스캐너
- **SQLMap**: SQL Injection 자동화 도구
- **Gobuster**: 빠른 디렉터리/파일 브루트포스

### 시스템 보안 도구
```bash
# 시스템 강화 및 감사
lynis audit system                      # 시스템 보안 감사
chkrootkit                             # 루트킷 탐지
rkhunter --check                       # 루트킷 헌터
```

**추천 도구**:
- **Lynis**: 시스템 보안 감사 도구
- **OSSEC**: 호스트 기반 침입탐지시스템
- **Tripwire**: 파일 무결성 모니터링
- **ClamAV**: 오픈소스 안티바이러스

## 💻 개발 환경 및 IDE

### Python 보안 개발 환경
```bash
# 가상환경 설정
python -m venv security_env
source security_env/bin/activate  # Linux/Mac
security_env\Scripts\activate     # Windows

# 필수 패키지 설치
pip install -r requirements.txt
```

**requirements.txt**:
```
# 네트워크 보안
scapy==2.4.5
netaddr==0.8.0
python-nmap==0.7.1

# 웹 보안
requests==2.28.1
beautifulsoup4==4.11.1
selenium==4.5.0

# 암호화
cryptography==38.0.1
pycryptodome==3.15.0

# 데이터 분석
pandas==1.5.1
numpy==1.23.4
matplotlib==3.6.1

# 보안 도구
bandit==1.7.4
safety==2.3.1
```

### 권장 IDE 및 에디터
| 도구 | 용도 | 장점 | 라이선스 |
|------|------|------|----------|
| **PyCharm Professional** | Python 개발 | 강력한 디버깅, 보안 플러그인 지원 | 상용 (학생 무료) |
| **Visual Studio Code** | 다목적 개발 | 가벼움, 다양한 확장 프로그램 | 무료 |
| **Sublime Text** | 텍스트 편집 | 빠른 성능, 플러그인 생태계 | 상용 |
| **Vim/Neovim** | 터미널 편집 | 서버 환경 최적화 | 무료 |

### 보안 개발을 위한 VS Code 확장
```json
{
  "recommendations": [
    "ms-python.python",           // Python 지원
    "ms-vscode.vscode-json",      // JSON 지원  
    "ms-toolsai.jupyter",         // Jupyter 노트북
    "ms-python.bandit",           // Python 보안 분석
    "streetsidesoftware.code-spell-checker",  // 맞춤법 검사
    "ms-vscode.vscode-security",  // 보안 분석
    "github.copilot"              // AI 코딩 어시스턴트
  ]
}
```

## 🐧 실습 환경 구성

### Kali Linux 설정
```bash
# Kali Linux 업데이트
sudo apt update && sudo apt upgrade -y

# 추가 보안 도구 설치
sudo apt install -y \
    metasploit-framework \
    burpsuite \
    sqlmap \
    aircrack-ng \
    john \
    hashcat \
    hydra \
    gobuster

# Docker 설치 (취약한 애플리케이션 실습용)
sudo apt install -y docker.io
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

### DVWA (Damn Vulnerable Web Application) 설정
```bash
# Docker를 이용한 DVWA 실행
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# 브라우저에서 접속: http://localhost
# 기본 계정: admin/password
```

### Metasploitable 설정
```bash
# Metasploitable 2 다운로드 및 실행
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip

# VMware에서 실행
# 기본 계정: msfadmin/msfadmin
```

## 📖 필수 도서 및 학습 자료

### 한국어 도서
| 도서명 | 저자 | 출판사 | 난이도 | 추천도 |
|--------|------|--------|--------|--------|
| **정보보안 개론과 실습** | 양대일 | 한빛아카데미 | 초급 | ⭐⭐⭐⭐ |
| **해킹 보안 전문가가 되는 법** | 이재광 | 한빛미디어 | 중급 | ⭐⭐⭐⭐ |
| **실무자를 위한 정보보안 관리체계** | 장항배 | 에이콘 | 고급 | ⭐⭐⭐ |
| **개인정보보호법 실무해설** | 개인정보보호위원회 | 법문사 | 중급 | ⭐⭐⭐⭐ |

### 영문 도서 (필독)
| 도서명 | 저자 | 출판사 | 분야 | 추천도 |
|--------|------|--------|------|--------|
| **The Web Application Hacker's Handbook** | Stuttard & Pinto | Wiley | 웹 보안 | ⭐⭐⭐⭐⭐ |
| **Metasploit: The Penetration Tester's Guide** | Kennedy et al. | No Starch | 침투 테스트 | ⭐⭐⭐⭐ |
| **Applied Cryptography** | Bruce Schneier | Wiley | 암호학 | ⭐⭐⭐⭐⭐ |
| **Network Security Essentials** | William Stallings | Pearson | 네트워크 보안 | ⭐⭐⭐⭐ |
| **Computer Security: Art and Science** | Matt Bishop | Addison-Wesley | 일반 보안 | ⭐⭐⭐⭐ |

## 🎓 온라인 교육 플랫폼

### 무료 학습 플랫폼
| 플랫폼 | 제공 콘텐츠 | 특징 | 접근성 |
|--------|-------------|------|---------|
| **Cybrary** | 종합 사이버보안 교육 | 무료 기초 과정 제공 | ⭐⭐⭐⭐ |
| **SANS Cyber Aces** | 실습 중심 보안 교육 | 터미널 기반 실습 | ⭐⭐⭐ |
| **Professor Messer** | CompTIA Security+ | 무료 동영상 강의 | ⭐⭐⭐⭐ |
| **YouTube Security Channels** | 다양한 보안 채널 | 최신 보안 동향 | ⭐⭐⭐⭐⭐ |

### 유료 프리미엄 플랫폼
| 플랫폼 | 월 구독료 | 제공 혜택 | 추천 대상 |
|--------|-----------|-----------|-----------|
| **Cybrary Pro** | $49/월 | 고급 코스, 실습 랩 | 전문가 과정 |
| **Linux Academy** | $29/월 | 클라우드 보안 특화 | 클라우드 엔지니어 |
| **Pluralsight** | $35/월 | 기술 전반 교육 | 개발자 겸 보안 |
| **Cloud Guru** | $39/월 | 클라우드 보안 | 클라우드 보안 전문가 |

## 🏆 보안 인증 및 자격증

### 국내 자격증
| 자격증 | 주관 기관 | 난이도 | 응시료 | 유효기간 |
|--------|-----------|--------|--------|----------|
| **정보보안기사** | 한국산업인력공단 | 중급 | 19,400원 | 없음 |
| **정보처리보안사** | 한국데이터산업진흥원 | 고급 | 55,000원 | 3년 |
| **해킹보안전문가** | 한국정보통신진흥협회 | 중급 | 66,000원 | 2년 |
| **개인정보보호전문가** | 개인정보보호위원회 | 중급 | 무료 | 없음 |

### 국제 인증
| 인증 | 주관 기관 | 난이도 | 응시료 | 갱신 주기 |
|------|-----------|--------|--------|-----------|
| **CISSP** | (ISC)² | 고급 | $749 | 3년 |
| **CEH** | EC-Council | 중급 | $1,199 | 3년 |
| **OSCP** | Offensive Security | 고급 | $1,499 | 3년 |
| **CompTIA Security+** | CompTIA | 초급 | $370 | 3년 |
| **CISA** | ISACA | 고급 | $760 | 3년 |

## 🌐 보안 커뮤니티 및 포럼

### 한국 커뮤니티
| 커뮤니티 | 특징 | 활동 분야 | 참여 방법 |
|----------|------|-----------|-----------|
| **KISA 보안포털** | 공식 정부 플랫폼 | 정책, 가이드라인 | 웹사이트 |
| **하마이** | 해킹 마스터즈 | CTF, 해킹 기법 | 온라인 가입 |
| **코드게이트** | 국제 해킹 대회 | CTF, 경진대회 | 대회 참가 |
| **정보보호학회** | 학술 커뮤니티 | 연구, 논문 | 회원 가입 |

### 국제 커뮤니티
| 커뮤니티 | 언어 | 특징 | 활동 분야 |
|----------|------|------|-----------|
| **Reddit r/netsec** | 영어 | 활발한 토론 | 일반 보안 |
| **Stack Overflow Security** | 영어 | Q&A 플랫폼 | 기술 문제 해결 |
| **OWASP Local Chapters** | 다국어 | 지역별 모임 | 웹 보안 |
| **DEF CON Forums** | 영어 | 해커 컨퍼런스 | 해킹 기법 |

## 🔍 보안 뉴스 및 동향

### 한국 보안 뉴스
- **🗞️ 보안뉴스**: [boannews.com](https://www.boannews.com)
- **🗞️ 데일리시큐**: [dailysecu.com](https://www.dailysecu.com)
- **🗞️ 전자신문 보안**: [etnews.com](https://www.etnews.com)

### 국제 보안 뉴스
- **🌐 KrebsOnSecurity**: [krebsonsecurity.com](https://krebsonsecurity.com)
- **🌐 The Hacker News**: [thehackernews.com](https://thehackernews.com)
- **🌐 Bleeping Computer**: [bleepingcomputer.com](https://www.bleepingcomputer.com)
- **🌐 Dark Reading**: [darkreading.com](https://www.darkreading.com)

### 보안 동향 리포트
| 기관 | 보고서명 | 발행 주기 | 내용 |
|------|----------|-----------|------|
| **Verizon** | Data Breach Investigations Report | 연간 | 데이터 침해 동향 |
| **IBM** | Cost of a Data Breach Report | 연간 | 데이터 침해 비용 분석 |
| **OWASP** | Top 10 Application Security Risks | 3-4년 | 웹 보안 위협 순위 |
| **SANS** | Top 20 Critical Security Controls | 연간 | 필수 보안 통제 |

## 🏅 CTF (Capture The Flag) 플랫폼

### 상시 CTF 플랫폼
| 플랫폼 | 난이도 | 분야 | 특징 |
|--------|--------|------|------|
| **OverTheWire** | 초급~고급 | 리눅스, 웹, 암호 | 단계별 학습 |
| **HackTheBox** | 중급~고급 | 침투 테스트 | 실제 시스템 해킹 |
| **TryHackMe** | 초급~중급 | 종합 보안 | 가이드형 학습 |
| **PicoCTF** | 초급 | 종합 보안 | 교육 목적 |

### 정기 CTF 대회
```markdown
주요 CTF 대회 일정 (예시)
├── 3월: CODEGATE (한국)
├── 5월: DEF CON CTF Quals (미국)  
├── 8월: DEF CON CTF Finals (미국)
├── 10월: HITCON CTF (대만)
└── 12월: 35C3 CTF (독일)
```

## 📱 보안 관련 팟캐스트

### 한국어 팟캐스트
- **🎧 디지털 포렌식 이야기**: 디지털 포렌식 전문
- **🎧 보안 뉴스 팟캐스트**: 주간 보안 뉴스 요약

### 영어 팟캐스트
- **🎧 Security Now**: 전반적인 보안 동향
- **🎧 Darknet Diaries**: 사이버 범죄 사례
- **🎧 The CyberWire**: 일간 사이버보안 뉴스
- **🎧 Risky Business**: 주간 보안 뉴스

## 🔗 유용한 웹사이트 및 도구

### 온라인 보안 도구
| 도구 | 용도 | URL | 무료 여부 |
|------|------|-----|-----------|
| **VirusTotal** | 파일/URL 스캔 | virustotal.com | 무료 |
| **Shodan** | IoT 기기 검색 | shodan.io | 부분 무료 |
| **Have I Been Pwned** | 데이터 침해 확인 | haveibeenpwned.com | 무료 |
| **SSL Labs** | SSL/TLS 테스트 | ssllabs.com | 무료 |

### 취약점 데이터베이스
- **🗄️ CVE Details**: [cvedetails.com](https://www.cvedetails.com)
- **🗄️ NVD (NIST)**: [nvd.nist.gov](https://nvd.nist.gov)
- **🗄️ Exploit Database**: [exploit-db.com](https://www.exploit-db.com)

### 보안 연구 및 블로그
- **🔬 Google Project Zero**: [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com)
- **🔬 Microsoft Security Response**: [msrc-blog.microsoft.com](https://msrc-blog.microsoft.com)
- **🔬 Talos Intelligence**: [blog.talosintelligence.com](https://blog.talosintelligence.com)

## 💡 학습 팁 및 전략

### 효과적인 학습 방법
1. **🎯 목표 설정**: 구체적이고 측정 가능한 학습 목표
2. **📅 일정 관리**: 주간/월간 학습 계획 수립
3. **🔄 반복 학습**: 이론 → 실습 → 복습 사이클
4. **👥 동료 학습**: 스터디 그룹 및 멘토링 활용

### 실습 환경 구축 팁
```bash
# 가상머신 최적화 설정
VirtualBox/VMware 권장 사양:
- RAM: 8GB 이상 (호스트 16GB 권장)
- Storage: SSD 100GB 이상
- Network: NAT + Host-Only 조합

# 실습용 네트워크 구성
DMZ Network: 192.168.1.0/24
Internal Network: 10.0.0.0/24
Management Network: 172.16.0.0/24
```

### 취업 준비 전략
1. **포트폴리오 구축**: GitHub을 통한 프로젝트 공개
2. **인증 취득**: 업계 인정 보안 인증 획득
3. **네트워킹**: 보안 컨퍼런스 및 모임 참석
4. **지속적 학습**: 최신 보안 동향 지속 추적

---

## 📞 문의 및 지원

### 학습 지원
- 📧 **이메일**: security-course@example.com
- 💬 **디스코드**: [보안 학습 커뮤니티](https://discord.gg/security-learning)
- 📚 **위키**: [보안 학습 위키](https://wiki.example.com/security)

### 기술 지원
- 🐛 **버그 리포트**: [GitHub Issues](https://github.com/security-course/issues)
- 💡 **기능 제안**: [GitHub Discussions](https://github.com/security-course/discussions)
- ❓ **FAQ**: [자주 묻는 질문](./FAQ.md)

---

**🚀 지속적인 학습을 통해 보안 전문가로 성장해보세요!**

> "보안은 목적지가 아니라 여정입니다. 끊임없이 학습하고 발전해야 합니다." 🛡️