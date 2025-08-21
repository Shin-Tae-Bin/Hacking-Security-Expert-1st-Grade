# 해킹보안전문가 1급 자격증 과정

## 📋 과정 개요

이 저장소는 **해킹보안전문가 1급 자격증** 취득을 위한 종합적인 학습 자료를 제공합니다. 실무 중심의 커리큘럼과 실습 코드를 통해 정보보안 전문가로서 필요한 핵심 역량을 체계적으로 학습할 수 있습니다.

## 🎯 학습 목표

- **정보보안 기초 이론** 및 **실무 응용 능력** 습득
- **해킹 기법 이해**를 통한 **보안 대응 역량** 강화
- **법적 규제**와 **윤리적 해킹** 원칙 이해
- **실습 프로젝트**를 통한 **실무 경험** 축적
- **해킹보안전문가 1급 자격증** 취득 준비

## 📚 교육과정 구성

### Core Curriculum (5개 필수 과목)

| 과목 | 강의 수 | 주요 내용 | 실습 코드 |
|------|---------|-----------|-----------|
| **[01. Fundamentals](./01_Fundamentals/)** | 5강 | 정보보안 기초, 취약점 분석, 위험 관리 | ✅ 포함 |
| **[02. Server Security](./02_Server_Security/)** | 5강 | 서버 보안, 시스템 해킹, 침입 탐지 | ✅ 포함 |
| **[03. Network Security](./03_Network_Security/)** | 6강 | 네트워크 보안, 방화벽, VPN, 무선 보안 | ✅ 포함 |
| **[04. Application Security](./04_Application_Security/)** | 6강 | 웹 보안, 데이터베이스 보안, 암호학 | ✅ 포함 |
| **[05. Information Security Management](./05_Information_Security_Management/)** | 5강 | 정보보안 관리, 개인정보보호법 | ✅ 포함 |

### 📊 학습 통계
- **총 강의 수**: 27강
- **총 실습 코드**: 100+ 파일
- **예상 학습 시간**: 120-150시간
- **실습 프로젝트**: 15개

## 🚀 빠른 시작

### 1. 환경 설정

```bash
git clone https://github.com/your-repo/hacking-security-expert-level1.git
cd hacking-security-expert-level1

# Python 환경 설정 (권장: Python 3.8+)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 필요한 패키지 설치
pip install -r requirements.txt
```

### 2. 학습 순서

#### 📚 **1단계: 기초 이론 (1-2주)**
- [01. Fundamentals](./01_Fundamentals/) → 정보보안 기초 개념 이해

#### 🖥️ **2단계: 시스템 보안 (2-3주)**
- [02. Server Security](./02_Server_Security/) → 서버 및 시스템 보안

#### 🌐 **3단계: 네트워크 보안 (3-4주)**
- [03. Network Security](./03_Network_Security/) → 네트워크 보안 및 인프라

#### 💻 **4단계: 애플리케이션 보안 (3-4주)**  
- [04. Application Security](./04_Application_Security/) → 웹/DB 보안 및 암호학

#### 📋 **5단계: 보안 관리 (2주)**
- [05. Information Security Management](./05_Information_Security_Management/) → 보안 관리 및 법적 요구사항

#### 🔬 **6단계: 실습 프로젝트 (2-3주)**
- [Lab Projects](./Lab_Projects.md) → 종합 실습 프로젝트 수행

## 📖 각 과목별 상세 내용

### 01. Fundamentals (정보보안 기초)
```
📁 01_Fundamentals/
├── 01_Introduction_to_Information_Security.md      # 정보보안 개요
├── 02_Threat_and_Vulnerability_Assessment.md      # 위협 및 취약점 평가
├── 03_Risk_Management.md                          # 위험 관리
├── 04_Security_Policies_and_Procedures.md         # 보안 정책 및 절차
└── 05_Incident_Response.md                        # 사고 대응
```

**주요 학습 내용:**
- 정보보안의 3요소 (CIA Triad)
- 위협 모델링 및 위험 평가 방법론
- 보안 정책 수립 및 관리
- 보안 사고 대응 체계

### 02. Server Security (서버 보안)
```
📁 02_Server_Security/
├── 06_Operating_System_Security.md                # 운영체제 보안
├── 07_Server_Hardening.md                        # 서버 강화
├── 08_Access_Control_and_Authentication.md        # 접근 제어 및 인증
├── 09_System_Monitoring_and_Logging.md           # 시스템 모니터링
└── 10_Intrusion_Detection_Systems.md             # 침입 탐지 시스템
```

**주요 학습 내용:**
- Windows/Linux 서버 보안 강화
- 사용자 계정 및 권한 관리
- 로그 분석 및 모니터링
- IDS/IPS 구축 및 운영

### 03. Network Security (네트워크 보안)
```
📁 03_Network_Security/
├── 11_Network_Security_Fundamentals.md           # 네트워크 보안 기초
├── 12_Firewall_and_IPS.md                       # 방화벽 및 IPS
├── 13_VPN_and_Remote_Access.md                  # VPN 및 원격 접근
├── 14_Wireless_Security.md                      # 무선 보안
├── 15_Network_Monitoring_and_Analysis.md        # 네트워크 모니터링
└── 16_Network_Attack_and_Defense.md             # 네트워크 공격과 방어
```

**주요 학습 내용:**
- TCP/IP 보안 및 네트워크 프로토콜
- 방화벽 정책 설정 및 관리
- VPN 구축 및 무선 보안
- 네트워크 패킷 분석

### 04. Application Security (애플리케이션 보안)
```
📁 04_Application_Security/
├── 17_Web_Application_Security.md               # 웹 애플리케이션 보안
├── 18_Database_Security.md                      # 데이터베이스 보안
├── 19_Secure_Coding_Practices.md               # 보안 코딩
├── 20_Cryptography_and_PKI.md                  # 암호학 및 PKI
├── 21_Mobile_Application_Security.md           # 모바일 앱 보안
└── 22_API_and_Cloud_Security.md                # API 및 클라우드 보안
```

**주요 학습 내용:**
- OWASP Top 10 취약점 분석
- SQL Injection, XSS 등 웹 공격 기법
- 암호화 알고리즘 및 PKI 구조
- 클라우드 보안 아키텍처

### 05. Information Security Management (정보보안 관리)
```
📁 05_Information_Security_Management/
├── 23_Information_Security_Concepts.md          # 정보보안 개념
├── 24_Personal_Data_Protection_1.md            # 개인정보보호 (1)
├── 25_Personal_Data_Protection_2.md            # 개인정보보호 (2)
├── 26_Personal_Data_Protection_3.md            # 개인정보보호 (3)
└── 27_Security_Governance_and_Compliance.md    # 보안 거버넌스
```

**주요 학습 내용:**
- 개인정보보호법 및 정보통신망법
- OECD 8원칙 및 국제 표준
- 정보주체의 권리 및 동의 관리
- 보안 거버넌스 체계

## 🛠️ 기술 스택

### 프로그래밍 언어
- **Python 3.8+**: 주요 실습 코드
- **Bash/PowerShell**: 시스템 관리 스크립트
- **SQL**: 데이터베이스 보안 실습
- **JavaScript**: 웹 보안 실습

### 보안 도구
- **Wireshark**: 네트워크 패킷 분석
- **Nmap**: 네트워크 스캐닝
- **Metasploit**: 침투 테스트
- **Burp Suite**: 웹 애플리케이션 테스트
- **OpenVAS**: 취약점 스캐너

### 가상화 환경
- **VMware/VirtualBox**: 실습 환경 구성
- **Docker**: 컨테이너 기반 실습
- **Kali Linux**: 보안 테스트 도구

## 📋 자격증 시험 정보

### 시험 개요
- **시험명**: 해킹보안전문가 1급
- **시험 방식**: CBT (Computer Based Test)
- **시험 시간**: 100분
- **문항 수**: 60문항 (객관식 4지선다)
- **합격 기준**: 60점 이상 (100점 만점)

### 출제 비중
| 영역 | 비중 | 문항 수 |
|------|------|---------|
| 정보보안 일반 | 20% | 12문항 |
| 시스템 보안 | 20% | 12문항 |
| 네트워크 보안 | 25% | 15문항 |
| 애플리케이션 보안 | 25% | 15문항 |
| 정보보안 관리 | 10% | 6문항 |

### 시험 준비 체크리스트
- [ ] 5개 필수 과목 완주 (27강)
- [ ] 실습 코드 직접 실행 및 이해
- [ ] Lab Projects 최소 10개 완료
- [ ] 모의고사 3회 이상 응시 (70점 이상)
- [ ] 최신 보안 동향 및 법령 변경사항 확인

## 🔗 추가 학습 자료

### 필수 참고 자료
- [Resources.md](./Resources.md) - 추가 학습 자료 및 도구
- [Lab_Projects.md](./Lab_Projects.md) - 실습 프로젝트 가이드
- [FAQ.md](./FAQ.md) - 자주 묻는 질문

### 유용한 링크
- 🏛️ [한국인터넷진흥원(KISA)](https://www.kisa.or.kr)
- 📜 [개인정보보호위원회](https://www.pipc.go.kr)
- 🌐 [OWASP Korea](https://owasp.org/www-chapter-korea/)
- 🛡️ [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🤝 기여 및 피드백

### 기여 방법
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 피드백
- 📧 이메일: [contact@example.com](mailto:contact@example.com)
- 🐛 버그 리포트: [Issues](https://github.com/your-repo/issues)
- 💡 기능 제안: [Discussions](https://github.com/your-repo/discussions)

## 📝 라이선스

이 프로젝트는 [MIT License](./LICENSE) 하에 배포됩니다.

## 👥 제작자

**해킹보안전문가 과정 개발팀**
- 정보보안 전문가 및 교육 전문가들이 공동 개발
- 실무 경험과 최신 보안 동향을 반영한 커리큘럼

---

## 🎓 수료 인증

과정을 완료하신 분들을 위한 수료 체크리스트:

### ✅ 학습 완료 체크리스트
- [ ] **01. Fundamentals** (5강) - 정보보안 기초
- [ ] **02. Server Security** (5강) - 서버 보안
- [ ] **03. Network Security** (6강) - 네트워크 보안  
- [ ] **04. Application Security** (6강) - 애플리케이션 보안
- [ ] **05. Information Security Management** (5강) - 정보보안 관리
- [ ] **Lab Projects** - 실습 프로젝트 10개 이상 완료
- [ ] **모의고사** - 3회 이상 응시 (평균 70점 이상)

### 🏆 수료 혜택
- 수료증 발급 (디지털 뱃지)
- LinkedIn 프로필 인증
- 해킹보안전문가 커뮤니티 가입 자격
- 지속적인 업데이트 자료 접근

---

**📞 문의사항이 있으시면 언제든 연락주세요!**

> "정보보안은 선택이 아닌 필수입니다. 체계적인 학습을 통해 전문가가 되어보세요!" 🛡️