# 23강: 개인정보보호의 이해 (1)

## 개요
해킹보안전문가 1급 과정의 23강으로, 개인정보보호의 기본 개념을 다룹니다. 해킹의 역사와 발전 과정, 정보보호의 필요성, CIA 3요소를 중심으로 한 정보보안의 핵심 목표들을 학습합니다.

## 주요 학습 내용

### 1. 해킹의 역사와 발전

#### 해킹의 역사적 발전 과정

```python
#!/usr/bin/env python3
# 해킹 역사 타임라인 분석 시스템

from datetime import datetime, date
import json
from enum import Enum

class HackingEra(Enum):
    EARLY = "초기 (1960-1980)"
    NETWORK = "네트워크 (1980-2000)"
    MODERN = "현대 (2000-2010)"
    ADVANCED = "고도화 (2010-현재)"

class HackingHistoryAnalyzer:
    """해킹 역사 분석 시스템"""
    
    def __init__(self):
        self.historical_events = [
            {
                'year': 1960,
                'event': 'MIT에서 "해킹" 용어 최초 사용',
                'description': '전화 시스템 해킹, 컴퓨터 시스템 탐구',
                'significance': '해킹 문화의 시작',
                'era': HackingEra.EARLY,
                'impact': 'LOW'
            },
            {
                'year': 1968,
                'event': '더글라스 이글버트, 마우스 개발',
                'description': '컴퓨터 인터페이스 혁신',
                'significance': 'GUI 시대의 시작',
                'era': HackingEra.EARLY,
                'impact': 'HIGH'
            },
            {
                'year': 1969,
                'event': 'ARPAnet 개발 (미 국방부)',
                'description': '최초의 인터넷, Telnet 프로토콜',
                'significance': '네트워크 해킹의 기반 마련',
                'era': HackingEra.EARLY,
                'impact': 'HIGH'
            },
            {
                'year': 1971,
                'event': '레이 토밀슨, 최초의 이메일 (@기호 사용)',
                'description': '네트워크를 통한 메시지 전송',
                'significance': '이메일 해킹, 피싱의 전신',
                'era': HackingEra.EARLY,
                'impact': 'MEDIUM'
            },
            {
                'year': 1975,
                'event': '빌 게이츠, 폴 앨런 마이크로소프트 설립',
                'description': '개인용 컴퓨터 시대 개막',
                'significance': 'PC 보안 문제의 시작',
                'era': HackingEra.EARLY,
                'impact': 'HIGH'
            },
            {
                'year': 1981,
                'event': 'IBM PC 제작, 독일 카오스 컴퓨터 클럽 결성',
                'description': 'PC 대중화와 해커 그룹 조직화',
                'significance': '현재 어나니머스의 전신',
                'era': HackingEra.NETWORK,
                'impact': 'MEDIUM'
            },
            {
                'year': 1988,
                'event': '로버트 타판 모리스 웜 바이러스',
                'description': '미국 전역 ARPAnet 감염, 자기복제 웜',
                'significance': '최초의 대규모 사이버 공격',
                'era': HackingEra.NETWORK,
                'impact': 'HIGH'
            },
            {
                'year': 1988,
                'event': 'CERT (컴퓨터 비상 대응팀) 설립',
                'description': '카네기 멜론 대학, 사이버 보안 대응 조직',
                'significance': '체계적 사이버 보안 대응의 시작',
                'era': HackingEra.NETWORK,
                'impact': 'HIGH'
            },
            {
                'year': 2003,
                'event': '대한민국 대규모 웜 감염',
                'description': '1월 25일, 2일간 네트워크 마비',
                'significance': '국가 차원의 사이버 보안 인식 제고',
                'era': HackingEra.MODERN,
                'impact': 'HIGH'
            }
        ]
        
        # 현대의 주요 해킹 사건들 추가
        self.modern_events = [
            {
                'year': 2010,
                'event': 'Stuxnet 웜',
                'description': '이란 핵시설 공격, 국가 후원 사이버 공격',
                'significance': '사이버 전쟁의 시대 개막',
                'era': HackingEra.ADVANCED,
                'impact': 'HIGH'
            },
            {
                'year': 2017,
                'event': 'WannaCry 랜섬웨어',
                'description': '전 세계 30만 대 컴퓨터 감염',
                'significance': '랜섬웨어의 대중화',
                'era': HackingEra.ADVANCED,
                'impact': 'HIGH'
            },
            {
                'year': 2020,
                'event': 'SolarWinds 공격',
                'description': '공급망 공격으로 1.8만 조직 감염',
                'significance': '공급망 보안의 중요성 대두',
                'era': HackingEra.ADVANCED,
                'impact': 'HIGH'
            }
        ]
        
        self.all_events = self.historical_events + self.modern_events
    
    def display_timeline(self):
        """해킹 역사 타임라인 표시"""
        print("=== 해킹의 역사 타임라인 ===\n")
        
        # 연도순 정렬
        sorted_events = sorted(self.all_events, key=lambda x: x['year'])
        
        for event in sorted_events:
            print(f"📅 {event['year']}년: {event['event']}")
            print(f"   📋 {event['description']}")
            print(f"   💡 의의: {event['significance']}")
            print(f"   📊 영향도: {event['impact']}")
            print(f"   🎭 시대: {event['era'].value}")
            print()
    
    def analyze_evolution_patterns(self):
        """해킹 진화 패턴 분석"""
        print("=== 해킹 진화 패턴 분석 ===\n")
        
        # 시대별 분류
        era_events = {}
        for era in HackingEra:
            era_events[era] = [e for e in self.all_events if e['era'] == era]
        
        for era, events in era_events.items():
            if not events:
                continue
                
            print(f"🎯 {era.value}")
            print(f"   기간: {min(e['year'] for e in events)} - {max(e['year'] for e in events)}")
            print(f"   주요 특징:")
            
            if era == HackingEra.EARLY:
                characteristics = [
                    "호기심 중심의 해킹",
                    "기술적 탐구 목적",
                    "소규모 개인 차원",
                    "네트워크 기반 구축"
                ]
            elif era == HackingEra.NETWORK:
                characteristics = [
                    "네트워크 기반 공격 시작",
                    "조직화된 해커 그룹 등장",
                    "대규모 피해 발생",
                    "보안 대응 조직 설립"
                ]
            elif era == HackingEra.MODERN:
                characteristics = [
                    "상업적/범죄적 목적",
                    "국가 차원의 피해",
                    "보안 산업 발전",
                    "법적 제재 강화"
                ]
            else:  # ADVANCED
                characteristics = [
                    "국가 후원 공격",
                    "고도화된 APT 공격",
                    "공급망 공격",
                    "AI/ML 활용 공격"
                ]
            
            for char in characteristics:
                print(f"     • {char}")
            print()
    
    def create_threat_evolution_model(self):
        """위협 진화 모델 생성"""
        print("=== 위협 진화 모델 ===\n")
        
        evolution_model = {
            '동기의 변화': {
                '1960s-1980s': '호기심, 기술적 도전',
                '1990s-2000s': '명성, 해커 문화',
                '2000s-2010s': '금전적 이익, 사이버 범죄',
                '2010s-현재': '국가적 목적, 정치적 동기'
            },
            '공격 기법의 발전': {
                '초기': '물리적 접근, 전화 해킹',
                '네트워크 시대': '원격 침입, 웜/바이러스',
                '웹 시대': 'SQL 인젝션, XSS, 피싱',
                '현대': 'APT, 제로데이, 소셜 엔지니어링'
            },
            '대상의 확대': {
                '개인': '개별 컴퓨터, 개인 정보',
                '기업': '기업 시스템, 영업 기밀',
                '정부': '국가 기반시설, 정부 기밀',
                '사회': '선거, 여론, 사회 혼란'
            },
            '피해 규모': {
                '소규모': '개별 시스템 마비',
                '중규모': '기업/조직 업무 중단',
                '대규모': '국가 인프라 마비',
                '초대규모': '글로벌 공급망 영향'
            }
        }
        
        for category, stages in evolution_model.items():
            print(f"📈 {category}:")
            for stage, description in stages.items():
                print(f"   {stage}: {description}")
            print()
        
        return evolution_model
    
    def modern_threat_landscape(self):
        """현대 위협 환경 분석"""
        print("=== 현대 위협 환경 ===\n")
        
        modern_threats = {
            'APT (Advanced Persistent Threat)': {
                'description': '장기간에 걸친 지능적이고 지속적인 공격',
                'characteristics': [
                    '특정 대상을 겨냥한 맞춤형 공격',
                    '다단계 침투 과정',
                    '장기간 잠복',
                    '고도의 기술과 자원'
                ],
                'examples': ['Stuxnet', 'APT1', 'Lazarus Group']
            },
            'Ransomware': {
                'description': '데이터를 암호화하고 몸값을 요구하는 악성코드',
                'characteristics': [
                    '파일 암호화',
                    '비트코인 결제 요구',
                    '네트워크 전파',
                    '백업 시스템 공격'
                ],
                'examples': ['WannaCry', 'NotPetya', 'REvil']
            },
            'Supply Chain Attack': {
                'description': '소프트웨어 공급망을 통한 우회 공격',
                'characteristics': [
                    '신뢰할 수 있는 소프트웨어 감염',
                    '광범위한 피해',
                    '탐지 어려움',
                    '장기간 잠복'
                ],
                'examples': ['SolarWinds', 'Kaseya', 'CCleaner']
            },
            'IoT Botnet': {
                'description': 'IoT 기기를 감염시켜 구축한 봇넷',
                'characteristics': [
                    '대규모 DDoS 공격',
                    '기본 암호 악용',
                    '업데이트 어려움',
                    '탐지 및 제거 곤란'
                ],
                'examples': ['Mirai', 'Reaper', 'VPNFilter']
            }
        }
        
        for threat_name, info in modern_threats.items():
            print(f"🎯 {threat_name}")
            print(f"   정의: {info['description']}")
            print(f"   특징:")
            for char in info['characteristics']:
                print(f"     • {char}")
            print(f"   주요 사례: {', '.join(info['examples'])}")
            print()

# 해킹 시뮬레이션 시스템
class EthicalHackingSimulator:
    """윤리적 해킹 교육 시뮬레이터"""
    
    def __init__(self):
        self.vulnerability_types = {
            'SQL Injection': {
                'description': 'SQL 쿼리에 악의적 코드 삽입',
                'risk_level': 'HIGH',
                'common_targets': ['웹 애플리케이션', '데이터베이스']
            },
            'XSS (Cross-Site Scripting)': {
                'description': '웹 페이지에 악성 스크립트 삽입',
                'risk_level': 'MEDIUM',
                'common_targets': ['웹 브라우저', '웹 애플리케이션']
            },
            'Buffer Overflow': {
                'description': '메모리 버퍼 경계 초과로 인한 취약점',
                'risk_level': 'HIGH',
                'common_targets': ['네이티브 애플리케이션', '시스템 소프트웨어']
            },
            'Phishing': {
                'description': '사회공학 기법을 통한 정보 탈취',
                'risk_level': 'HIGH',
                'common_targets': ['사용자 크리덴셜', '개인정보']
            }
        }
    
    def simulate_vulnerability_assessment(self, target_system):
        """취약점 평가 시뮬레이션"""
        print(f"=== {target_system} 취약점 평가 시뮬레이션 ===\n")
        
        import random
        
        # 시뮬레이션된 취약점 발견
        found_vulnerabilities = []
        
        for vuln_name, vuln_info in self.vulnerability_types.items():
            # 랜덤하게 취약점 발견 (실제 스캔 시뮬레이션)
            if random.random() > 0.5:  # 50% 확률로 취약점 발견
                severity_score = random.randint(1, 10)
                found_vulnerabilities.append({
                    'name': vuln_name,
                    'info': vuln_info,
                    'severity': severity_score,
                    'status': 'DETECTED'
                })
        
        # 결과 출력
        if found_vulnerabilities:
            print("🔍 발견된 취약점:")
            for vuln in sorted(found_vulnerabilities, key=lambda x: x['severity'], reverse=True):
                print(f"   • {vuln['name']} (심각도: {vuln['severity']}/10)")
                print(f"     설명: {vuln['info']['description']}")
                print(f"     위험도: {vuln['info']['risk_level']}")
                print(f"     대상: {', '.join(vuln['info']['common_targets'])}")
                print()
        else:
            print("✅ 현재 스캔에서 주요 취약점이 발견되지 않았습니다.")
        
        return found_vulnerabilities
    
    def generate_security_recommendations(self, vulnerabilities):
        """보안 권장사항 생성"""
        if not vulnerabilities:
            print("현재 시스템이 안전한 상태입니다. 정기적인 보안 점검을 권장합니다.")
            return
        
        print("=== 보안 강화 권장사항 ===\n")
        
        recommendations = {
            'SQL Injection': [
                'Prepared Statement 사용',
                '입력값 검증 및 이스케이프 처리',
                '최소 권한 원칙 적용',
                '정기적인 보안 코드 리뷰'
            ],
            'XSS (Cross-Site Scripting)': [
                '출력값 인코딩',
                'Content Security Policy (CSP) 적용',
                '입력값 검증',
                'HttpOnly 쿠키 사용'
            ],
            'Buffer Overflow': [
                '안전한 함수 사용 (strncpy vs strcpy)',
                '스택 보호 기능 활성화',
                '주소 공간 배치 무작위화 (ASLR)',
                '정적 분석 도구 활용'
            ],
            'Phishing': [
                '사용자 보안 교육',
                '이메일 필터링 시스템',
                '2단계 인증 도입',
                'URL 검증 도구 사용'
            ]
        }
        
        for vuln in vulnerabilities:
            vuln_name = vuln['name']
            if vuln_name in recommendations:
                print(f"🔧 {vuln_name} 대응 방안:")
                for rec in recommendations[vuln_name]:
                    print(f"   • {rec}")
                print()
    
    def ethical_hacking_principles(self):
        """윤리적 해킹 원칙"""
        print("=== 윤리적 해킹 (Ethical Hacking) 원칙 ===\n")
        
        principles = {
            '합법성 (Legality)': [
                '명시적 사전 승인 필요',
                '관련 법률 및 규정 준수',
                '계약서 및 NDA 체결',
                '승인된 범위 내에서만 활동'
            ],
            '기밀성 (Confidentiality)': [
                '발견한 취약점 정보 보호',
                '고객 정보 및 시스템 정보 보안',
                '적절한 보고서 작성',
                '정보 공개 금지'
            ],
            '무해성 (Non-malicious)': [
                '시스템 손상 방지',
                '서비스 중단 최소화',
                '데이터 무결성 보장',
                '백업 및 복구 계획 수립'
            ],
            '전문성 (Professionalism)': [
                '지속적인 기술 업데이트',
                '표준 방법론 준수',
                '정확한 문서화',
                '건설적인 개선 방안 제시'
            ]
        }
        
        for principle, guidelines in principles.items():
            print(f"📋 {principle}:")
            for guideline in guidelines:
                print(f"   • {guideline}")
            print()
        
        print("⚠️  중요: 윤리적 해킹은 시스템 보안 향상이 목적이며,")
        print("          악의적 목적의 해킹과는 엄격히 구분됩니다.")

# 실행 예시
def demo_hacking_history():
    print("🕰️  해킹의 역사와 현대 정보보안")
    print("=" * 50)
    
    # 해킹 역사 분석
    analyzer = HackingHistoryAnalyzer()
    analyzer.display_timeline()
    analyzer.analyze_evolution_patterns()
    analyzer.create_threat_evolution_model()
    analyzer.modern_threat_landscape()
    
    # 윤리적 해킹 시뮬레이션
    print("\n" + "=" * 50)
    simulator = EthicalHackingSimulator()
    
    # 가상 시스템 취약점 평가
    vulnerabilities = simulator.simulate_vulnerability_assessment("웹 애플리케이션 서버")
    simulator.generate_security_recommendations(vulnerabilities)
    simulator.ethical_hacking_principles()

if __name__ == "__main__":
    demo_hacking_history()
```

### 2. 정보보호의 필요성과 목적

#### 대국민 측면의 정보보호 필요성

```python
#!/usr/bin/env python3
# 개인정보보호 필요성 분석 시스템

import json
import random
from datetime import datetime, timedelta
from collections import defaultdict

class PersonalDataProtectionAnalyzer:
    """개인정보보호 필요성 분석 시스템"""
    
    def __init__(self):
        self.privacy_threats = {
            '프라이버시 침해': {
                'causes': ['바이러스', '스파이웨어', '사회공학적 해킹', '이메일 해킹'],
                'impacts': [
                    '개인정보 무단 수집',
                    '사생활 노출',
                    '개인 행동 패턴 분석',
                    '타겟 광고 남용'
                ],
                'financial_loss': '간접적',
                'severity': 'MEDIUM'
            },
            '2차 범죄 악용': {
                'causes': ['개인정보 유출', '신원도용', '금융정보 탈취'],
                'impacts': [
                    '금융 사기',
                    '신용카드 도용',
                    '대출 사기',
                    '명의 도용'
                ],
                'financial_loss': '직접적',
                'severity': 'HIGH'
            },
            '사이버 괴롭힘': {
                'causes': ['SNS 해킹', '개인정보 악용', '딥페이크'],
                'impacts': [
                    '명예훼손',
                    '정신적 피해',
                    '사회적 고립',
                    '온라인 스토킹'
                ],
                'financial_loss': '간접적',
                'severity': 'HIGH'
            }
        }
        
        # 연도별 개인정보 침해 상담 건수 (시뮬레이션 데이터)
        self.privacy_incidents_by_year = {
            2018: 32000,
            2019: 35000,
            2020: 45000,  # 코로나로 인한 디지털 활동 증가
            2021: 52000,
            2022: 48000,
            2023: 55000,
            2024: 60000   # 예상치
        }
    
    def analyze_personal_impact(self):
        """개인 차원의 영향 분석"""
        print("=== 개인 차원의 정보보호 필요성 ===\n")
        
        print("📊 연도별 개인정보 침해 상담건수 (출처: 방통위)")
        print(f"{'연도':<8} {'상담건수':<12} {'전년 대비':<12}")
        print("-" * 35)
        
        prev_count = None
        for year, count in self.privacy_incidents_by_year.items():
            if prev_count:
                change = ((count - prev_count) / prev_count) * 100
                change_str = f"{change:+.1f}%"
            else:
                change_str = "기준년도"
            
            print(f"{year:<8} {count:<12,} {change_str:<12}")
            prev_count = count
        
        print(f"\n주요 개인 피해 유형:")
        for threat_type, details in self.privacy_threats.items():
            print(f"\n🎯 {threat_type}")
            print(f"   원인: {', '.join(details['causes'])}")
            print(f"   피해: {', '.join(details['impacts'])}")
            print(f"   재정적 손실: {details['financial_loss']}")
            print(f"   심각도: {details['severity']}")
    
    def calculate_personal_risk_score(self, user_profile):
        """개인 위험도 점수 계산"""
        risk_factors = {
            'age': {
                '10-20': 0.8,    # 높은 온라인 활동
                '21-40': 1.0,    # 최고 위험군
                '41-60': 0.7,    # 중간 위험
                '60+': 0.5       # 낮은 온라인 활동
            },
            'online_activity_level': {
                'low': 0.3,
                'medium': 0.6,
                'high': 1.0
            },
            'financial_activity': {
                'none': 0.2,
                'basic': 0.5,    # 기본적인 온라인 뱅킹
                'extensive': 1.0  # 투자, 대출 등 복합 활동
            },
            'social_media_usage': {
                'none': 0.1,
                'limited': 0.4,
                'active': 0.7,
                'extensive': 1.0
            },
            'security_awareness': {
                'low': 1.0,
                'medium': 0.6,
                'high': 0.3
            }
        }
        
        total_score = 0
        max_score = 0
        
        for factor, value in user_profile.items():
            if factor in risk_factors:
                factor_score = risk_factors[factor].get(value, 0.5)
                total_score += factor_score
                max_score += 1.0
        
        # 0-100 점수로 변환
        risk_score = (total_score / max_score) * 100 if max_score > 0 else 50
        
        return risk_score
    
    def generate_personal_protection_plan(self, user_profile):
        """개인 맞춤형 보호 계획"""
        risk_score = self.calculate_personal_risk_score(user_profile)
        
        print(f"=== 개인 맞춤형 정보보호 계획 ===\n")
        print(f"위험도 점수: {risk_score:.1f}/100")
        
        if risk_score >= 80:
            risk_level = "매우 높음"
            recommendations = [
                "강력한 비밀번호 관리자 사용",
                "2단계 인증을 모든 서비스에 적용",
                "정기적인 신용정보 모니터링",
                "VPN 사용 고려",
                "개인정보 노출 최소화",
                "보안 교육 이수"
            ]
        elif risk_score >= 60:
            risk_level = "높음"
            recommendations = [
                "비밀번호 복잡성 강화",
                "주요 서비스에 2단계 인증 적용",
                "정기적인 개인정보 이용내역 확인",
                "의심스러운 이메일 주의",
                "소프트웨어 업데이트 자동화"
            ]
        elif risk_score >= 40:
            risk_level = "보통"
            recommendations = [
                "기본적인 보안 수칙 준수",
                "비밀번호 정기 변경",
                "안티바이러스 소프트웨어 사용",
                "공공 WiFi 사용 시 주의"
            ]
        else:
            risk_level = "낮음"
            recommendations = [
                "현재 보안 수준 유지",
                "정기적인 보안 점검",
                "새로운 위협에 대한 관심"
            ]
        
        print(f"위험 수준: {risk_level}")
        print(f"\n권장사항:")
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
        return risk_score, recommendations

class BusinessDataProtectionAnalyzer:
    """기업 정보보호 필요성 분석 시스템"""
    
    def __init__(self):
        self.business_threats = {
            '자산 손실': {
                'causes': ['기업 핵심 정보 변조', '정보 유출', '지적재산권 침해'],
                'impacts': [
                    '경쟁력 약화',
                    '기업 가치 하락',
                    '복구 비용 증가',
                    '법적 책임'
                ],
                'avg_cost': 500000  # 평균 50만 달러
            },
            '영업 손실': {
                'causes': ['신제품 정보 유출', '핵심 기술 유출', '고객 정보 유출'],
                'impacts': [
                    '경쟁사 이익 제공',
                    '신제품 출시 지연',
                    '시장 점유율 하락',
                    'R&D 투자 손실'
                ],
                'avg_cost': 1000000  # 평균 100만 달러
            },
            '기업 이미지 손상': {
                'causes': ['고객정보 유출', '기업정보 유출', '보안 사고 공개'],
                'impacts': [
                    '충성고객 이탈',
                    '브랜드 신뢰도 하락',
                    '신규 고객 확보 어려움',
                    '주가 하락'
                ],
                'avg_cost': 2000000  # 평균 200만 달러
            }
        }
        
        # 산업별 위험도
        self.industry_risk_levels = {
            '금융': {'risk_multiplier': 1.5, 'regulation_level': 'HIGH'},
            '의료': {'risk_multiplier': 1.4, 'regulation_level': 'HIGH'},
            '정부': {'risk_multiplier': 1.3, 'regulation_level': 'HIGH'},
            '교육': {'risk_multiplier': 1.1, 'regulation_level': 'MEDIUM'},
            '제조': {'risk_multiplier': 1.2, 'regulation_level': 'MEDIUM'},
            '통신': {'risk_multiplier': 1.3, 'regulation_level': 'HIGH'},
            '유통': {'risk_multiplier': 1.0, 'regulation_level': 'MEDIUM'}
        }
    
    def analyze_business_impact(self):
        """기업 차원의 영향 분석"""
        print("=== 기업 측면의 정보보호 필요성 ===\n")
        
        total_cost = 0
        
        for threat_type, details in self.business_threats.items():
            print(f"💼 {threat_type}")
            print(f"   원인: {', '.join(details['causes'])}")
            print(f"   영향: {', '.join(details['impacts'])}")
            print(f"   평균 피해액: ${details['avg_cost']:,}")
            total_cost += details['avg_cost']
            print()
        
        print(f"기업 정보보안 사고 시 총 평균 피해액: ${total_cost:,}")
        
        # 산업별 위험도
        print(f"\n산업별 위험 수준:")
        print(f"{'산업':<8} {'위험도':<8} {'규제 수준':<12} {'예상 피해액':<15}")
        print("-" * 45)
        
        for industry, risk_data in self.industry_risk_levels.items():
            multiplier = risk_data['risk_multiplier']
            regulation = risk_data['regulation_level']
            estimated_cost = int(total_cost * multiplier)
            
            print(f"{industry:<8} {multiplier:.1f}x{'':<3} {regulation:<12} ${estimated_cost:<14,}")
    
    def calculate_security_roi(self, company_profile):
        """기업 보안 투자 ROI 계산"""
        print(f"\n=== 기업 보안 투자 ROI 분석 ===\n")
        
        # 회사 규모별 기본 위험도
        size_multipliers = {
            'startup': 0.5,
            'small': 0.7,
            'medium': 1.0,
            'large': 1.3,
            'enterprise': 1.5
        }
        
        industry = company_profile.get('industry', '제조')
        size = company_profile.get('size', 'medium')
        revenue = company_profile.get('annual_revenue', 10000000)  # 1000만 달러 기본
        
        # 위험도 계산
        industry_multiplier = self.industry_risk_levels.get(industry, {'risk_multiplier': 1.0})['risk_multiplier']
        size_multiplier = size_multipliers.get(size, 1.0)
        
        # 예상 연간 보안 사고 비용
        base_threat_cost = sum(threat['avg_cost'] for threat in self.business_threats.values())
        annual_threat_cost = base_threat_cost * industry_multiplier * size_multiplier
        
        # 보안 투자 시나리오
        investment_scenarios = {
            '기본 보안': {
                'investment_ratio': 0.02,  # 매출의 2%
                'risk_reduction': 0.4      # 40% 위험 감소
            },
            '강화 보안': {
                'investment_ratio': 0.05,  # 매출의 5%
                'risk_reduction': 0.7      # 70% 위험 감소
            },
            '최고급 보안': {
                'investment_ratio': 0.10,  # 매출의 10%
                'risk_reduction': 0.9      # 90% 위험 감소
            }
        }
        
        print(f"회사 정보:")
        print(f"  산업: {industry}")
        print(f"  규모: {size}")
        print(f"  연매출: ${revenue:,}")
        print(f"  예상 연간 보안 위협 비용: ${annual_threat_cost:,}")
        print()
        
        print(f"{'투자 시나리오':<12} {'투자액':<15} {'위험감소':<10} {'절약액':<15} {'ROI':<10}")
        print("-" * 65)
        
        for scenario, data in investment_scenarios.items():
            investment = revenue * data['investment_ratio']
            risk_reduction = data['risk_reduction']
            cost_savings = annual_threat_cost * risk_reduction
            roi = ((cost_savings - investment) / investment) * 100 if investment > 0 else 0
            
            print(f"{scenario:<12} ${investment:<14,.0f} {risk_reduction*100:<9.0f}% ${cost_savings:<14,.0f} {roi:<9.1f}%")
        
        return investment_scenarios
    
    def generate_compliance_requirements(self, industry):
        """산업별 규제 준수 요구사항"""
        compliance_by_industry = {
            '금융': [
                'PCI DSS (카드 데이터 보안)',
                'SOX (사베인즈-옥슬리법)',
                'FFIEC 사이버보안 가이드라인',
                '금융개인정보보호법'
            ],
            '의료': [
                'HIPAA (건강정보 프라이버시법)',
                'FDA 의료기기 사이버보안',
                '개인정보보호법',
                '의료법'
            ],
            '정부': [
                'FISMA (연방정보보안관리법)',
                'NIST 사이버보안 프레임워크',
                '정보보안 기본법',
                '개인정보보호법'
            ],
            '교육': [
                'FERPA (교육기록 프라이버시법)',
                '개인정보보호법',
                '정보통신망법'
            ],
            '일반': [
                'GDPR (유럽 개인정보보호법)',
                '개인정보보호법',
                '정보통신망법',
                'ISO 27001'
            ]
        }
        
        requirements = compliance_by_industry.get(industry, compliance_by_industry['일반'])
        
        print(f"\n=== {industry} 산업 규제 준수 요구사항 ===")
        for i, req in enumerate(requirements, 1):
            print(f"{i}. {req}")
        
        return requirements

# 종합 분석 시스템
class ComprehensiveProtectionAnalyzer:
    """종합 정보보호 필요성 분석"""
    
    def __init__(self):
        self.personal_analyzer = PersonalDataProtectionAnalyzer()
        self.business_analyzer = BusinessDataProtectionAnalyzer()
    
    def comprehensive_analysis(self):
        """종합 분석 수행"""
        print("🛡️  정보보호의 필요성 - 종합 분석")
        print("=" * 60)
        
        # 개인 차원 분석
        self.personal_analyzer.analyze_personal_impact()
        
        # 샘플 사용자 프로필
        sample_user = {
            'age': '21-40',
            'online_activity_level': 'high',
            'financial_activity': 'extensive',
            'social_media_usage': 'active',
            'security_awareness': 'medium'
        }
        
        print(f"\n=== 샘플 사용자 위험도 분석 ===")
        self.personal_analyzer.generate_personal_protection_plan(sample_user)
        
        print(f"\n" + "=" * 60)
        
        # 기업 차원 분석
        self.business_analyzer.analyze_business_impact()
        
        # 샘플 기업 프로필
        sample_company = {
            'industry': '금융',
            'size': 'large',
            'annual_revenue': 100000000  # 1억 달러
        }
        
        self.business_analyzer.calculate_security_roi(sample_company)
        self.business_analyzer.generate_compliance_requirements('금융')
        
        # 사회적 영향
        self.analyze_social_impact()
    
    def analyze_social_impact(self):
        """사회적 영향 분석"""
        print(f"\n=== 사회적 차원의 정보보호 필요성 ===\n")
        
        social_impacts = {
            '경제적 영향': [
                '디지털 경제의 신뢰성 확보',
                '사이버 범죄로 인한 경제적 손실 방지',
                'IT 산업 경쟁력 강화',
                '국가 경쟁력 제고'
            ],
            '사회적 영향': [
                '디지털 사회의 안전성 확보',
                '개인의 프라이버시 권리 보장',
                '사회적 신뢰 구축',
                '디지털 격차 해소'
            ],
            '국가적 영향': [
                '국가 기반시설 보호',
                '국가 기밀 보안',
                '사이버 주권 확립',
                '국제 협력 기반 마련'
            ]
        }
        
        for impact_type, effects in social_impacts.items():
            print(f"🌍 {impact_type}:")
            for effect in effects:
                print(f"   • {effect}")
            print()
    
    def future_challenges(self):
        """미래 도전과제"""
        print(f"=== 미래 정보보호 도전과제 ===\n")
        
        challenges = [
            "AI/ML을 활용한 고도화된 사이버 공격",
            "IoT 기기 급증에 따른 공격 표면 확대",
            "양자컴퓨터 위협에 대한 암호화 기술 대응",
            "클라우드/메타버스 환경의 새로운 보안 위협",
            "국경을 초월하는 사이버 범죄에 대한 국제 협력",
            "개인정보보호와 혁신 기술 간의 균형",
            "사이버보안 전문가 인력 부족",
            "급변하는 기술 환경에 대한 법제도 정비"
        ]
        
        for i, challenge in enumerate(challenges, 1):
            print(f"{i}. {challenge}")
        
        print(f"\n결론: 정보보호는 개인, 기업, 사회 모든 차원에서")
        print(f"      지속적이고 적극적인 대응이 필요한 시대적 과제입니다.")

# 실행 예시
def main():
    analyzer = ComprehensiveProtectionAnalyzer()
    analyzer.comprehensive_analysis()
    analyzer.future_challenges()

if __name__ == "__main__":
    main()
```

### 3. 정보보호의 3대 목표와 추가 요소

#### CIA Triad와 확장 요소들

```python
#!/usr/bin/env python3
# 정보보안 목표 구현 시스템

import hashlib
import hmac
import time
import random
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import json

class SecurityTriadImplementation:
    """정보보안 3요소 (CIA Triad) 구현"""
    
    def __init__(self):
        self.confidentiality_system = ConfidentialityManager()
        self.integrity_system = IntegrityManager()
        self.availability_system = AvailabilityManager()
        
        # 확장 보안 요소
        self.authentication_system = AuthenticationManager()
        self.authorization_system = AuthorizationManager()
        self.non_repudiation_system = NonRepudiationManager()
    
    def demonstrate_security_balance(self):
        """보안 3요소의 균형 시연"""
        print("=== 정보보안 3요소의 균형 ===\n")
        
        scenarios = [
            {
                'name': '높은 기밀성 중심 시나리오',
                'confidentiality': 95,
                'integrity': 80,
                'availability': 60,
                'description': '군사, 국가기밀',
                'trade_offs': '접근성 제한으로 가용성 저하'
            },
            {
                'name': '높은 가용성 중심 시나리오',
                'confidentiality': 60,
                'integrity': 85,
                'availability': 99,
                'description': '긴급 의료시스템, 911',
                'trade_offs': '빠른 접근을 위해 인증 절차 단순화'
            },
            {
                'name': '높은 무결성 중심 시나리오',
                'confidentiality': 70,
                'integrity': 99,
                'availability': 80,
                'description': '금융 거래, 블록체인',
                'trade_offs': '검증 과정으로 처리 속도 저하'
            },
            {
                'name': '균형잡힌 시나리오',
                'confidentiality': 85,
                'integrity': 85,
                'availability': 85,
                'description': '일반 기업 시스템',
                'trade_offs': '모든 요소의 적절한 수준 유지'
            }
        ]
        
        print(f"{'시나리오':<20} {'기밀성':<8} {'무결성':<8} {'가용성':<8} {'특성':<15}")
        print("-" * 70)
        
        for scenario in scenarios:
            print(f"{scenario['name']:<20} {scenario['confidentiality']:<8} "
                  f"{scenario['integrity']:<8} {scenario['availability']:<8} "
                  f"{scenario['description']:<15}")
            print(f"{'  └ Trade-off:':<20} {scenario['trade_offs']}")
            print()
        
        # 균형의 중요성
        print("보안 3요소 균형의 중요성:")
        print("• 어느 하나라도 미흡하면 전체 보안 수준 저하")
        print("• 비즈니스 요구사항에 따른 적절한 균형점 필요")
        print("• 위험 평가를 통한 우선순위 결정")
        print("• 동적인 균형 조정 필요")

class ConfidentialityManager:
    """기밀성 관리 시스템"""
    
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.access_levels = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']
    
    def classify_information(self, data, classification_level):
        """정보 분류"""
        if classification_level not in self.access_levels:
            raise ValueError(f"Invalid classification level. Use: {self.access_levels}")
        
        classified_info = {
            'data': data,
            'classification': classification_level,
            'access_requirements': self._get_access_requirements(classification_level),
            'handling_instructions': self._get_handling_instructions(classification_level),
            'classified_at': datetime.now().isoformat()
        }
        
        return classified_info
    
    def _get_access_requirements(self, level):
        """분류 수준별 접근 요구사항"""
        requirements = {
            'PUBLIC': ['None'],
            'INTERNAL': ['Employee authentication'],
            'CONFIDENTIAL': ['Manager approval', 'Need-to-know basis'],
            'SECRET': ['Security clearance', 'Dual authorization'],
            'TOP_SECRET': ['Highest clearance', 'Compartmentalized access', 'Physical security']
        }
        return requirements.get(level, ['Unknown'])
    
    def _get_handling_instructions(self, level):
        """분류 수준별 처리 지침"""
        instructions = {
            'PUBLIC': ['Standard handling'],
            'INTERNAL': ['Internal use only', 'No external sharing'],
            'CONFIDENTIAL': ['Encrypted storage', 'Secure transmission', 'Access logging'],
            'SECRET': ['Hardware security module', 'Air-gapped systems', 'Clean desk policy'],
            'TOP_SECRET': ['TEMPEST protection', 'Faraday cage', 'Biometric access']
        }
        return instructions.get(level, ['Standard handling'])
    
    def encrypt_sensitive_data(self, data):
        """민감 데이터 암호화"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted_data = self.cipher_suite.encrypt(data)
        
        return {
            'encrypted_data': encrypted_data,
            'encryption_method': 'AES-256 (Fernet)',
            'encrypted_at': datetime.now().isoformat()
        }
    
    def decrypt_sensitive_data(self, encrypted_info):
        """민감 데이터 복호화 (인가된 사용자만)"""
        try:
            decrypted_data = self.cipher_suite.decrypt(encrypted_info['encrypted_data'])
            return decrypted_data.decode()
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    def demonstrate_confidentiality(self):
        """기밀성 구현 시연"""
        print("=== 기밀성 (Confidentiality) 구현 ===\n")
        
        # 다양한 분류 수준의 정보
        test_data = [
            ("공개 보도자료", "PUBLIC"),
            ("내부 직원 명단", "INTERNAL"),
            ("신제품 개발 계획", "CONFIDENTIAL"),
            ("인수합병 계획서", "SECRET"),
            ("국가기밀 프로젝트", "TOP_SECRET")
        ]
        
        for data, level in test_data:
            classified = self.classify_information(data, level)
            print(f"📄 {data}")
            print(f"   분류: {level}")
            print(f"   접근 요구사항: {', '.join(classified['access_requirements'])}")
            print(f"   처리 지침: {', '.join(classified['handling_instructions'])}")
            
            # 암호화 적용 (CONFIDENTIAL 이상)
            if self.access_levels.index(level) >= 2:
                encrypted = self.encrypt_sensitive_data(data)
                print(f"   암호화: 적용됨 ({encrypted['encryption_method']})")
            else:
                print(f"   암호화: 불필요")
            print()

class IntegrityManager:
    """무결성 관리 시스템"""
    
    def __init__(self):
        self.hash_functions = ['sha256', 'sha512', 'md5']  # md5는 데모용
        self.integrity_records = {}
    
    def create_integrity_hash(self, data, algorithm='sha256'):
        """무결성 해시 생성"""
        if isinstance(data, str):
            data = data.encode()
        
        if algorithm == 'sha256':
            hash_obj = hashlib.sha256(data)
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512(data)
        elif algorithm == 'md5':
            hash_obj = hashlib.md5(data)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return hash_obj.hexdigest()
    
    def create_hmac(self, data, key, algorithm='sha256'):
        """HMAC 생성 (키 기반 무결성)"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        if algorithm == 'sha256':
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        elif algorithm == 'sha512':
            return hmac.new(key, data, hashlib.sha512).hexdigest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
    
    def store_with_integrity(self, data_id, data, use_hmac=False, hmac_key=None):
        """무결성 보장을 위한 데이터 저장"""
        timestamp = datetime.now().isoformat()
        
        # 기본 해시
        sha256_hash = self.create_integrity_hash(data, 'sha256')
        
        record = {
            'data_id': data_id,
            'data': data,
            'sha256_hash': sha256_hash,
            'timestamp': timestamp,
            'integrity_verified': True
        }
        
        # HMAC 사용 시
        if use_hmac and hmac_key:
            hmac_value = self.create_hmac(data, hmac_key)
            record['hmac'] = hmac_value
            record['hmac_key_used'] = True
        
        self.integrity_records[data_id] = record
        
        return record
    
    def verify_integrity(self, data_id, current_data=None, hmac_key=None):
        """무결성 검증"""
        if data_id not in self.integrity_records:
            return False, "No integrity record found"
        
        stored_record = self.integrity_records[data_id]
        
        # 현재 데이터가 제공되지 않으면 저장된 데이터 사용
        if current_data is None:
            current_data = stored_record['data']
        
        # SHA256 해시 검증
        current_hash = self.create_integrity_hash(current_data, 'sha256')
        stored_hash = stored_record['sha256_hash']
        
        hash_matches = (current_hash == stored_hash)
        
        # HMAC 검증 (있는 경우)
        hmac_matches = True
        if 'hmac' in stored_record:
            if hmac_key:
                current_hmac = self.create_hmac(current_data, hmac_key)
                stored_hmac = stored_record['hmac']
                hmac_matches = hmac.compare_digest(current_hmac, stored_hmac)
            else:
                return False, "HMAC key required for verification"
        
        if hash_matches and hmac_matches:
            return True, "Integrity verified"
        else:
            issues = []
            if not hash_matches:
                issues.append("Hash mismatch")
            if not hmac_matches:
                issues.append("HMAC mismatch")
            return False, f"Integrity violation: {', '.join(issues)}"
    
    def demonstrate_integrity(self):
        """무결성 구현 시연"""
        print("=== 무결성 (Integrity) 구현 ===\n")
        
        # 원본 데이터
        original_document = "중요한 계약서: 갑과 을은 다음과 같이 합의한다..."
        hmac_secret = "secret_key_for_hmac"
        
        print(f"원본 문서: {original_document}")
        
        # 무결성 보장 저장
        integrity_record = self.store_with_integrity(
            "contract_001", 
            original_document, 
            use_hmac=True, 
            hmac_key=hmac_secret
        )
        
        print(f"SHA256 해시: {integrity_record['sha256_hash']}")
        print(f"HMAC: {integrity_record['hmac'][:32]}...")
        
        # 정상 데이터 검증
        is_valid, message = self.verify_integrity("contract_001", hmac_key=hmac_secret)
        print(f"\n정상 데이터 검증: {'✅ ' + message if is_valid else '❌ ' + message}")
        
        # 변조된 데이터 검증
        tampered_document = "중요한 계약서: 갑과 을은 다음과 같이 합의한다... [악의적 수정]"
        is_valid, message = self.verify_integrity("contract_001", tampered_document, hmac_key=hmac_secret)
        print(f"변조된 데이터 검증: {'✅ ' + message if is_valid else '❌ ' + message}")
        
        # 해시 알고리즘 비교
        print(f"\n해시 알고리즘 비교:")
        test_data = "무결성 테스트 데이터"
        
        for algorithm in ['md5', 'sha256', 'sha512']:
            if algorithm == 'md5':
                print(f"  {algorithm.upper()}: {self.create_integrity_hash(test_data, algorithm)} (⚠️ 권장하지 않음)")
            else:
                print(f"  {algorithm.upper()}: {self.create_integrity_hash(test_data, algorithm)}")

class AvailabilityManager:
    """가용성 관리 시스템"""
    
    def __init__(self):
        self.service_status = {}
        self.backup_systems = {}
        self.load_balancers = {}
        self.monitoring_active = False
    
    def setup_redundancy(self, service_name, primary_endpoint, backup_endpoints):
        """이중화 설정"""
        self.service_status[service_name] = {
            'primary': {
                'endpoint': primary_endpoint,
                'status': 'active',
                'last_check': None,
                'response_time': 0,
                'failure_count': 0
            },
            'backups': []
        }
        
        for i, endpoint in enumerate(backup_endpoints):
            backup_info = {
                'endpoint': endpoint,
                'status': 'standby',
                'last_check': None,
                'response_time': 0,
                'priority': i + 1
            }
            self.service_status[service_name]['backups'].append(backup_info)
    
    def setup_load_balancer(self, service_name, endpoints, algorithm='round_robin'):
        """로드 밸런서 설정"""
        self.load_balancers[service_name] = {
            'endpoints': endpoints,
            'algorithm': algorithm,
            'current_index': 0,
            'endpoint_weights': {ep: 1 for ep in endpoints},
            'endpoint_health': {ep: True for ep in endpoints}
        }
    
    def health_check(self, service_name):
        """서비스 헬스 체크"""
        if service_name not in self.service_status:
            return False, "Service not found"
        
        service = self.service_status[service_name]
        
        # Primary 서버 체크 (시뮬레이션)
        primary_healthy = self._simulate_health_check(service['primary']['endpoint'])
        current_time = datetime.now()
        
        service['primary']['last_check'] = current_time
        
        if primary_healthy:
            service['primary']['status'] = 'active'
            service['primary']['failure_count'] = 0
            service['primary']['response_time'] = random.uniform(0.01, 0.1)  # 10-100ms
            return True, f"Primary server {service['primary']['endpoint']} is healthy"
        else:
            service['primary']['failure_count'] += 1
            service['primary']['response_time'] = float('inf')
            
            if service['primary']['failure_count'] >= 3:
                service['primary']['status'] = 'failed'
                return self._perform_failover(service_name)
            else:
                return False, f"Primary server unhealthy (failures: {service['primary']['failure_count']}/3)"
    
    def _simulate_health_check(self, endpoint):
        """헬스 체크 시뮬레이션"""
        # 90% 확률로 정상
        return random.random() > 0.1
    
    def _perform_failover(self, service_name):
        """페일오버 수행"""
        service = self.service_status[service_name]
        
        # 사용 가능한 백업 서버 찾기
        for backup in service['backups']:
            if self._simulate_health_check(backup['endpoint']):
                backup['status'] = 'active'
                service['primary']['status'] = 'failed'
                
                return True, f"Failover successful to backup: {backup['endpoint']}"
        
        return False, "No healthy backup servers available"
    
    def get_next_endpoint(self, service_name):
        """로드 밸런싱을 통한 다음 엔드포인트 반환"""
        if service_name not in self.load_balancers:
            return None
        
        lb = self.load_balancers[service_name]
        
        if lb['algorithm'] == 'round_robin':
            # 건강한 엔드포인트만 선택
            healthy_endpoints = [ep for ep in lb['endpoints'] if lb['endpoint_health'][ep]]
            
            if not healthy_endpoints:
                return None
            
            # Round Robin
            endpoint = healthy_endpoints[lb['current_index'] % len(healthy_endpoints)]
            lb['current_index'] += 1
            
            return endpoint
        
        return None
    
    def create_backup_schedule(self, data_sources, backup_frequency='daily'):
        """백업 스케줄 생성"""
        backup_schedule = {
            'frequency': backup_frequency,
            'data_sources': data_sources,
            'backup_types': {
                'full': 'Weekly on Sunday',
                'incremental': 'Daily except Sunday',
                'differential': 'On demand'
            },
            'retention_policy': {
                'daily_backups': 30,    # 30일
                'weekly_backups': 12,   # 12주
                'monthly_backups': 12   # 12개월
            },
            'backup_locations': {
                'local': '/backup/local/',
                'offsite': 'backup.company.com',
                'cloud': 'aws-s3-bucket'
            }
        }
        
        return backup_schedule
    
    def demonstrate_availability(self):
        """가용성 구현 시연"""
        print("=== 가용성 (Availability) 구현 ===\n")
        
        # 이중화 설정
        self.setup_redundancy(
            'web_service',
            'web1.company.com',
            ['web2.company.com', 'web3.company.com']
        )
        
        print("이중화 설정:")
        print("  Primary: web1.company.com")
        print("  Backup1: web2.company.com")
        print("  Backup2: web3.company.com")
        
        # 로드 밸런서 설정
        self.setup_load_balancer(
            'api_service',
            ['api1.company.com', 'api2.company.com', 'api3.company.com']
        )
        
        print("\n로드 밸런서 설정:")
        print("  알고리즘: Round Robin")
        print("  엔드포인트: api1, api2, api3.company.com")
        
        # 헬스 체크 시뮬레이션
        print("\n헬스 체크 결과:")
        for i in range(5):
            is_healthy, message = self.health_check('web_service')
            status_icon = "✅" if is_healthy else "❌"
            print(f"  체크 {i+1}: {status_icon} {message}")
        
        # 로드 밸런싱 시뮬레이션
        print("\n로드 밸런싱 결과:")
        for i in range(6):
            endpoint = self.get_next_endpoint('api_service')
            print(f"  요청 {i+1}: {endpoint}")
        
        # 백업 스케줄
        backup_schedule = self.create_backup_schedule([
            'user_database',
            'transaction_logs',
            'configuration_files'
        ])
        
        print(f"\n백업 전략:")
        print(f"  빈도: {backup_schedule['frequency']}")
        print(f"  백업 유형:")
        for backup_type, schedule in backup_schedule['backup_types'].items():
            print(f"    {backup_type}: {schedule}")
        
        print(f"  보존 정책:")
        for retention_type, period in backup_schedule['retention_policy'].items():
            print(f"    {retention_type}: {period}")

class AuthenticationManager:
    """인증 관리 시스템"""
    
    def __init__(self):
        self.user_credentials = {}
        self.authentication_methods = {
            'password': self._password_auth,
            'otp': self._otp_auth,
            'biometric': self._biometric_auth,
            'certificate': self._certificate_auth
        }
    
    def register_user(self, username, auth_methods):
        """사용자 등록"""
        self.user_credentials[username] = {
            'auth_methods': auth_methods,
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked': False
        }
    
    def _password_auth(self, username, credentials):
        """패스워드 인증"""
        # 간단한 시뮬레이션
        expected_password = credentials.get('expected_password', 'password123')
        provided_password = credentials.get('password', '')
        
        return provided_password == expected_password
    
    def _otp_auth(self, username, credentials):
        """OTP 인증"""
        # 시뮬레이션: 6자리 숫자 OTP
        expected_otp = credentials.get('expected_otp', '123456')
        provided_otp = credentials.get('otp', '')
        
        return provided_otp == expected_otp
    
    def _biometric_auth(self, username, credentials):
        """생체 인증"""
        # 시뮬레이션: 95% 성공률
        return random.random() > 0.05
    
    def _certificate_auth(self, username, credentials):
        """인증서 인증"""
        # 시뮬레이션: 인증서 유효성 검사
        cert_valid = credentials.get('cert_valid', True)
        cert_expired = credentials.get('cert_expired', False)
        
        return cert_valid and not cert_expired
    
    def multi_factor_authenticate(self, username, auth_data):
        """다중 인증"""
        if username not in self.user_credentials:
            return False, "User not found"
        
        user_info = self.user_credentials[username]
        
        if user_info['locked']:
            return False, "Account locked"
        
        required_methods = user_info['auth_methods']
        successful_auths = []
        
        for method in required_methods:
            if method in self.authentication_methods:
                auth_func = self.authentication_methods[method]
                if auth_func(username, auth_data):
                    successful_auths.append(method)
                else:
                    user_info['failed_attempts'] += 1
                    if user_info['failed_attempts'] >= 3:
                        user_info['locked'] = True
                        return False, f"Authentication failed for {method}. Account locked."
                    return False, f"Authentication failed for {method}"
        
        if len(successful_auths) == len(required_methods):
            user_info['last_login'] = datetime.now()
            user_info['failed_attempts'] = 0
            return True, f"Multi-factor authentication successful: {', '.join(successful_auths)}"
        
        return False, "Incomplete authentication"

class AuthorizationManager:
    """권한 부여 관리 시스템"""
    
    def __init__(self):
        self.roles = {}
        self.user_roles = {}
        self.resources = {}
        self.access_control_model = 'RBAC'  # Role-Based Access Control
    
    def define_role(self, role_name, permissions):
        """역할 정의"""
        self.roles[role_name] = {
            'permissions': permissions,
            'created_at': datetime.now(),
            'description': f"Role: {role_name}"
        }
    
    def assign_role(self, username, roles):
        """사용자에게 역할 할당"""
        self.user_roles[username] = {
            'roles': roles,
            'assigned_at': datetime.now(),
            'assigned_by': 'system'
        }
    
    def define_resource(self, resource_name, required_permissions):
        """리소스 정의"""
        self.resources[resource_name] = {
            'required_permissions': required_permissions,
            'access_level': 'restricted',
            'owner': 'system'
        }
    
    def check_authorization(self, username, resource_name, requested_action):
        """권한 확인"""
        if username not in self.user_roles:
            return False, "User has no assigned roles"
        
        if resource_name not in self.resources:
            return False, "Resource not found"
        
        # 사용자의 모든 권한 수집
        user_permissions = set()
        user_roles_list = self.user_roles[username]['roles']
        
        for role in user_roles_list:
            if role in self.roles:
                role_permissions = self.roles[role]['permissions']
                user_permissions.update(role_permissions)
        
        # 리소스 접근에 필요한 권한
        required_permissions = self.resources[resource_name]['required_permissions']
        required_permission = f"{requested_action}:{resource_name}"
        
        # 권한 확인
        if required_permission in user_permissions:
            return True, f"Access granted to {resource_name} for {requested_action}"
        elif f"admin:{resource_name}" in user_permissions:
            return True, f"Admin access granted to {resource_name}"
        elif "superuser" in user_permissions:
            return True, "Superuser access granted"
        else:
            return False, f"Insufficient permissions for {requested_action} on {resource_name}"

class NonRepudiationManager:
    """부인방지 관리 시스템"""
    
    def __init__(self):
        self.digital_signatures = {}
        self.audit_trail = []
        
        # RSA 키 쌍 생성
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def create_digital_signature(self, message, signer_id):
        """디지털 서명 생성"""
        if isinstance(message, str):
            message = message.encode()
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        signature_record = {
            'message': message,
            'signature': signature,
            'signer_id': signer_id,
            'timestamp': datetime.now(),
            'algorithm': 'RSA-PSS with SHA256'
        }
        
        signature_id = f"{signer_id}_{int(datetime.now().timestamp())}"
        self.digital_signatures[signature_id] = signature_record
        
        # 감사 로그에 기록
        self._log_audit_event('DIGITAL_SIGNATURE_CREATED', {
            'signature_id': signature_id,
            'signer_id': signer_id,
            'message_hash': hashlib.sha256(message).hexdigest()[:16]
        })
        
        return signature_id, signature
    
    def verify_digital_signature(self, signature_id):
        """디지털 서명 검증"""
        if signature_id not in self.digital_signatures:
            return False, "Signature record not found"
        
        record = self.digital_signatures[signature_id]
        
        try:
            self.public_key.verify(
                record['signature'],
                record['message'],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self._log_audit_event('SIGNATURE_VERIFIED', {
                'signature_id': signature_id,
                'verification_result': 'SUCCESS'
            })
            
            return True, f"Signature verified for {record['signer_id']} at {record['timestamp']}"
            
        except Exception as e:
            self._log_audit_event('SIGNATURE_VERIFICATION_FAILED', {
                'signature_id': signature_id,
                'error': str(e)
            })
            
            return False, f"Signature verification failed: {str(e)}"
    
    def _log_audit_event(self, event_type, details):
        """감사 로그 기록"""
        audit_entry = {
            'timestamp': datetime.now(),
            'event_type': event_type,
            'details': details,
            'session_id': f"session_{random.randint(1000, 9999)}"
        }
        
        self.audit_trail.append(audit_entry)
    
    def get_audit_trail(self, filter_by=None):
        """감사 추적 정보 조회"""
        if filter_by:
            return [entry for entry in self.audit_trail 
                   if filter_by.lower() in entry['event_type'].lower()]
        return self.audit_trail

# 종합 시연 시스템
def comprehensive_security_demo():
    """종합 보안 요소 시연"""
    print("🛡️  정보보안 3요소 + 확장 요소 종합 시연")
    print("=" * 60)
    
    # 보안 시스템 초기화
    security_system = SecurityTriadImplementation()
    
    # 1. 균형 시연
    security_system.demonstrate_security_balance()
    
    print("\n" + "=" * 60)
    
    # 2. CIA Triad 시연
    print("\n🔐 기밀성 (Confidentiality)")
    security_system.confidentiality_system.demonstrate_confidentiality()
    
    print("\n" + "-" * 40)
    
    print("\n✅ 무결성 (Integrity)")
    security_system.integrity_system.demonstrate_integrity()
    
    print("\n" + "-" * 40)
    
    print("\n🔄 가용성 (Availability)")
    security_system.availability_system.demonstrate_availability()
    
    print("\n" + "=" * 60)
    
    # 3. 확장 보안 요소 시연
    print("\n🔑 인증 (Authentication)")
    auth_mgr = security_system.authentication_system
    
    # 사용자 등록
    auth_mgr.register_user('alice', ['password', 'otp'])
    auth_mgr.register_user('bob', ['password', 'biometric'])
    
    # 인증 테스트
    auth_data = {
        'expected_password': 'secure123',
        'password': 'secure123',
        'expected_otp': '789012',
        'otp': '789012'
    }
    
    success, message = auth_mgr.multi_factor_authenticate('alice', auth_data)
    print(f"Alice 인증 결과: {'✅' if success else '❌'} {message}")
    
    # 실패 케이스
    wrong_auth_data = {
        'expected_password': 'secure123',
        'password': 'wrong_password',
        'expected_otp': '789012',
        'otp': '789012'
    }
    
    success, message = auth_mgr.multi_factor_authenticate('alice', wrong_auth_data)
    print(f"Alice 잘못된 인증: {'✅' if success else '❌'} {message}")
    
    print("\n🔐 권한 부여 (Authorization)")
    authz_mgr = security_system.authorization_system
    
    # 역할 및 권한 정의
    authz_mgr.define_role('admin', ['read:database', 'write:database', 'delete:database', 'admin:database'])
    authz_mgr.define_role('user', ['read:database'])
    authz_mgr.define_role('manager', ['read:database', 'write:database'])
    
    # 사용자에게 역할 할당
    authz_mgr.assign_role('alice', ['admin'])
    authz_mgr.assign_role('bob', ['user'])
    
    # 리소스 정의
    authz_mgr.define_resource('customer_database', ['read:customer_database', 'write:customer_database'])
    
    # 권한 확인
    success, message = authz_mgr.check_authorization('alice', 'customer_database', 'read')
    print(f"Alice 데이터베이스 읽기: {'✅' if success else '❌'} {message}")
    
    success, message = authz_mgr.check_authorization('bob', 'customer_database', 'write')
    print(f"Bob 데이터베이스 쓰기: {'✅' if success else '❌'} {message}")
    
    print("\n📝 부인방지 (Non-repudiation)")
    nonrep_mgr = security_system.non_repudiation_system
    
    # 디지털 서명 생성
    contract_message = "계약 내용: 갑과 을은 2024년 12월 31일까지 본 계약을 이행한다."
    signature_id, signature = nonrep_mgr.create_digital_signature(contract_message, 'alice')
    
    print(f"Alice의 디지털 서명 생성: {signature_id}")
    print(f"서명 (처음 32바이트): {signature.hex()[:64]}...")
    
    # 서명 검증
    success, message = nonrep_mgr.verify_digital_signature(signature_id)
    print(f"서명 검증 결과: {'✅' if success else '❌'} {message}")
    
    # 감사 추적 조회
    audit_entries = nonrep_mgr.get_audit_trail()
    print(f"\n감사 로그 엔트리 수: {len(audit_entries)}")
    for entry in audit_entries[-2:]:  # 최근 2개 항목
        print(f"  {entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {entry['event_type']}")
    
    print(f"\n" + "=" * 60)
    print(f"결론: 정보보안은 CIA 3요소와 확장 요소들이")
    print(f"      유기적으로 결합되어 종합적 보안을 제공합니다.")

if __name__ == "__main__":
    comprehensive_security_demo()
```

### 4. 인증(Authentication)과 접근통제(Access Control)

#### 인증 방법의 종류

```python
#!/usr/bin/env python3
# 인증과 접근통제 종합 시스템

import hashlib
import hmac
import random
import time
import qrcode
import base64
from datetime import datetime, timedelta
import json

class MultiFactorAuthSystem:
    """다중 인증 시스템"""
    
    def __init__(self):
        self.users = {}
        self.otp_secrets = {}
        self.failed_attempts = {}
        self.locked_accounts = set()
        
        # 인증 방법별 설정
        self.auth_methods = {
            'knowledge': {  # 지식 기반
                'password': {'min_length': 8, 'complexity_required': True},
                'pin': {'length': 4, 'numeric_only': True},
                'security_questions': {'min_questions': 3}
            },
            'possession': {  # 소유 기반
                'smart_card': {'certificate_required': True},
                'hardware_token': {'otp_algorithm': 'TOTP'},
                'mobile_app': {'push_notification': True}
            },
            'inherence': {  # 생체 기반
                'fingerprint': {'accuracy_threshold': 0.95},
                'face_recognition': {'accuracy_threshold': 0.90},
                'voice_recognition': {'accuracy_threshold': 0.92},
                'iris_scan': {'accuracy_threshold': 0.99}
            }
        }
    
    def register_user(self, username, password, auth_methods_required):
        """사용자 등록"""
        # 비밀번호 해시화
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'auth_methods': auth_methods_required,
            'created_at': datetime.now(),
            'last_login': None,
            'login_count': 0
        }
        
        # OTP 시크릿 생성 (TOTP 사용 시)
        if 'otp' in auth_methods_required:
            self.otp_secrets[username] = self._generate_otp_secret()
        
        return True, f"User {username} registered successfully"
    
    def _generate_salt(self):
        """솔트 생성"""
        import secrets
        return secrets.token_hex(16)
    
    def _hash_password(self, password, salt):
        """비밀번호 해시화"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    
    def _generate_otp_secret(self):
        """OTP 시크릿 키 생성"""
        import secrets
        return base64.b32encode(secrets.token_bytes(20)).decode()
    
    def _verify_password(self, username, password):
        """비밀번호 검증"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        expected_hash = user['password_hash']
        salt = user['salt']
        
        password_hash = self._hash_password(password, salt)
        
        return password_hash == expected_hash
    
    def _generate_totp(self, secret, timestamp=None):
        """TOTP 생성"""
        if timestamp is None:
            timestamp = int(time.time())
        
        # 30초 간격
        counter = timestamp // 30
        
        # HMAC 계산
        counter_bytes = counter.to_bytes(8, byteorder='big')
        secret_bytes = base64.b32decode(secret.encode())
        
        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0f
        code = (
            (hmac_hash[offset] & 0x7f) << 24 |
            (hmac_hash[offset + 1] & 0xff) << 16 |
            (hmac_hash[offset + 2] & 0xff) << 8 |
            (hmac_hash[offset + 3] & 0xff)
        )
        
        return f"{code % 1000000:06d}"
    
    def _verify_totp(self, username, provided_otp):
        """TOTP 검증"""
        if username not in self.otp_secrets:
            return False
        
        secret = self.otp_secrets[username]
        current_time = int(time.time())
        
        # 시간 윈도우 허용 (±30초)
        for time_offset in [-30, 0, 30]:
            timestamp = current_time + time_offset
            expected_otp = self._generate_totp(secret, timestamp)
            
            if provided_otp == expected_otp:
                return True
        
        return False
    
    def _simulate_biometric_auth(self, auth_type):
        """생체 인증 시뮬레이션"""
        if auth_type not in self.auth_methods['inherence']:
            return False
        
        threshold = self.auth_methods['inherence'][auth_type]['accuracy_threshold']
        
        # 시뮬레이션: 임계값 기반 성공/실패
        accuracy = random.uniform(0.80, 1.00)
        return accuracy >= threshold
    
    def authenticate(self, username, auth_data):
        """종합 인증 수행"""
        # 계정 잠금 확인
        if username in self.locked_accounts:
            return False, "Account is locked due to multiple failed attempts"
        
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        required_methods = user['auth_methods']
        successful_auths = []
        
        # 각 인증 방법별 검증
        for method in required_methods:
            if method == 'password':
                password = auth_data.get('password', '')
                if self._verify_password(username, password):
                    successful_auths.append('password')
                else:
                    return self._handle_failed_auth(username, "Password verification failed")
            
            elif method == 'otp':
                otp = auth_data.get('otp', '')
                if self._verify_totp(username, otp):
                    successful_auths.append('otp')
                else:
                    return self._handle_failed_auth(username, "OTP verification failed")
            
            elif method in ['fingerprint', 'face_recognition', 'voice_recognition', 'iris_scan']:
                if self._simulate_biometric_auth(method):
                    successful_auths.append(method)
                else:
                    return self._handle_failed_auth(username, f"{method} verification failed")
            
            elif method == 'smart_card':
                # 스마트카드 시뮬레이션
                card_present = auth_data.get('smart_card_present', False)
                if card_present:
                    successful_auths.append('smart_card')
                else:
                    return self._handle_failed_auth(username, "Smart card not present")
        
        # 모든 인증 방법이 성공했는지 확인
        if len(successful_auths) == len(required_methods):
            # 성공 처리
            user['last_login'] = datetime.now()
            user['login_count'] += 1
            
            # 실패 카운터 리셋
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            
            return True, f"Authentication successful: {', '.join(successful_auths)}"
        
        return self._handle_failed_auth(username, "Incomplete authentication")
    
    def _handle_failed_auth(self, username, reason):
        """인증 실패 처리"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = 0
        
        self.failed_attempts[username] += 1
        
        if self.failed_attempts[username] >= 3:
            self.locked_accounts.add(username)
            return False, f"{reason}. Account locked after 3 failed attempts."
        
        return False, f"{reason}. Attempts: {self.failed_attempts[username]}/3"
    
    def unlock_account(self, username, admin_verification=False):
        """계정 잠금 해제"""
        if admin_verification:
            self.locked_accounts.discard(username)
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            return True, f"Account {username} unlocked by administrator"
        
        return False, "Administrator verification required"
    
    def get_qr_code_for_otp(self, username, issuer="MyCompany"):
        """OTP 설정용 QR 코드 생성"""
        if username not in self.otp_secrets:
            return None, "OTP not configured for user"
        
        secret = self.otp_secrets[username]
        
        # OTP URI 형식
        otp_uri = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"
        
        try:
            # QR 코드 생성
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(otp_uri)
            qr.make(fit=True)
            
            return otp_uri, "QR code data generated"
        except:
            return otp_uri, "QR code generation available with qrcode library"
    
    def demonstrate_multi_factor_auth(self):
        """다중 인증 시스템 시연"""
        print("=== 다중 인증 시스템 시연 ===\n")
        
        # 다양한 인증 조합의 사용자 등록
        users_to_register = [
            ("alice", "SecurePass123!", ["password", "otp"]),
            ("bob", "MyPassword456@", ["password", "fingerprint"]),
            ("charlie", "ComplexPwd789#", ["password", "otp", "face_recognition"]),
            ("admin", "AdminPass000$", ["password", "smart_card", "iris_scan"])
        ]
        
        for username, password, auth_methods in users_to_register:
            success, message = self.register_user(username, password, auth_methods)
            print(f"사용자 등록 - {username}: {'✅' if success else '❌'} {message}")
            print(f"  인증 방법: {', '.join(auth_methods)}")
            
            # OTP 사용자의 경우 QR 코드 정보 제공
            if 'otp' in auth_methods:
                qr_data, qr_message = self.get_qr_code_for_otp(username)
                print(f"  OTP QR: {qr_message}")
                if 'MyCompany' in qr_data:
                    print(f"  OTP Secret: {self.otp_secrets[username]}")
            print()
        
        print("=" * 50)
        
        # 인증 테스트 시나리오
        test_scenarios = [
            {
                'username': 'alice',
                'auth_data': {
                    'password': 'SecurePass123!',
                    'otp': self._generate_totp(self.otp_secrets['alice'])
                },
                'expected': True,
                'description': '올바른 패스워드 + OTP'
            },
            {
                'username': 'alice',
                'auth_data': {
                    'password': 'WrongPassword',
                    'otp': self._generate_totp(self.otp_secrets['alice'])
                },
                'expected': False,
                'description': '잘못된 패스워드 + 올바른 OTP'
            },
            {
                'username': 'bob',
                'auth_data': {
                    'password': 'MyPassword456@',
                    'fingerprint': True  # 생체 인증은 시뮬레이션
                },
                'expected': True,
                'description': '올바른 패스워드 + 지문 인식'
            },
            {
                'username': 'charlie',
                'auth_data': {
                    'password': 'ComplexPwd789#',
                    'otp': self._generate_totp(self.otp_secrets['charlie']),
                    'face_recognition': True
                },
                'expected': True,
                'description': '3단계 인증 (패스워드 + OTP + 얼굴인식)'
            }
        ]
        
        print("인증 테스트 결과:")
        for i, scenario in enumerate(test_scenarios, 1):
            success, message = self.authenticate(scenario['username'], scenario['auth_data'])
            
            expected_icon = "✅" if scenario['expected'] else "❌"
            actual_icon = "✅" if success else "❌"
            
            print(f"{i}. {scenario['description']}")
            print(f"   사용자: {scenario['username']}")
            print(f"   예상: {expected_icon} | 실제: {actual_icon}")
            print(f"   결과: {message}")
            print()

class AccessControlSystem:
    """접근 통제 시스템"""
    
    def __init__(self):
        # 접근 통제 모델들
        self.dac_system = DiscretionaryAccessControl()
        self.mac_system = MandatoryAccessControl()
        self.rbac_system = RoleBasedAccessControl()
        
        # 3단계 접근 통제 프로세스
        self.access_control_process = {
            'identification': self._identification,
            'authentication': self._authentication,
            'authorization': self._authorization
        }
    
    def _identification(self, user_identity):
        """1단계: 식별"""
        # 시스템에 사용자 신분 제시
        if not user_identity or len(user_identity.strip()) == 0:
            return False, "User identity required"
        
        return True, f"User identity '{user_identity}' received"
    
    def _authentication(self, user_identity, credentials):
        """2단계: 인증"""
        # 제시된 신분과 주체가 일치함을 증명
        # 간단한 시뮬레이션
        valid_users = ['alice', 'bob', 'charlie', 'admin']
        
        if user_identity not in valid_users:
            return False, "Unknown user"
        
        # 자격 증명 확인
        expected_password = f"{user_identity}_password"  # 간단한 시뮬레이션
        provided_password = credentials.get('password', '')
        
        if provided_password == expected_password:
            return True, f"User '{user_identity}' authenticated"
        else:
            return False, "Authentication failed"
    
    def _authorization(self, user_identity, resource, action):
        """3단계: 권한 부여"""
        # 시스템 내에서 자원 또는 정보의 접근 허용
        
        # RBAC 기반 권한 확인
        return self.rbac_system.check_permission(user_identity, resource, action)
    
    def process_access_request(self, user_identity, credentials, resource, action):
        """접근 요청 처리 (3단계 프로세스)"""
        print(f"=== 접근 통제 3단계 프로세스 ===")
        print(f"요청: {user_identity} -> {resource} ({action})\n")
        
        # 1단계: 식별
        success, message = self._identification(user_identity)
        print(f"1️⃣ 식별: {'✅' if success else '❌'} {message}")
        if not success:
            return False, message
        
        # 2단계: 인증
        success, message = self._authentication(user_identity, credentials)
        print(f"2️⃣ 인증: {'✅' if success else '❌'} {message}")
        if not success:
            return False, message
        
        # 3단계: 권한 부여
        success, message = self._authorization(user_identity, resource, action)
        print(f"3️⃣ 권한부여: {'✅' if success else '❌'} {message}")
        
        return success, message

class DiscretionaryAccessControl:
    """임의 접근 통제 (DAC) - 신분 기반"""
    
    def __init__(self):
        self.resource_owners = {}
        self.access_control_lists = {}
    
    def set_resource_owner(self, resource, owner):
        """리소스 소유자 설정"""
        self.resource_owners[resource] = owner
        
        # 소유자는 모든 권한을 가짐
        if resource not in self.access_control_lists:
            self.access_control_lists[resource] = {}
        
        self.access_control_lists[resource][owner] = ['read', 'write', 'execute', 'delete']
    
    def grant_permission(self, resource, user, permissions, grantor):
        """권한 부여 (소유자만 가능)"""
        if resource not in self.resource_owners:
            return False, "Resource not found"
        
        if self.resource_owners[resource] != grantor:
            return False, "Only resource owner can grant permissions"
        
        if resource not in self.access_control_lists:
            self.access_control_lists[resource] = {}
        
        self.access_control_lists[resource][user] = permissions
        
        return True, f"Permissions {permissions} granted to {user} for {resource}"
    
    def check_permission(self, user, resource, action):
        """권한 확인"""
        if resource not in self.access_control_lists:
            return False, "Resource not found"
        
        if user not in self.access_control_lists[resource]:
            return False, f"User {user} has no permissions for {resource}"
        
        user_permissions = self.access_control_lists[resource][user]
        
        if action in user_permissions:
            return True, f"Permission granted: {user} can {action} {resource}"
        else:
            return False, f"Permission denied: {user} cannot {action} {resource}"

class MandatoryAccessControl:
    """강제 접근 통제 (MAC) - 보안 등급 기반"""
    
    def __init__(self):
        self.security_levels = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']
        self.user_clearances = {}
        self.resource_classifications = {}
    
    def set_user_clearance(self, user, clearance_level):
        """사용자 보안 등급 설정"""
        if clearance_level not in self.security_levels:
            return False, f"Invalid clearance level: {clearance_level}"
        
        self.user_clearances[user] = clearance_level
        return True, f"User {user} clearance set to {clearance_level}"
    
    def classify_resource(self, resource, classification_level):
        """리소스 보안 분류"""
        if classification_level not in self.security_levels:
            return False, f"Invalid classification level: {classification_level}"
        
        self.resource_classifications[resource] = classification_level
        return True, f"Resource {resource} classified as {classification_level}"
    
    def check_permission(self, user, resource, action):
        """보안 등급 기반 권한 확인"""
        if user not in self.user_clearances:
            return False, f"User {user} has no security clearance"
        
        if resource not in self.resource_classifications:
            return False, f"Resource {resource} not classified"
        
        user_level_index = self.security_levels.index(self.user_clearances[user])
        resource_level_index = self.security_levels.index(self.resource_classifications[resource])
        
        # Bell-LaPadula Model: "No Read Up" rule
        if action == 'read' and user_level_index >= resource_level_index:
            return True, f"Read access granted: {user} clearance >= {resource} classification"
        
        # Biba Model: "No Write Down" rule  
        elif action == 'write' and user_level_index <= resource_level_index:
            return True, f"Write access granted: {user} clearance <= {resource} classification"
        
        else:
            return False, f"Access denied: Security level mismatch ({action})"

class RoleBasedAccessControl:
    """역할 기반 접근 통제 (RBAC)"""
    
    def __init__(self):
        self.roles = {}
        self.user_roles = {}
        self.role_permissions = {}
        self.role_hierarchy = {}
        
        # 기본 역할 설정
        self._setup_default_roles()
    
    def _setup_default_roles(self):
        """기본 역할 설정"""
        default_roles = {
            'guest': {
                'description': '게스트 사용자',
                'permissions': ['read:public_documents']
            },
            'employee': {
                'description': '일반 직원',
                'permissions': ['read:internal_documents', 'write:own_documents']
            },
            'manager': {
                'description': '관리자',
                'permissions': ['read:internal_documents', 'write:internal_documents', 'read:confidential_documents']
            },
            'admin': {
                'description': '시스템 관리자',
                'permissions': ['read:*', 'write:*', 'delete:*', 'admin:*']
            }
        }
        
        for role_name, role_info in default_roles.items():
            self.create_role(role_name, role_info['permissions'], role_info['description'])
        
        # 역할 계층 구조 설정
        self.role_hierarchy = {
            'admin': ['manager', 'employee', 'guest'],
            'manager': ['employee', 'guest'],
            'employee': ['guest'],
            'guest': []
        }
    
    def create_role(self, role_name, permissions, description=""):
        """역할 생성"""
        self.roles[role_name] = {
            'permissions': permissions,
            'description': description,
            'created_at': datetime.now()
        }
        
        return True, f"Role '{role_name}' created"
    
    def assign_role(self, user, roles):
        """사용자에게 역할 할당"""
        # 역할 존재 확인
        for role in roles:
            if role not in self.roles:
                return False, f"Role '{role}' does not exist"
        
        self.user_roles[user] = roles
        return True, f"Roles {roles} assigned to user {user}"
    
    def get_user_permissions(self, user):
        """사용자의 모든 권한 조회 (역할 계층 포함)"""
        if user not in self.user_roles:
            return set()
        
        all_permissions = set()
        user_roles = self.user_roles[user]
        
        for role in user_roles:
            # 직접 할당된 역할의 권한
            if role in self.roles:
                role_permissions = self.roles[role]['permissions']
                all_permissions.update(role_permissions)
            
            # 계층 구조에 따른 하위 역할의 권한
            if role in self.role_hierarchy:
                for inherited_role in self.role_hierarchy[role]:
                    if inherited_role in self.roles:
                        inherited_permissions = self.roles[inherited_role]['permissions']
                        all_permissions.update(inherited_permissions)
        
        return all_permissions
    
    def check_permission(self, user, resource, action):
        """권한 확인"""
        user_permissions = self.get_user_permissions(user)
        
        if not user_permissions:
            return False, f"User {user} has no assigned roles"
        
        # 필요한 권한 형식: action:resource
        required_permission = f"{action}:{resource}"
        
        # 직접적인 권한 확인
        if required_permission in user_permissions:
            return True, f"Permission granted: {required_permission}"
        
        # 와일드카드 권한 확인
        wildcard_permission = f"{action}:*"
        if wildcard_permission in user_permissions:
            return True, f"Wildcard permission granted: {wildcard_permission}"
        
        # 관리자 권한 확인
        if "admin:*" in user_permissions:
            return True, "Administrator access granted"
        
        return False, f"Permission denied: {required_permission}"
    
    def demonstrate_rbac(self):
        """RBAC 시연"""
        print("=== 역할 기반 접근 통제 (RBAC) 시연 ===\n")
        
        # 사용자에게 역할 할당
        test_users = [
            ('alice', ['admin']),
            ('bob', ['manager']),
            ('charlie', ['employee']),
            ('david', ['guest'])
        ]
        
        for user, roles in test_users:
            success, message = self.assign_role(user, roles)
            print(f"역할 할당 - {user}: {roles} -> {'✅' if success else '❌'} {message}")
        
        print()
        
        # 권한 테스트
        test_scenarios = [
            ('alice', 'confidential_documents', 'read'),
            ('alice', 'system_config', 'delete'),
            ('bob', 'confidential_documents', 'read'),
            ('bob', 'internal_documents', 'write'),
            ('charlie', 'internal_documents', 'read'),
            ('charlie', 'confidential_documents', 'read'),  # 거부될 것
            ('david', 'public_documents', 'read'),
            ('david', 'internal_documents', 'read')  # 거부될 것
        ]
        
        print("권한 테스트 결과:")
        for user, resource, action in test_scenarios:
            success, message = self.check_permission(user, resource, action)
            icon = "✅" if success else "❌"
            print(f"  {icon} {user} -> {action} {resource}: {message}")
        
        print()
        
        # 사용자별 권한 요약
        print("사용자별 권한 요약:")
        for user in ['alice', 'bob', 'charlie', 'david']:
            permissions = self.get_user_permissions(user)
            roles = self.user_roles.get(user, [])
            print(f"  {user} ({', '.join(roles)}): {len(permissions)}개 권한")
            for perm in sorted(list(permissions))[:3]:  # 처음 3개만 표시
                print(f"    • {perm}")
            if len(permissions) > 3:
                print(f"    ... 및 {len(permissions)-3}개 더")

# 종합 데모
def comprehensive_access_control_demo():
    """종합 접근 통제 시연"""
    print("🔐 인증과 접근통제 종합 시연")
    print("=" * 60)
    
    # 1. 다중 인증 시스템
    mfa_system = MultiFactorAuthSystem()
    mfa_system.demonstrate_multi_factor_auth()
    
    print("\n" + "=" * 60)
    
    # 2. 접근 통제 모델들
    print("\n🏛️ 접근 통제 모델 비교\n")
    
    # DAC 시연
    print("1. 임의 접근 통제 (DAC)")
    dac = DiscretionaryAccessControl()
    dac.set_resource_owner('project_files', 'alice')
    dac.grant_permission('project_files', 'bob', ['read', 'write'], 'alice')
    
    success, message = dac.check_permission('bob', 'project_files', 'read')
    print(f"   Bob의 project_files 읽기: {'✅' if success else '❌'} {message}")
    
    success, message = dac.check_permission('charlie', 'project_files', 'read')
    print(f"   Charlie의 project_files 읽기: {'✅' if success else '❌'} {message}")
    print()
    
    # MAC 시연
    print("2. 강제 접근 통제 (MAC)")
    mac = MandatoryAccessControl()
    mac.set_user_clearance('alice', 'SECRET')
    mac.set_user_clearance('bob', 'CONFIDENTIAL')
    mac.classify_resource('classified_doc', 'SECRET')
    
    success, message = mac.check_permission('alice', 'classified_doc', 'read')
    print(f"   Alice의 classified_doc 읽기: {'✅' if success else '❌'} {message}")
    
    success, message = mac.check_permission('bob', 'classified_doc', 'read')
    print(f"   Bob의 classified_doc 읽기: {'✅' if success else '❌'} {message}")
    print()
    
    # RBAC 시연
    print("3. 역할 기반 접근 통제 (RBAC)")
    rbac = RoleBasedAccessControl()
    rbac.demonstrate_rbac()
    
    print("\n" + "=" * 60)
    
    # 3. 통합 접근 통제 시스템
    print("\n🎯 통합 접근 통제 프로세스\n")
    
    access_system = AccessControlSystem()
    
    # 테스트 시나리오
    test_requests = [
        {
            'user': 'alice',
            'credentials': {'password': 'alice_password'},
            'resource': 'confidential_documents',
            'action': 'read'
        },
        {
            'user': 'unknown_user',
            'credentials': {'password': 'any_password'},
            'resource': 'public_documents',
            'action': 'read'
        }
    ]
    
    for i, request in enumerate(test_requests, 1):
        print(f"테스트 시나리오 {i}:")
        access_system.rbac_system.assign_role(request['user'], ['admin'])  # 테스트용
        
        success, final_message = access_system.process_access_request(
            request['user'],
            request['credentials'],
            request['resource'],
            request['action']
        )
        
        print(f"최종 결과: {'✅ 접근 허용' if success else '❌ 접근 거부'}")
        print(f"사유: {final_message}")
        print()
    
    print("=" * 60)
    print("결론:")
    print("• 인증(Authentication): 사용자가 누구인지 확인")
    print("• 권한부여(Authorization): 무엇을 할 수 있는지 결정")  
    print("• 접근통제 모델: 조직의 보안 정책에 따라 선택")
    print("• 다중 요소 인증: 보안성 강화를 위한 필수 요소")

if __name__ == "__main__":
    comprehensive_access_control_demo()
```

## 마무리

이번 23강에서는 **개인정보보호의 이해 (1)**을 다뤘습니다. **해킹의 역사와 발전 과정**, **개인과 기업 차원에서의 정보보호 필요성**, **CIA 3대 목표와 확장 보안 요소들**, **인증과 접근통제의 다양한 방법** 등을 통해 정보보호의 기본 개념과 중요성을 이해했습니다.

다음 강의에서는 **개인정보보호의 이해 (2)**를 학습하여 개인정보보호법의 발전 과정과 주요 내용을 알아보겠습니다.

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*