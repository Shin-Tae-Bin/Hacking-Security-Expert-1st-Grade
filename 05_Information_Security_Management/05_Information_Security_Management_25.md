# 25강: 개인정보보호의 이해 (3)

## 개요
해킹보안전문가 1급 과정의 25강으로, 정보주체의 권리와 개인정보 수집·이용·제공에 대한 구체적인 규정을 다룹니다. 정보주체의 5대 권리, 개인정보 보호 10계명, 국가의 개인정보보호 의무, 그리고 실제 개인정보 처리 시 준수해야 할 절차와 방법을 학습합니다.

## 주요 학습 내용

### 1. 정보주체의 권리

#### 정보주체의 5대 권리 시스템

```python
#!/usr/bin/env python3
# 정보주체 권리 행사 관리 시스템

from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib
from typing import Dict, List, Optional, Any

class SubjectRightType(Enum):
    """정보주체 권리 유형"""
    RIGHT_TO_BE_INFORMED = "정보를 제공받을 권리"
    RIGHT_TO_CONSENT = "동의 여부를 선택하고 결정할 권리"
    RIGHT_OF_ACCESS = "개인정보 처리여부 확인 및 열람을 요구할 권리"
    RIGHT_TO_RECTIFICATION = "개인정보의 처리 정지, 정정·삭제 및 파기를 요구할 권리"
    RIGHT_TO_REMEDY = "개인정보 처리로 인한 피해를 구제받을 권리"

class DataSubjectRightsManagement:
    """정보주체 권리 관리 시스템"""
    
    def __init__(self):
        self.data_subjects = {}  # 정보주체 정보
        self.processing_records = {}  # 처리 기록
        self.consent_records = {}  # 동의 기록
        self.rights_requests = {}  # 권리 행사 요청
        self.remedy_cases = {}  # 피해구제 사례
        
        # 정보주체 권리 상세 정의
        self.rights_details = {
            SubjectRightType.RIGHT_TO_BE_INFORMED: {
                'description': '자신의 개인정보 처리에 관한 정보를 제공받을 권리',
                'includes': [
                    '개인정보 처리목적',
                    '개인정보 처리항목',
                    '개인정보 보유 및 이용기간',
                    '개인정보 제3자 제공 현황',
                    '개인정보 처리위탁 현황',
                    '정보주체의 권리와 행사방법',
                    '개인정보보호책임자 연락처'
                ],
                'response_time': 10  # 10일 이내 응답
            },
            SubjectRightType.RIGHT_TO_CONSENT: {
                'description': '개인정보 처리에 관한 동의 여부, 동의 범위 등을 선택하고 결정할 권리',
                'includes': [
                    '개별 동의 (수집·이용, 제3자 제공, 마케팅 등)',
                    '선택적 동의와 필수 동의 구분',
                    '동의 철회권 보장',
                    '동의 거부에 따른 불이익 최소화'
                ],
                'response_time': 0  # 즉시 처리
            },
            SubjectRightType.RIGHT_OF_ACCESS: {
                'description': '개인정보 처리여부를 확인하고 개인정보에 대해 열람을 요구할 권리',
                'includes': [
                    '개인정보 처리현황 통지',
                    '개인정보 사본 발급',
                    '개인정보 수집 출처',
                    '개인정보 처리 목적',
                    '개인정보 이용 및 제공 현황'
                ],
                'response_time': 10  # 10일 이내 응답
            },
            SubjectRightType.RIGHT_TO_RECTIFICATION: {
                'description': '개인정보의 처리 정지, 정정·삭제 및 파기를 요구할 권리',
                'includes': [
                    '개인정보 정정·삭제 요구',
                    '개인정보 처리정지 요구',
                    '잘못된 개인정보 수정 요구',
                    '불법 수집된 개인정보 삭제 요구'
                ],
                'response_time': 10  # 10일 이내 처리
            },
            SubjectRightType.RIGHT_TO_REMEDY: {
                'description': '개인정보 처리로 인해 발생한 피해를 신속하고 공정한 절차에 따라 구제받을 권리',
                'includes': [
                    '손해배상 청구',
                    '정신적 피해 배상',
                    '개인정보보호위원회 신고',
                    '집단분쟁조정 신청',
                    '소송 제기'
                ],
                'response_time': 30  # 30일 이내 (경우에 따라 연장 가능)
            }
        }
    
    def register_data_subject(self, subject_id: str, personal_info: Dict) -> str:
        """정보주체 등록"""
        self.data_subjects[subject_id] = {
            'personal_info': personal_info,
            'registered_at': datetime.now(),
            'consent_history': [],
            'access_history': [],
            'rights_exercised': [],
            'status': 'active'
        }
        
        return f"정보주체 {subject_id} 등록 완료"
    
    def request_information_provision(self, subject_id: str, request_details: Dict) -> str:
        """정보 제공 요구 (1번째 권리)"""
        request_id = f"info_{subject_id}_{int(datetime.now().timestamp())}"
        
        request_record = {
            'request_id': request_id,
            'subject_id': subject_id,
            'right_type': SubjectRightType.RIGHT_TO_BE_INFORMED,
            'request_details': request_details,
            'requested_at': datetime.now(),
            'response_deadline': datetime.now() + timedelta(days=10),
            'status': 'processing'
        }
        
        self.rights_requests[request_id] = request_record
        
        # 정보주체 기록에 추가
        if subject_id in self.data_subjects:
            self.data_subjects[subject_id]['rights_exercised'].append(request_id)
        
        # 자동 응답 생성 (시뮬레이션)
        response_info = self._generate_information_response(subject_id)
        
        # 응답 완료 처리
        request_record['status'] = 'completed'
        request_record['response_provided'] = response_info
        request_record['completed_at'] = datetime.now()
        
        return request_id
    
    def _generate_information_response(self, subject_id: str) -> Dict:
        """정보 제공 응답 생성"""
        return {
            'processing_purposes': ['서비스 제공', '고객 지원', '법적 의무 이행'],
            'data_items': ['이름', '연락처', '서비스 이용기록'],
            'retention_period': '서비스 이용 종료 후 3년',
            'third_party_provision': '없음',
            'processing_outsourcing': '데이터 처리 전문업체 (보안서버 관리)',
            'subject_rights': [
                '열람권', '정정·삭제권', '처리정지권', '손해배상청구권'
            ],
            'contact_info': {
                'privacy_officer': '개인정보보호책임자',
                'email': 'privacy@company.com',
                'phone': '02-1234-5678'
            }
        }
    
    def manage_consent(self, subject_id: str, consent_action: str, consent_details: Dict) -> str:
        """동의 관리 (2번째 권리)"""
        consent_id = f"consent_{subject_id}_{int(datetime.now().timestamp())}"
        
        if consent_action == 'grant':
            # 동의 부여
            consent_record = {
                'consent_id': consent_id,
                'subject_id': subject_id,
                'action': 'granted',
                'purposes': consent_details.get('purposes', []),
                'data_items': consent_details.get('data_items', []),
                'third_party_provision': consent_details.get('third_party_provision', False),
                'marketing': consent_details.get('marketing', False),
                'granted_at': datetime.now(),
                'status': 'active'
            }
            
            result_message = f"동의 부여 완료: {consent_id}"
            
        elif consent_action == 'withdraw':
            # 동의 철회
            original_consent_id = consent_details.get('original_consent_id', '')
            
            if original_consent_id in self.consent_records:
                self.consent_records[original_consent_id]['status'] = 'withdrawn'
                self.consent_records[original_consent_id]['withdrawn_at'] = datetime.now()
                
                result_message = f"동의 철회 완료: {original_consent_id}"
            else:
                result_message = "철회할 동의를 찾을 수 없습니다"
                
            consent_record = {
                'consent_id': consent_id,
                'subject_id': subject_id,
                'action': 'withdrawn',
                'original_consent_id': original_consent_id,
                'withdrawn_at': datetime.now(),
                'status': 'completed'
            }
        else:
            return "잘못된 동의 액션입니다"
        
        self.consent_records[consent_id] = consent_record
        
        # 정보주체 기록에 추가
        if subject_id in self.data_subjects:
            self.data_subjects[subject_id]['consent_history'].append(consent_id)
        
        return result_message
    
    def request_access(self, subject_id: str, access_type: str) -> str:
        """열람권 행사 (3번째 권리)"""
        request_id = f"access_{subject_id}_{int(datetime.now().timestamp())}"
        
        access_record = {
            'request_id': request_id,
            'subject_id': subject_id,
            'access_type': access_type,  # 'status_check', 'data_copy', 'processing_history'
            'requested_at': datetime.now(),
            'response_deadline': datetime.now() + timedelta(days=10),
            'status': 'processing'
        }
        
        self.rights_requests[request_id] = access_record
        
        # 열람 정보 생성
        if access_type == 'status_check':
            access_info = self._generate_processing_status(subject_id)
        elif access_type == 'data_copy':
            access_info = self._generate_data_copy(subject_id)
        elif access_type == 'processing_history':
            access_info = self._generate_processing_history(subject_id)
        else:
            access_info = {'error': '지원하지 않는 열람 유형'}
        
        # 응답 완료
        access_record['status'] = 'completed'
        access_record['access_info_provided'] = access_info
        access_record['completed_at'] = datetime.now()
        
        # 정보주체 기록에 추가
        if subject_id in self.data_subjects:
            self.data_subjects[subject_id]['access_history'].append(request_id)
            self.data_subjects[subject_id]['rights_exercised'].append(request_id)
        
        return request_id
    
    def _generate_processing_status(self, subject_id: str) -> Dict:
        """개인정보 처리현황 생성"""
        return {
            'processing_status': '처리 중',
            'purposes': ['회원 관리', '서비스 제공', '고객 지원'],
            'data_items': ['이름', '이메일', '전화번호', '주소', '서비스 이용기록'],
            'collection_date': '2024-01-15',
            'retention_period': '회원 탈퇴 후 3년',
            'third_party_providers': '없음',
            'outsourcing_companies': ['클라우드 서비스 제공업체', '결제대행업체']
        }
    
    def _generate_data_copy(self, subject_id: str) -> Dict:
        """개인정보 사본 생성"""
        # 실제로는 암호화된 개인정보를 안전하게 제공
        return {
            'personal_data': {
                'name': '홍길동',
                'email': 'hong@example.com',
                'phone': '010-****-5678',  # 부분 마스킹
                'address': '서울시 ***구 ***동',  # 부분 마스킹
                'registration_date': '2024-01-15',
                'last_login': '2024-03-20'
            },
            'copy_generated_at': datetime.now().isoformat(),
            'security_note': '본 정보는 암호화되어 안전하게 전송됩니다'
        }
    
    def _generate_processing_history(self, subject_id: str) -> Dict:
        """개인정보 처리 이력 생성"""
        return {
            'collection_history': [
                {'date': '2024-01-15', 'purpose': '회원가입', 'items': ['이름', '이메일', '전화번호']},
                {'date': '2024-02-01', 'purpose': '서비스 개선', 'items': ['서비스 이용패턴']}
            ],
            'usage_history': [
                {'date': '2024-01-16', 'purpose': '서비스 제공', 'details': '계정 활성화'},
                {'date': '2024-02-15', 'purpose': '고객 지원', 'details': '문의사항 응답'}
            ],
            'sharing_history': [],  # 제3자 제공 없음
            'modification_history': [
                {'date': '2024-02-20', 'type': '주소 변경', 'requested_by': '정보주체'}
            ]
        }
    
    def request_rectification(self, subject_id: str, rectification_type: str, details: Dict) -> str:
        """정정·삭제·처리정지 요구 (4번째 권리)"""
        request_id = f"rectify_{subject_id}_{int(datetime.now().timestamp())}"
        
        rectification_record = {
            'request_id': request_id,
            'subject_id': subject_id,
            'rectification_type': rectification_type,  # 'correct', 'delete', 'stop_processing'
            'details': details,
            'requested_at': datetime.now(),
            'response_deadline': datetime.now() + timedelta(days=10),
            'status': 'processing'
        }
        
        self.rights_requests[request_id] = rectification_record
        
        # 요청 처리 시뮬레이션
        if rectification_type == 'correct':
            result = self._process_correction(subject_id, details)
        elif rectification_type == 'delete':
            result = self._process_deletion(subject_id, details)
        elif rectification_type == 'stop_processing':
            result = self._process_stop_processing(subject_id, details)
        else:
            result = {'status': 'error', 'message': '지원하지 않는 요청 유형'}
        
        # 완료 처리
        rectification_record['status'] = 'completed'
        rectification_record['processing_result'] = result
        rectification_record['completed_at'] = datetime.now()
        
        # 정보주체 기록에 추가
        if subject_id in self.data_subjects:
            self.data_subjects[subject_id]['rights_exercised'].append(request_id)
        
        return request_id
    
    def _process_correction(self, subject_id: str, details: Dict) -> Dict:
        """개인정보 정정 처리"""
        return {
            'status': 'completed',
            'corrected_items': details.get('items_to_correct', []),
            'correction_date': datetime.now().isoformat(),
            'message': '요청하신 개인정보 정정이 완료되었습니다'
        }
    
    def _process_deletion(self, subject_id: str, details: Dict) -> Dict:
        """개인정보 삭제 처리"""
        deletion_items = details.get('items_to_delete', [])
        
        # 삭제 가능 여부 확인
        legal_retention = ['법정 보존 의무', '계약 이행 필요', '분쟁 해결 필요']
        
        if any(item in legal_retention for item in deletion_items):
            return {
                'status': 'partial',
                'deleted_items': [item for item in deletion_items if item not in legal_retention],
                'retained_items': [item for item in deletion_items if item in legal_retention],
                'retention_reason': '법적 보존 의무',
                'message': '일부 개인정보는 법적 보존 의무로 인해 보존됩니다'
            }
        else:
            return {
                'status': 'completed',
                'deleted_items': deletion_items,
                'deletion_date': datetime.now().isoformat(),
                'message': '요청하신 개인정보 삭제가 완료되었습니다'
            }
    
    def _process_stop_processing(self, subject_id: str, details: Dict) -> Dict:
        """개인정보 처리정지 처리"""
        return {
            'status': 'completed',
            'stopped_processing': details.get('processing_to_stop', []),
            'stop_date': datetime.now().isoformat(),
            'message': '요청하신 개인정보 처리정지가 완료되었습니다'
        }
    
    def file_remedy_request(self, subject_id: str, remedy_type: str, incident_details: Dict) -> str:
        """피해구제 요청 (5번째 권리)"""
        remedy_id = f"remedy_{subject_id}_{int(datetime.now().timestamp())}"
        
        remedy_record = {
            'remedy_id': remedy_id,
            'subject_id': subject_id,
            'remedy_type': remedy_type,  # 'compensation', 'mediation', 'complaint'
            'incident_details': incident_details,
            'filed_at': datetime.now(),
            'response_deadline': datetime.now() + timedelta(days=30),
            'status': 'investigating'
        }
        
        self.remedy_cases[remedy_id] = remedy_record
        
        # 정보주체 기록에 추가
        if subject_id in self.data_subjects:
            self.data_subjects[subject_id]['rights_exercised'].append(remedy_id)
        
        return remedy_id
    
    def demonstrate_subject_rights(self):
        """정보주체 권리 시연"""
        print("=== 정보주체의 5대 권리 행사 시연 ===\n")
        
        # 정보주체 등록
        subject_info = {
            'name': '김정보',
            'email': 'kim@example.com',
            'phone': '010-1234-5678'
        }
        
        subject_id = 'subject_001'
        print(f"1. {self.register_data_subject(subject_id, subject_info)}")
        
        # 1번째 권리: 정보 제공 요구
        info_request = {
            'requested_info': ['처리목적', '처리항목', '보유기간', '제3자제공현황']
        }
        
        request_id = self.request_information_provision(subject_id, info_request)
        print(f"2. 정보 제공 요구 완료: {request_id}")
        
        if request_id in self.rights_requests:
            response = self.rights_requests[request_id]['response_provided']
            print(f"   제공된 정보: 처리목적 {len(response['processing_purposes'])}개, 처리항목 {len(response['data_items'])}개")
        
        # 2번째 권리: 동의 관리
        consent_details = {
            'purposes': ['서비스 제공', '마케팅'],
            'data_items': ['이름', '이메일', '전화번호'],
            'marketing': True
        }
        
        consent_result = self.manage_consent(subject_id, 'grant', consent_details)
        print(f"3. {consent_result}")
        
        # 3번째 권리: 열람권 행사
        access_id = self.request_access(subject_id, 'processing_history')
        print(f"4. 개인정보 처리이력 열람 요청 완료: {access_id}")
        
        # 4번째 권리: 정정·삭제 요구
        rectification_details = {
            'items_to_correct': ['전화번호'],
            'new_values': {'전화번호': '010-9876-5432'}
        }
        
        rectify_id = self.request_rectification(subject_id, 'correct', rectification_details)
        print(f"5. 개인정보 정정 요청 완료: {rectify_id}")
        
        # 5번째 권리: 피해구제 요청 (예시)
        incident_details = {
            'incident_type': '개인정보 유출',
            'incident_date': '2024-03-15',
            'damage_description': '개인정보 유출로 인한 스팸 메일 증가',
            'requested_remedy': '손해배상'
        }
        
        remedy_id = self.file_remedy_request(subject_id, 'compensation', incident_details)
        print(f"6. 피해구제 요청 완료: {remedy_id}")
        
        # 전체 권리 행사 내역
        print(f"\n📊 권리 행사 현황:")
        if subject_id in self.data_subjects:
            rights_count = len(self.data_subjects[subject_id]['rights_exercised'])
            print(f"   총 권리 행사: {rights_count}건")
            
            print(f"   세부 내역:")
            for right_type, details in self.rights_details.items():
                print(f"     • {right_type.value}: {details['description']}")

class PersonalDataProtectionGuidelines:
    """개인정보보호 가이드라인"""
    
    def __init__(self):
        # 개인정보보호 오남용 피해방지 10계명
        self.protection_commandments = [
            {
                'number': 1,
                'title': '개인정보 처리방침 및 이용 약관 꼼꼼히 살피기',
                'description': '서비스 이용 전 개인정보 처리방침과 이용약관을 반드시 확인',
                'details': [
                    '수집하는 개인정보 항목 확인',
                    '개인정보 이용 목적 확인',
                    '개인정보 보유 및 이용기간 확인',
                    '제3자 제공 현황 확인'
                ]
            },
            {
                'number': 2,
                'title': '비밀번호는 문자와 숫자로 10자리(문자+숫자+특수문자 8자리) 이상으로 설정',
                'description': '안전한 비밀번호로 개인정보 보호',
                'details': [
                    '영문 대소문자, 숫자, 특수문자 조합',
                    '개인정보와 관련없는 비밀번호 사용',
                    '서비스별로 다른 비밀번호 사용',
                    '추측하기 어려운 복잡한 조합 선택'
                ]
            },
            {
                'number': 3,
                'title': '비밀번호는 주기적으로 변경하기(최소 6개월)',
                'description': '정기적인 비밀번호 변경으로 보안 강화',
                'details': [
                    '6개월마다 비밀번호 변경',
                    '이전 비밀번호와 다른 새로운 비밀번호 사용',
                    '비밀번호 변경 알림 서비스 활용',
                    '의심스러운 접근 시 즉시 변경'
                ]
            },
            {
                'number': 4,
                'title': '회원가입은 주민등록번호 대신 I-PIN 사용',
                'description': '고유식별정보 보호를 위한 대체 인증수단 활용',
                'details': [
                    'I-PIN(Internet Personal Identification Number) 활용',
                    '휴대폰 본인인증 서비스 이용',
                    '공인인증서 활용',
                    '주민번호 제공 최소화'
                ]
            },
            {
                'number': 5,
                'title': '명의도용 확인 서비스 이용하여 가입정보 확인',
                'description': '본인 명의로 가입된 서비스 정기 확인',
                'details': [
                    '인터넷 명의도용 확인 서비스 정기 이용',
                    '본인 명의 휴대폰 가입현황 확인',
                    '신용정보 조회 서비스 활용',
                    '의심스러운 가입 내역 발견 시 즉시 신고'
                ]
            },
            {
                'number': 6,
                'title': '개인정보는 친구에게도 알려주지 않기',
                'description': '개인정보의 철저한 보호 관리',
                'details': [
                    '비밀번호, 주민번호 등 타인에게 제공 금지',
                    '금융 관련 정보 절대 공유 금지',
                    '가족에게도 필요시에만 제한적 공유',
                    '개인정보 관련 대화 시 주변 확인'
                ]
            },
            {
                'number': 7,
                'title': 'P2P 공유 폴더에 개인정보 저장하지 않기',
                'description': '파일 공유 프로그램 사용 시 개인정보 보호',
                'details': [
                    'P2P 공유 폴더와 개인정보 저장 폴더 분리',
                    '개인정보가 포함된 파일의 공유 방지',
                    'P2P 프로그램 사용 시 보안 설정 확인',
                    '개인정보 파일 암호화 보관'
                ]
            },
            {
                'number': 8,
                'title': '금융거래는 PC방에서 이용하지 않기',
                'description': '공공장소에서의 금융거래 지양',
                'details': [
                    'PC방, 공공 와이파이에서 금융거래 금지',
                    '개인 기기에서만 금융거래 수행',
                    '금융거래 후 로그아웃 및 브라우저 종료',
                    '금융거래 내역 정기 확인'
                ]
            },
            {
                'number': 9,
                'title': '출처가 불명확한 자료는 다운로드 금지',
                'description': '악성코드 및 개인정보 탈취 방지',
                'details': [
                    '신뢰할 수 있는 사이트에서만 파일 다운로드',
                    '이메일 첨부파일 주의',
                    '백신 프로그램으로 검사 후 실행',
                    '의심스러운 링크 클릭 금지'
                ]
            },
            {
                'number': 10,
                'title': '개인정보 침해신고 적극 활용하기',
                'description': '개인정보 침해 시 신속한 신고 및 대응',
                'details': [
                    '개인정보보호위원회 privacy.go.kr 활용',
                    '개인정보 침해신고센터(privacy.go.kr) 신고',
                    '개인정보 유출 의심 시 즉시 신고',
                    '피해구제 절차 적극 활용'
                ]
            }
        ]
        
        # 국가와 지방자치단체의 개인정보보호 의무
        self.government_obligations = [
            {
                'obligation': '개인정보 목적 외 수집, 오용·남용 및 무분별한 감시·추적 등에 따른 폐해 방지',
                'description': '인간의 존엄과 개인의 사생활 보호를 도모하기 위한 시책 강구',
                'implementation': [
                    '개인정보 처리 가이드라인 제정',
                    '개인정보보호 교육 실시',
                    '개인정보 감시체계 구축',
                    '개인정보 오남용 방지 제도 운영'
                ]
            },
            {
                'obligation': '정보주체의 권리를 보호하기 위한 법령 개선 등 필요한 시책 마련',
                'description': '정보주체의 권리 보장을 위한 제도적 기반 구축',
                'implementation': [
                    '개인정보보호 관련 법령 정비',
                    '정보주체 권리 보장 체계 구축',
                    '개인정보보호 분쟁조정 제도 운영',
                    '개인정보보호 인식 제고 활동'
                ]
            },
            {
                'obligation': '개인정보 처리에 관한 불합리한 사회적 관행 개선',
                'description': '개인정보처리자의 자율적인 개인정보보호활동 존중 및 촉진·지원',
                'implementation': [
                    '개인정보보호 우수기업 인증 제도',
                    '개인정보보호 관리체계 인증(PIMS) 활성화',
                    '민간 자율규제 지원',
                    '개인정보보호 모범사례 확산'
                ]
            },
            {
                'obligation': '개인정보 처리에 관한 법령 또는 조례 제정·개정 시 본 법의 목적 부합',
                'description': '개인정보보호법의 목적과 원칙에 부합하는 법령 체계 구축',
                'implementation': [
                    '신규 법령 제정 시 개인정보보호 영향 검토',
                    '기존 법령의 개인정보보호 조항 점검',
                    '지방자치단체 조례 가이드라인 제공',
                    '법령 간 상충 방지 체계 운영'
                ]
            }
        ]
    
    def display_protection_commandments(self):
        """개인정보보호 10계명 표시"""
        print("=== 개인정보 보호 오남용 피해방지 10계명 ===\n")
        
        for commandment in self.protection_commandments:
            print(f"📋 {commandment['number']}. {commandment['title']}")
            print(f"   설명: {commandment['description']}")
            print(f"   세부사항:")
            for detail in commandment['details']:
                print(f"     • {detail}")
            print()
        
        # 실천 방법 요약
        print("💡 실천 포인트:")
        practice_points = [
            "사전 확인: 개인정보 처리방침 숙지",
            "보안 강화: 안전한 비밀번호 설정 및 관리",
            "대체 수단: 주민번호 대신 I-PIN 등 활용",
            "정기 점검: 명의도용 여부 확인",
            "신중한 공유: 개인정보 공유 최소화",
            "안전한 환경: 신뢰할 수 있는 환경에서만 거래",
            "적극적 대응: 침해 의심 시 즉시 신고"
        ]
        
        for point in practice_points:
            print(f"   ✓ {point}")
    
    def display_government_obligations(self):
        """국가·지방자치단체 의무 표시"""
        print(f"\n=== 국가와 지방자치단체의 개인정보보호 의무 ===\n")
        
        for i, obligation in enumerate(self.government_obligations, 1):
            print(f"🏛️ {i}. {obligation['obligation']}")
            print(f"   목적: {obligation['description']}")
            print(f"   시행 방안:")
            for impl in obligation['implementation']:
                print(f"     • {impl}")
            print()

# 실행 예시
def demo_subject_rights():
    print("👤 정보주체의 권리와 개인정보보호 가이드라인")
    print("=" * 60)
    
    # 정보주체 권리 시연
    rights_manager = DataSubjectRightsManagement()
    rights_manager.demonstrate_subject_rights()
    
    print("\n" + "=" * 60)
    
    # 개인정보보호 가이드라인
    guidelines = PersonalDataProtectionGuidelines()
    guidelines.display_protection_commandments()
    guidelines.display_government_obligations()

if __name__ == "__main__":
    demo_subject_rights()
```

### 2. 개인정보 수집·이용 및 제공

#### 개인정보 처리 단계별 요구사항

```python
#!/usr/bin/env python3
# 개인정보 수집·이용·제공 관리 시스템

from datetime import datetime, timedelta
from enum import Enum
import json
from typing import Dict, List, Optional, Union

class ProcessingPhase(Enum):
    """개인정보 처리 단계"""
    COLLECTION = "수집"
    USE = "이용" 
    PROVISION = "제공"
    CONSIGNMENT = "위탁"
    DESTRUCTION = "파기"

class ConsentType(Enum):
    """동의 유형"""
    REQUIRED = "필수"
    OPTIONAL = "선택"
    SEPARATE = "별도"
    LEGAL_BASIS = "법적근거"

class PersonalDataProcessingManager:
    """개인정보 처리 관리 시스템"""
    
    def __init__(self):
        self.processing_purposes = {}
        self.collected_data = {}
        self.consent_records = {}
        self.provision_records = {}
        self.consignment_records = {}
        
        # 처리 단계별 요구사항
        self.processing_requirements = {
            ProcessingPhase.COLLECTION: {
                'legal_basis': [
                    '정보주체의 동의',
                    '법률의 특별한 규정',
                    '법령상 의무의 이행',
                    '정보주체의 중요한 이익',
                    '개인정보처리자의 정당한 이익'
                ],
                'consent_elements': [
                    '개인정보 수집·이용 목적',
                    '수집하는 개인정보의 항목',
                    '개인정보의 보유 및 이용기간',
                    '동의를 거부할 권리가 있다는 사실',
                    '동의거부에 따른 불이익 내용'
                ],
                'principles': [
                    '목적에 필요한 최소한의 개인정보 수집',
                    '수집 목적의 명확한 고지',
                    '정보주체의 동의 획득',
                    '적법하고 정당한 수단에 의한 수집'
                ]
            },
            ProcessingPhase.USE: {
                'principles': [
                    '수집 목적 범위 내에서만 이용',
                    '목적 외 이용 시 별도 동의 필요',
                    '정확성·완전성·최신성 보장',
                    '안전성 확보조치 이행'
                ],
                'exceptions': [
                    '법률에 특별한 규정이 있는 경우',
                    '정보주체의 생명·신체·재산의 이익을 위해 필요한 경우',
                    '공공기관이 법령 등에서 정하는 소관업무 수행을 위해 필요한 경우',
                    '통계작성 및 학술연구를 위해 필요한 경우'
                ]
            },
            ProcessingPhase.PROVISION: {
                'consent_requirements': [
                    '개인정보를 제공받는 자',
                    '개인정보의 이용 목적',
                    '이용·제공하는 개인정보의 항목',
                    '개인정보의 보유 및 이용기간',
                    '동의를 거부할 권리 및 불이익'
                ],
                'record_keeping': [
                    '개인정보를 제공받는 자',
                    '개인정보 제공 목적 및 이용목적',
                    '제공하는 개인정보의 항목',
                    '제공 방법',
                    '개인정보를 제공받는 자의 개인정보 보유기간',
                    '제공 근거'
                ]
            }
        }
        
        # 민감정보 처리 특별 요구사항
        self.sensitive_data_requirements = {
            'categories': [
                '사상, 신념',
                '노동조합·정당의 가입·탈퇴',
                '정치적 견해',
                '건강, 성생활',
                '그 밖에 정보주체의 사생활을 현저히 침해할 우려가 있는 정보'
            ],
            'processing_requirements': [
                '정보주체의 별도 동의 필요',
                '법률에서 민감정보 처리를 요구하거나 허용하는 경우만 처리',
                '안전성 확보조치 강화',
                '처리 현황 공개'
            ]
        }
    
    def collect_personal_data(self, data_subject_id: str, collection_details: Dict) -> str:
        """개인정보 수집"""
        collection_id = f"collect_{data_subject_id}_{int(datetime.now().timestamp())}"
        
        # 수집 요구사항 검증
        validation_result = self._validate_collection(collection_details)
        
        if not validation_result['valid']:
            return f"수집 실패: {validation_result['reason']}"
        
        # 동의 확인
        consent_result = self._obtain_collection_consent(data_subject_id, collection_details)
        
        collection_record = {
            'collection_id': collection_id,
            'data_subject_id': data_subject_id,
            'purposes': collection_details['purposes'],
            'data_items': collection_details['data_items'],
            'collection_method': collection_details.get('collection_method', 'direct'),
            'legal_basis': collection_details.get('legal_basis', '정보주체의 동의'),
            'retention_period': collection_details['retention_period'],
            'consent_id': consent_result['consent_id'] if consent_result['obtained'] else None,
            'collected_at': datetime.now(),
            'is_sensitive': self._check_sensitive_data(collection_details['data_items']),
            'status': 'active'
        }
        
        self.collected_data[collection_id] = collection_record
        
        return collection_id
    
    def _validate_collection(self, collection_details: Dict) -> Dict:
        """수집 요구사항 검증"""
        # 필수 요소 확인
        required_elements = ['purposes', 'data_items', 'retention_period']
        
        for element in required_elements:
            if element not in collection_details:
                return {'valid': False, 'reason': f'{element} 누락'}
        
        # 최소성 원칙 확인 (시뮬레이션)
        purposes = collection_details['purposes']
        data_items = collection_details['data_items']
        
        # 목적과 수집항목 간 적절성 확인
        essential_items = self._get_essential_items(purposes)
        excessive_items = [item for item in data_items if item not in essential_items]
        
        if excessive_items:
            return {
                'valid': False, 
                'reason': f'목적에 불필요한 항목 포함: {excessive_items}'
            }
        
        return {'valid': True}
    
    def _get_essential_items(self, purposes: List[str]) -> List[str]:
        """목적별 필수 수집항목 반환"""
        essential_mapping = {
            '회원관리': ['이름', '이메일', '전화번호'],
            '서비스 제공': ['이름', '연락처', '서비스 이용기록'],
            '마케팅': ['이름', '연락처'],
            '고객지원': ['이름', '연락처', '문의내용'],
            '법적 의무 이행': ['이름', '주민등록번호', '주소']
        }
        
        essential_items = set()
        for purpose in purposes:
            if purpose in essential_mapping:
                essential_items.update(essential_mapping[purpose])
        
        return list(essential_items)
    
    def _obtain_collection_consent(self, data_subject_id: str, collection_details: Dict) -> Dict:
        """수집 동의 획득"""
        # 법적 근거가 동의인 경우만 동의 획득
        legal_basis = collection_details.get('legal_basis', '정보주체의 동의')
        
        if legal_basis != '정보주체의 동의':
            return {'obtained': False, 'reason': '법적 근거로 처리'}
        
        consent_id = f"consent_{data_subject_id}_{int(datetime.now().timestamp())}"
        
        consent_record = {
            'consent_id': consent_id,
            'data_subject_id': data_subject_id,
            'consent_type': 'collection',
            'purposes': collection_details['purposes'],
            'data_items': collection_details['data_items'],
            'retention_period': collection_details['retention_period'],
            'sensitive_data': self._check_sensitive_data(collection_details['data_items']),
            'marketing_consent': 'marketing' in collection_details['purposes'],
            'obtained_at': datetime.now(),
            'method': collection_details.get('consent_method', 'online'),
            'status': 'active'
        }
        
        self.consent_records[consent_id] = consent_record
        
        return {'obtained': True, 'consent_id': consent_id}
    
    def _check_sensitive_data(self, data_items: List[str]) -> bool:
        """민감정보 포함 여부 확인"""
        sensitive_keywords = [
            '종교', '사상', '신념', '정치', '건강', '성생활', '장애', 
            '병력', '진료', '유전', '범죄', '노동조합', '정당'
        ]
        
        for item in data_items:
            if any(keyword in item for keyword in sensitive_keywords):
                return True
        
        return False
    
    def provide_to_third_party(self, collection_id: str, provision_details: Dict) -> str:
        """제3자 제공"""
        provision_id = f"provide_{collection_id}_{int(datetime.now().timestamp())}"
        
        if collection_id not in self.collected_data:
            return "제공 실패: 수집 기록을 찾을 수 없음"
        
        collection_record = self.collected_data[collection_id]
        
        # 제공 동의 확인
        provision_consent = self._obtain_provision_consent(
            collection_record['data_subject_id'], 
            provision_details
        )
        
        provision_record = {
            'provision_id': provision_id,
            'collection_id': collection_id,
            'recipient': provision_details['recipient'],
            'purpose': provision_details['purpose'],
            'provided_items': provision_details['provided_items'],
            'provision_method': provision_details.get('method', 'electronic'),
            'recipient_retention_period': provision_details['recipient_retention_period'],
            'legal_basis': provision_details.get('legal_basis', '정보주체의 동의'),
            'consent_id': provision_consent['consent_id'] if provision_consent['obtained'] else None,
            'provided_at': datetime.now(),
            'status': 'active'
        }
        
        self.provision_records[provision_id] = provision_record
        
        # 수집 기록에 제공 이력 추가
        if 'provision_history' not in collection_record:
            collection_record['provision_history'] = []
        collection_record['provision_history'].append(provision_id)
        
        return provision_id
    
    def _obtain_provision_consent(self, data_subject_id: str, provision_details: Dict) -> Dict:
        """제3자 제공 동의 획득"""
        consent_id = f"provision_consent_{data_subject_id}_{int(datetime.now().timestamp())}"
        
        consent_record = {
            'consent_id': consent_id,
            'data_subject_id': data_subject_id,
            'consent_type': 'provision',
            'recipient': provision_details['recipient'],
            'purpose': provision_details['purpose'],
            'provided_items': provision_details['provided_items'],
            'recipient_retention_period': provision_details['recipient_retention_period'],
            'obtained_at': datetime.now(),
            'status': 'active'
        }
        
        self.consent_records[consent_id] = consent_record
        
        return {'obtained': True, 'consent_id': consent_id}
    
    def consign_processing(self, collection_id: str, consignment_details: Dict) -> str:
        """개인정보 처리 위탁"""
        consignment_id = f"consign_{collection_id}_{int(datetime.now().timestamp())}"
        
        if collection_id not in self.collected_data:
            return "위탁 실패: 수집 기록을 찾을 수 없음"
        
        # 위탁 계약서 요구사항 확인
        contract_elements = self._validate_consignment_contract(consignment_details)
        
        consignment_record = {
            'consignment_id': consignment_id,
            'collection_id': collection_id,
            'consignee': consignment_details['consignee'],
            'consignment_purpose': consignment_details['purpose'],
            'consigned_items': consignment_details['consigned_items'],
            'contract_elements': contract_elements,
            'supervision_plan': consignment_details.get('supervision_plan', {}),
            'consigned_at': datetime.now(),
            'status': 'active'
        }
        
        self.consignment_records[consignment_id] = consignment_record
        
        return consignment_id
    
    def _validate_consignment_contract(self, consignment_details: Dict) -> Dict:
        """위탁 계약 요소 확인"""
        required_contract_elements = [
            '위탁업무의 목적과 범위',
            '재위탁 제한에 관한 사항',
            '개인정보의 기술적·관리적 보호조치',
            '위탁업무와 관련하여 보유하고 있는 개인정보의 관리현황 점검',
            '수탁자가 준수하여야 할 의무',
            '개인정보의 안전관리를 위한 수탁자의 교육',
            '손해배상 등 책임에 관한 사항'
        ]
        
        return {
            'required_elements': required_contract_elements,
            'contract_date': datetime.now().isoformat(),
            'review_status': 'completed'
        }
    
    def generate_consent_form(self, collection_details: Dict) -> Dict:
        """동의서 양식 생성"""
        consent_form = {
            'title': '개인정보 수집·이용 동의서',
            'sections': {
                '1. 개인정보 수집·이용 목적': {
                    'content': ', '.join(collection_details['purposes']),
                    'required': True
                },
                '2. 수집하는 개인정보의 항목': {
                    'content': ', '.join(collection_details['data_items']),
                    'required': True
                },
                '3. 개인정보의 보유 및 이용기간': {
                    'content': collection_details['retention_period'],
                    'required': True
                },
                '4. 동의를 거부할 권리 및 불이익': {
                    'content': '정보주체는 개인정보 수집·이용에 대한 동의를 거부할 권리가 있으며, 동의 거부 시 서비스 이용이 제한될 수 있습니다.',
                    'required': True
                }
            },
            'consent_options': {
                '필수 동의': {
                    'items': [item for item in collection_details['data_items'] 
                             if self._is_essential_item(item, collection_details['purposes'])],
                    'required': True
                },
                '선택 동의': {
                    'items': [item for item in collection_details['data_items'] 
                             if not self._is_essential_item(item, collection_details['purposes'])],
                    'required': False
                }
            },
            'signature_section': {
                'date': '년    월    일',
                'signature': '동의자 성명:                 (서명 또는 인)',
                'checkbox': '☐ 위의 개인정보 수집·이용에 동의합니다.'
            }
        }
        
        # 민감정보 포함 시 별도 동의 섹션 추가
        if self._check_sensitive_data(collection_details['data_items']):
            consent_form['sections']['5. 민감정보 처리 동의'] = {
                'content': '민감정보 처리에 대해 별도로 동의하며, 민감정보는 더욱 엄격하게 보호됩니다.',
                'required': True
            }
            consent_form['signature_section']['sensitive_checkbox'] = '☐ 민감정보 처리에 동의합니다.'
        
        return consent_form
    
    def _is_essential_item(self, item: str, purposes: List[str]) -> bool:
        """필수 수집항목 여부 판단"""
        essential_for_service = ['이름', '이메일', '전화번호']
        return item in essential_for_service
    
    def demonstrate_processing_lifecycle(self):
        """개인정보 처리 생애주기 시연"""
        print("=== 개인정보 처리 생애주기 시연 ===\n")
        
        # 1. 개인정보 수집
        collection_details = {
            'purposes': ['회원관리', '서비스 제공', '고객지원'],
            'data_items': ['이름', '이메일', '전화번호', '주소', '서비스 이용기록'],
            'retention_period': '회원 탈퇴 시까지',
            'collection_method': 'direct',
            'legal_basis': '정보주체의 동의',
            'consent_method': 'online'
        }
        
        subject_id = 'user_001'
        collection_id = self.collect_personal_data(subject_id, collection_details)
        print(f"1. 개인정보 수집 완료: {collection_id}")
        
        if collection_id.startswith('collect_'):
            collection_record = self.collected_data[collection_id]
            print(f"   수집 목적: {', '.join(collection_record['purposes'])}")
            print(f"   수집 항목: {', '.join(collection_record['data_items'])}")
            print(f"   민감정보 포함: {'예' if collection_record['is_sensitive'] else '아니오'}")
        
        # 2. 동의서 양식 생성
        consent_form = self.generate_consent_form(collection_details)
        print(f"\n2. 동의서 양식 생성 완료")
        print(f"   필수 동의 항목: {len(consent_form['consent_options']['필수 동의']['items'])}개")
        print(f"   선택 동의 항목: {len(consent_form['consent_options']['선택 동의']['items'])}개")
        
        # 3. 제3자 제공
        provision_details = {
            'recipient': '배송업체',
            'purpose': '상품 배송',
            'provided_items': ['이름', '전화번호', '주소'],
            'recipient_retention_period': '배송 완료 후 1개월',
            'method': 'electronic',
            'legal_basis': '정보주체의 동의'
        }
        
        provision_id = self.provide_to_third_party(collection_id, provision_details)
        print(f"\n3. 제3자 제공 완료: {provision_id}")
        
        if provision_id.startswith('provide_'):
            provision_record = self.provision_records[provision_id]
            print(f"   제공받는 자: {provision_record['recipient']}")
            print(f"   제공 목적: {provision_record['purpose']}")
            print(f"   제공 항목: {', '.join(provision_record['provided_items'])}")
        
        # 4. 처리 위탁
        consignment_details = {
            'consignee': '클라우드 서비스 제공업체',
            'purpose': '개인정보 저장 및 관리',
            'consigned_items': ['이름', '이메일', '서비스 이용기록'],
            'supervision_plan': {
                'monitoring_frequency': '월 1회',
                'security_audit': '분기별',
                'contract_review': '연 1회'
            }
        }
        
        consignment_id = self.consign_processing(collection_id, consignment_details)
        print(f"\n4. 처리 위탁 완료: {consignment_id}")
        
        if consignment_id.startswith('consign_'):
            consignment_record = self.consignment_records[consignment_id]
            print(f"   수탁자: {consignment_record['consignee']}")
            print(f"   위탁 목적: {consignment_record['consignment_purpose']}")
            print(f"   위탁 항목: {', '.join(consignment_record['consigned_items'])}")
        
        # 처리 현황 요약
        print(f"\n📊 처리 현황 요약:")
        print(f"   수집 기록: {len(self.collected_data)}건")
        print(f"   동의 기록: {len(self.consent_records)}건")
        print(f"   제3자 제공: {len(self.provision_records)}건")
        print(f"   처리 위탁: {len(self.consignment_records)}건")

class PersonalDataCollectionGuidelines:
    """개인정보 수집 가이드라인"""
    
    def __init__(self):
        self.collection_principles = {
            '최소수집 원칙': {
                'description': '처리 목적에 필요한 최소한의 개인정보만 수집',
                'implementation': [
                    '수집 목적과 직접 관련된 항목만 수집',
                    '선택적 수집항목과 필수 수집항목 구분',
                    '정기적인 수집항목 적정성 검토',
                    '불필요한 항목 수집 금지'
                ],
                'examples': {
                    '적절한 수집': '온라인 쇼핑몰에서 주문 처리를 위한 이름, 연락처, 배송지 수집',
                    '부적절한 수집': '온라인 쇼핑몰에서 종교, 정치 성향 등 불필요한 정보 수집'
                }
            },
            '목적 명시 원칙': {
                'description': '개인정보 수집 시 구체적이고 명확한 목적 고지',
                'implementation': [
                    '구체적이고 명확한 수집목적 명시',
                    '포괄적이고 추상적인 목적 표현 금지',
                    '수집 시점에 목적 고지',
                    '목적 변경 시 재동의 획득'
                ],
                'examples': {
                    '적절한 명시': '회원 관리, 서비스 제공, 고객 상담을 위해 수집',
                    '부적절한 명시': '기타 부가 서비스 제공 등을 위해 수집'
                }
            },
            '동의 획득 원칙': {
                'description': '개인정보 수집 전 정보주체의 동의 획득',
                'implementation': [
                    '사전 고지 및 동의 획득',
                    '명확하고 구체적인 동의 내용',
                    '자유로운 의사에 의한 동의',
                    '동의 철회권 보장'
                ],
                'exceptions': [
                    '법률에 특별한 규정이 있는 경우',
                    '법령상 의무를 이행하기 위해 불가피한 경우',
                    '정보주체의 중요한 이익을 위해 필요한 경우'
                ]
            }
        }
        
        # 수집 방법별 주의사항
        self.collection_methods = {
            '직접 수집': {
                'definition': '정보주체로부터 직접 개인정보를 수집',
                'examples': ['회원가입', '설문조사', '상담신청'],
                'requirements': [
                    '수집 전 동의 획득',
                    '수집목적, 항목, 기간 고지',
                    '동의거부권 및 불이익 고지'
                ]
            },
            '간접 수집': {
                'definition': '정보주체가 아닌 제3자로부터 개인정보를 수집',
                'examples': ['제휴사로부터 정보 제공', '공개된 정보 수집'],
                'requirements': [
                    '수집 출처 고지',
                    '수집 목적 및 이용계획 고지',
                    '정보주체 권리 및 행사방법 고지',
                    '개인정보보호책임자 연락처 고지'
                ]
            },
            '생성 정보 수집': {
                'definition': '서비스 이용 과정에서 자동으로 생성되는 정보 수집',
                'examples': ['접속로그', '쿠키', '이용기록'],
                'requirements': [
                    '자동 수집 사실 고지',
                    '수집되는 정보의 종류 명시',
                    '이용 목적 및 거부 방법 안내'
                ]
            }
        }
    
    def display_collection_guidelines(self):
        """개인정보 수집 가이드라인 표시"""
        print("=== 개인정보 수집 가이드라인 ===\n")
        
        for principle_name, details in self.collection_principles.items():
            print(f"📋 {principle_name}")
            print(f"   정의: {details['description']}")
            
            print(f"   실행 방안:")
            for impl in details['implementation']:
                print(f"     • {impl}")
            
            if 'examples' in details:
                print(f"   사례:")
                for example_type, example in details['examples'].items():
                    print(f"     {example_type}: {example}")
            
            if 'exceptions' in details:
                print(f"   예외사항:")
                for exception in details['exceptions']:
                    print(f"     • {exception}")
            
            print()
        
        print("=" * 60)
        print("수집 방법별 주의사항:\n")
        
        for method_name, details in self.collection_methods.items():
            print(f"🔍 {method_name}")
            print(f"   정의: {details['definition']}")
            print(f"   예시: {', '.join(details['examples'])}")
            print(f"   요구사항:")
            for req in details['requirements']:
                print(f"     • {req}")
            print()

class PersonalDataUsageAndProvision:
    """개인정보 이용 및 제공 관리"""
    
    def __init__(self):
        # 목적 외 이용·제공 요건
        self.purpose_beyond_requirements = {
            '정보주체 동의': {
                'description': '정보주체로부터 별도의 동의를 받은 경우',
                'procedure': [
                    '목적 외 이용·제공 사실 고지',
                    '이용·제공받는 자 명시',
                    '이용·제공 목적 명확히 제시',
                    '이용·제공할 개인정보 항목 명시',
                    '동의거부권 및 불이익 고지'
                ]
            },
            '법률 특별규정': {
                'description': '다른 법률에 특별한 규정이 있는 경우',
                'examples': [
                    '국세기본법에 따른 세무조사',
                    '형사소송법에 따른 수사',
                    '금융실명거래법에 따른 자료제출'
                ]
            },
            '생명·신체·재산 보호': {
                'description': '정보주체 또는 제3자의 급박한 생명, 신체, 재산의 이익을 위해 필요한 경우',
                'conditions': [
                    '급박한 위험 상황',
                    '정보주체의 사전 동의가 불가능한 상황',
                    '다른 방법으로는 보호가 어려운 경우'
                ]
            },
            '공공기관 소관업무': {
                'description': '공공기관이 법령 등에서 정하는 소관업무 수행을 위해 필요한 경우',
                'limitations': [
                    '소관업무와 직접 관련',
                    '필요 최소한의 범위',
                    '정보주체의 권리침해 최소화'
                ]
            },
            '통계·연구 목적': {
                'description': '통계작성 및 학술연구 등의 목적을 위해 필요한 경우',
                'conditions': [
                    '특정 개인을 알아볼 수 없는 형태로 가공',
                    '통계 또는 연구 목적으로만 이용',
                    '제3자에게 제공 시 가명처리'
                ]
            }
        }
        
        # 제3자 제공 시 기록·보관 사항
        self.provision_record_requirements = [
            '개인정보를 제공받은 자',
            '개인정보를 제공한 목적',
            '제3자가 이용할 목적',
            '제공한 개인정보의 항목',
            '개인정보를 제공받은 자의 개인정보 보유·이용기간',
            '제공 방법',
            '제공 근거',
            '제공 일시'
        ]
    
    def analyze_purpose_beyond_case(self, case_details: Dict) -> Dict:
        """목적 외 이용·제공 사례 분석"""
        analysis_result = {
            'case_summary': case_details.get('summary', ''),
            'original_purpose': case_details.get('original_purpose', ''),
            'intended_use': case_details.get('intended_use', ''),
            'applicable_requirements': [],
            'compliance_status': 'pending',
            'recommendations': []
        }
        
        intended_use = case_details.get('intended_use', '').lower()
        
        # 적용 가능한 요건 분석
        if '동의' in intended_use or case_details.get('consent_obtained', False):
            analysis_result['applicable_requirements'].append('정보주체 동의')
            
        if '법률' in intended_use or '수사' in intended_use or '세무' in intended_use:
            analysis_result['applicable_requirements'].append('법률 특별규정')
            
        if '응급' in intended_use or '생명' in intended_use or '안전' in intended_use:
            analysis_result['applicable_requirements'].append('생명·신체·재산 보호')
            
        if '통계' in intended_use or '연구' in intended_use:
            analysis_result['applicable_requirements'].append('통계·연구 목적')
            
        if '공공기관' in case_details.get('requestor', ''):
            analysis_result['applicable_requirements'].append('공공기관 소관업무')
        
        # 준수 상태 판정
        if analysis_result['applicable_requirements']:
            analysis_result['compliance_status'] = 'compliant'
            analysis_result['recommendations'].append('적용 요건에 따라 처리 가능')
        else:
            analysis_result['compliance_status'] = 'non_compliant'
            analysis_result['recommendations'].extend([
                '정보주체의 별도 동의 필요',
                '목적 외 이용·제공 불가'
            ])
        
        return analysis_result
    
    def demonstrate_purpose_beyond_analysis(self):
        """목적 외 이용·제공 분석 시연"""
        print("=== 목적 외 이용·제공 분석 ===\n")
        
        test_cases = [
            {
                'summary': '온라인 쇼핑몰 고객정보를 마케팅 업체에 제공',
                'original_purpose': '상품 주문 처리',
                'intended_use': '마케팅 목적 이용',
                'requestor': '마케팅 전문업체',
                'consent_obtained': False
            },
            {
                'summary': '병원 환자정보를 보건당국에 제공',
                'original_purpose': '진료 서비스 제공',
                'intended_use': '감염병 역학조사',
                'requestor': '보건당국',
                'consent_obtained': False
            },
            {
                'summary': '은행 고객정보를 연구기관에 제공',
                'original_purpose': '금융 서비스 제공',
                'intended_use': '금융 소비자 행태 연구',
                'requestor': '대학 연구소',
                'consent_obtained': True
            },
            {
                'summary': '통신사 위치정보를 응급구조대에 제공',
                'original_purpose': '통신 서비스 제공',
                'intended_use': '응급환자 구조',
                'requestor': '119 구급대',
                'consent_obtained': False
            }
        ]
        
        for i, case in enumerate(test_cases, 1):
            print(f"📋 사례 {i}: {case['summary']}")
            
            analysis = self.analyze_purpose_beyond_case(case)
            
            print(f"   원래 목적: {analysis['original_purpose']}")
            print(f"   의도된 이용: {analysis['intended_use']}")
            print(f"   적용 가능 요건: {', '.join(analysis['applicable_requirements']) if analysis['applicable_requirements'] else '없음'}")
            
            status_icon = "✅" if analysis['compliance_status'] == 'compliant' else "❌"
            print(f"   준수 상태: {status_icon} {analysis['compliance_status']}")
            
            print(f"   권고사항:")
            for rec in analysis['recommendations']:
                print(f"     • {rec}")
            print()

# 실행 예시
def demo_data_processing():
    print("📊 개인정보 수집·이용·제공 관리")
    print("=" * 60)
    
    # 개인정보 처리 생애주기
    processor = PersonalDataProcessingManager()
    processor.demonstrate_processing_lifecycle()
    
    print("\n" + "=" * 60)
    
    # 수집 가이드라인
    guidelines = PersonalDataCollectionGuidelines()
    guidelines.display_collection_guidelines()
    
    print("\n" + "=" * 60)
    
    # 목적 외 이용·제공 분석
    usage_provision = PersonalDataUsageAndProvision()
    usage_provision.demonstrate_purpose_beyond_analysis()

if __name__ == "__main__":
    demo_data_processing()
```

### 3. 개인정보 동의 관리

#### 유효한 동의의 요건과 관리

```python
#!/usr/bin/env python3
# 개인정보 동의 관리 시스템

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
import json

class ConsentValidityRequirement(Enum):
    """동의의 유효 요건"""
    SPECIFIC = "구체성"
    INFORMED = "사전 고지"
    FREE_WILL = "자유의사"
    EXPLICIT = "명시성"

class ConsentManagementSystem:
    """개인정보 동의 관리 시스템"""
    
    def __init__(self):
        self.consent_records = {}
        self.consent_forms = {}
        self.withdrawal_records = {}
        
        # 유효한 동의의 요건
        self.validity_requirements = {
            ConsentValidityRequirement.SPECIFIC: {
                'description': '구체적이고 명확한 동의',
                'criteria': [
                    '수집·이용 목적이 구체적으로 명시',
                    '개인정보 항목이 명확히 제시',
                    '보유·이용기간이 명시',
                    '포괄적·추상적 표현 금지'
                ],
                'bad_examples': [
                    '기타 부가서비스 제공 등을 위해',
                    '서비스 향상 등의 목적으로',
                    '기타 마케팅 활용'
                ],
                'good_examples': [
                    '회원 관리 및 본인 확인을 위해',
                    '상품 주문 및 배송 서비스 제공을 위해',
                    '이벤트 당첨자 발표 및 경품 발송을 위해'
                ]
            },
            ConsentValidityRequirement.INFORMED: {
                'description': '충분한 정보 제공 후 동의',
                'criteria': [
                    '동의 전 필요한 모든 정보 제공',
                    '이해하기 쉬운 언어로 설명',
                    '동의거부권 및 불이익 고지',
                    '충분한 숙고시간 제공'
                ],
                'required_information': [
                    '개인정보 수집·이용 목적',
                    '수집하는 개인정보 항목',
                    '개인정보 보유·이용기간',
                    '동의를 거부할 권리 및 거부 시 불이익',
                    '개인정보 제3자 제공 계획(있는 경우)'
                ]
            },
            ConsentValidityRequirement.FREE_WILL: {
                'description': '자유로운 의사에 의한 동의',
                'criteria': [
                    '강요나 기만 없는 동의',
                    '서비스 이용에 꼭 필요하지 않은 개인정보는 선택 동의',
                    '일괄 동의가 아닌 개별 동의 원칙',
                    '동의 철회 가능성 보장'
                ],
                'prohibited_practices': [
                    '서비스 이용을 위한 불필요한 개인정보 동의 강요',
                    '미리 체크된 동의 체크박스',
                    '복잡한 동의 철회 절차',
                    '동의하지 않으면 서비스 이용 전면 차단'
                ]
            },
            ConsentValidityRequirement.EXPLICIT: {
                'description': '명시적이고 능동적인 동의',
                'criteria': [
                    '적극적인 동의 표시 필요',
                    '동의 의사가 명확히 확인 가능',
                    '침묵이나 무작위는 동의로 간주하지 않음',
                    '동의 기록의 보관'
                ],
                'valid_methods': [
                    '체크박스 직접 선택',
                    '동의 버튼 클릭',
                    '서명 또는 날인',
                    '구두 동의(기록 보관)'
                ]
            }
        }
        
        # 동의 철회권
        self.withdrawal_rights = {
            'principle': '정보주체는 언제든지 개인정보 처리에 대한 동의를 철회할 수 있다',
            'requirements': [
                '동의 획득보다 쉬운 철회 절차',
                '철회 방법을 동의 시점에 고지',
                '철회 요청 시 지체 없이 처리',
                '철회로 인한 불이익 최소화'
            ],
            'withdrawal_methods': [
                '웹사이트 마이페이지',
                '이메일 요청',
                '전화 요청',
                '서면 요청',
                '방문 요청'
            ]
        }
    
    def create_consent_form(self, form_details: Dict) -> str:
        """동의서 양식 생성"""
        form_id = f"form_{int(datetime.now().timestamp())}"
        
        consent_form = {
            'form_id': form_id,
            'title': form_details.get('title', '개인정보 수집·이용 동의서'),
            'organization': form_details.get('organization', ''),
            'created_at': datetime.now(),
            'sections': self._generate_consent_sections(form_details),
            'consent_options': self._generate_consent_options(form_details),
            'validity_check': self._check_form_validity(form_details),
            'status': 'active'
        }
        
        self.consent_forms[form_id] = consent_form
        
        return form_id
    
    def _generate_consent_sections(self, form_details: Dict) -> Dict:
        """동의서 섹션 생성"""
        sections = {
            '수집·이용목적': {
                'content': ', '.join(form_details.get('purposes', [])),
                'required': True
            },
            '수집항목': {
                'content': ', '.join(form_details.get('data_items', [])),
                'required': True
            },
            '보유·이용기간': {
                'content': form_details.get('retention_period', ''),
                'required': True
            },
            '동의거부권': {
                'content': '정보주체는 개인정보 수집·이용에 대한 동의를 거부할 권리가 있으며, 다만 동의를 거부할 경우 서비스 이용에 제한이 있을 수 있습니다.',
                'required': True
            }
        }
        
        # 제3자 제공이 있는 경우
        if form_details.get('third_party_provision'):
            sections['제3자제공'] = {
                'content': self._generate_third_party_content(form_details.get('third_party_details', {})),
                'required': True
            }
        
        # 민감정보가 있는 경우
        sensitive_items = [item for item in form_details.get('data_items', []) 
                          if self._is_sensitive_data(item)]
        if sensitive_items:
            sections['민감정보처리'] = {
                'content': f'민감정보({", ".join(sensitive_items)})에 대한 별도 동의가 필요합니다.',
                'required': True
            }
        
        return sections
    
    def _generate_third_party_content(self, third_party_details: Dict) -> str:
        """제3자 제공 내용 생성"""
        return f"""
        제공받는 자: {third_party_details.get('recipient', '')}
        제공 목적: {third_party_details.get('purpose', '')}
        제공 항목: {', '.join(third_party_details.get('items', []))}
        보유·이용기간: {third_party_details.get('retention_period', '')}
        """
    
    def _is_sensitive_data(self, data_item: str) -> bool:
        """민감정보 여부 확인"""
        sensitive_keywords = ['건강', '병력', '종교', '사상', '정치', '성생활', '장애']
        return any(keyword in data_item for keyword in sensitive_keywords)
    
    def _generate_consent_options(self, form_details: Dict) -> Dict:
        """동의 옵션 생성"""
        essential_items = form_details.get('essential_items', [])
        optional_items = [item for item in form_details.get('data_items', []) 
                         if item not in essential_items]
        
        options = {
            '필수동의': {
                'items': essential_items,
                'required': True,
                'description': '서비스 이용을 위해 반드시 필요한 개인정보'
            }
        }
        
        if optional_items:
            options['선택동의'] = {
                'items': optional_items,
                'required': False,
                'description': '서비스 향상 및 편의 제공을 위한 개인정보'
            }
        
        if form_details.get('marketing_consent'):
            options['마케팅활용동의'] = {
                'items': form_details.get('marketing_items', []),
                'required': False,
                'description': '마케팅 및 광고를 위한 개인정보 활용'
            }
        
        return options
    
    def _check_form_validity(self, form_details: Dict) -> Dict:
        """동의서 유효성 검증"""
        validity_check = {
            'is_valid': True,
            'issues': [],
            'recommendations': []
        }
        
        # 구체성 검증
        purposes = form_details.get('purposes', [])
        if not purposes or any('기타' in purpose or '등' in purpose for purpose in purposes):
            validity_check['issues'].append('목적이 구체적이지 않음')
            validity_check['is_valid'] = False
        
        # 필수 정보 검증
        required_fields = ['purposes', 'data_items', 'retention_period']
        for field in required_fields:
            if not form_details.get(field):
                validity_check['issues'].append(f'{field} 누락')
                validity_check['is_valid'] = False
        
        # 권장사항 추가
        if not form_details.get('withdrawal_method'):
            validity_check['recommendations'].append('동의 철회 방법 안내 추가')
        
        if not form_details.get('contact_info'):
            validity_check['recommendations'].append('개인정보보호책임자 연락처 추가')
        
        return validity_check
    
    def obtain_consent(self, form_id: str, data_subject_id: str, consent_details: Dict) -> str:
        """동의 획득"""
        consent_id = f"consent_{data_subject_id}_{int(datetime.now().timestamp())}"
        
        if form_id not in self.consent_forms:
            return "오류: 동의서 양식을 찾을 수 없음"
        
        consent_form = self.consent_forms[form_id]
        
        consent_record = {
            'consent_id': consent_id,
            'form_id': form_id,
            'data_subject_id': data_subject_id,
            'consents': consent_details.get('consents', {}),
            'consent_method': consent_details.get('method', 'online'),
            'ip_address': consent_details.get('ip_address', ''),
            'user_agent': consent_details.get('user_agent', ''),
            'obtained_at': datetime.now(),
            'validity_confirmed': self._validate_consent_details(consent_details, consent_form),
            'status': 'active'
        }
        
        self.consent_records[consent_id] = consent_record
        
        return consent_id
    
    def _validate_consent_details(self, consent_details: Dict, consent_form: Dict) -> bool:
        """동의 내역 유효성 확인"""
        consents = consent_details.get('consents', {})
        form_options = consent_form.get('consent_options', {})
        
        # 필수 동의 확인
        for option_name, option_info in form_options.items():
            if option_info.get('required', False):
                if not consents.get(option_name, False):
                    return False  # 필수 동의 누락
        
        return True
    
    def withdraw_consent(self, consent_id: str, data_subject_id: str, withdrawal_reason: str = '') -> str:
        """동의 철회"""
        if consent_id not in self.consent_records:
            return "오류: 동의 기록을 찾을 수 없음"
        
        consent_record = self.consent_records[consent_id]
        
        if consent_record['data_subject_id'] != data_subject_id:
            return "오류: 동의 철회 권한이 없음"
        
        if consent_record['status'] != 'active':
            return "오류: 이미 철회된 동의"
        
        withdrawal_id = f"withdraw_{consent_id}_{int(datetime.now().timestamp())}"
        
        withdrawal_record = {
            'withdrawal_id': withdrawal_id,
            'consent_id': consent_id,
            'data_subject_id': data_subject_id,
            'withdrawal_reason': withdrawal_reason,
            'withdrawn_at': datetime.now(),
            'withdrawal_method': 'online',  # 실제로는 요청 시 전달받음
            'status': 'completed'
        }
        
        self.withdrawal_records[withdrawal_id] = withdrawal_record
        
        # 동의 기록 상태 변경
        consent_record['status'] = 'withdrawn'
        consent_record['withdrawn_at'] = datetime.now()
        consent_record['withdrawal_id'] = withdrawal_id
        
        return withdrawal_id
    
    def generate_consent_report(self, organization: str, period_start: datetime, period_end: datetime) -> Dict:
        """동의 현황 보고서 생성"""
        report = {
            'organization': organization,
            'report_period': {
                'start': period_start.isoformat(),
                'end': period_end.isoformat()
            },
            'generated_at': datetime.now(),
            'consent_statistics': {
                'total_consents': 0,
                'active_consents': 0,
                'withdrawn_consents': 0,
                'consent_rate': 0.0
            },
            'consent_methods': {},
            'withdrawal_statistics': {
                'total_withdrawals': 0,
                'withdrawal_rate': 0.0,
                'common_reasons': []
            },
            'compliance_issues': []
        }
        
        # 기간 내 동의 기록 필터링
        period_consents = [
            record for record in self.consent_records.values()
            if period_start <= record['obtained_at'] <= period_end
        ]
        
        # 통계 계산
        report['consent_statistics']['total_consents'] = len(period_consents)
        report['consent_statistics']['active_consents'] = len([
            record for record in period_consents if record['status'] == 'active'
        ])
        report['consent_statistics']['withdrawn_consents'] = len([
            record for record in period_consents if record['status'] == 'withdrawn'
        ])
        
        if report['consent_statistics']['total_consents'] > 0:
            report['consent_statistics']['consent_rate'] = (
                report['consent_statistics']['active_consents'] / 
                report['consent_statistics']['total_consents'] * 100
            )
        
        # 동의 방법별 통계
        method_counts = {}
        for record in period_consents:
            method = record['consent_method']
            method_counts[method] = method_counts.get(method, 0) + 1
        
        report['consent_methods'] = method_counts
        
        # 철회 통계
        period_withdrawals = [
            record for record in self.withdrawal_records.values()
            if period_start <= record['withdrawn_at'] <= period_end
        ]
        
        report['withdrawal_statistics']['total_withdrawals'] = len(period_withdrawals)
        
        if report['consent_statistics']['total_consents'] > 0:
            report['withdrawal_statistics']['withdrawal_rate'] = (
                len(period_withdrawals) / 
                report['consent_statistics']['total_consents'] * 100
            )
        
        return report
    
    def demonstrate_consent_management(self):
        """동의 관리 시스템 시연"""
        print("=== 개인정보 동의 관리 시스템 시연 ===\n")
        
        # 1. 동의서 양식 생성
        form_details = {
            'title': '온라인 쇼핑몰 개인정보 수집·이용 동의서',
            'organization': '쇼핑몰 주식회사',
            'purposes': ['회원 관리', '상품 주문 처리', '고객 서비스 제공'],
            'data_items': ['이름', '이메일', '전화번호', '주소', '생년월일'],
            'essential_items': ['이름', '이메일', '전화번호', '주소'],
            'retention_period': '회원 탈퇴 시까지',
            'third_party_provision': True,
            'third_party_details': {
                'recipient': '배송업체',
                'purpose': '상품 배송',
                'items': ['이름', '전화번호', '주소'],
                'retention_period': '배송 완료 후 1개월'
            },
            'marketing_consent': True,
            'marketing_items': ['이메일', '전화번호'],
            'withdrawal_method': '웹사이트 마이페이지 또는 고객센터 전화',
            'contact_info': 'privacy@shopping.com, 02-1234-5678'
        }
        
        form_id = self.create_consent_form(form_details)
        print(f"1. 동의서 양식 생성 완료: {form_id}")
        
        consent_form = self.consent_forms[form_id]
        print(f"   조직: {consent_form['organization']}")
        print(f"   섹션 수: {len(consent_form['sections'])}개")
        print(f"   동의 옵션: {', '.join(consent_form['consent_options'].keys())}")
        
        validity = consent_form['validity_check']
        validity_status = "유효" if validity['is_valid'] else "문제있음"
        print(f"   유효성: {validity_status}")
        
        if validity['issues']:
            print(f"   문제점: {', '.join(validity['issues'])}")
        if validity['recommendations']:
            print(f"   권장사항: {', '.join(validity['recommendations'])}")
        
        # 2. 동의 획득
        consent_details = {
            'consents': {
                '필수동의': True,
                '선택동의': False,
                '마케팅활용동의': True
            },
            'method': 'online',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        data_subject_id = 'user_001'
        consent_id = self.obtain_consent(form_id, data_subject_id, consent_details)
        print(f"\n2. 동의 획득 완료: {consent_id}")
        
        if consent_id.startswith('consent_'):
            consent_record = self.consent_records[consent_id]
            print(f"   동의자: {consent_record['data_subject_id']}")
            print(f"   동의 항목: {', '.join([k for k, v in consent_record['consents'].items() if v])}")
            print(f"   동의 방법: {consent_record['consent_method']}")
        
        # 3. 동의 철회
        withdrawal_reason = '개인정보 활용 중단 희망'
        withdrawal_id = self.withdraw_consent(consent_id, data_subject_id, withdrawal_reason)
        print(f"\n3. 동의 철회 완료: {withdrawal_id}")
        
        if withdrawal_id.startswith('withdraw_'):
            withdrawal_record = self.withdrawal_records[withdrawal_id]
            print(f"   철회 사유: {withdrawal_record['withdrawal_reason']}")
            print(f"   철회 일시: {withdrawal_record['withdrawn_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 4. 동의 현황 보고서
        report_start = datetime.now() - timedelta(days=30)
        report_end = datetime.now()
        
        report = self.generate_consent_report('쇼핑몰 주식회사', report_start, report_end)
        print(f"\n4. 동의 현황 보고서 (최근 30일)")
        print(f"   총 동의: {report['consent_statistics']['total_consents']}건")
        print(f"   활성 동의: {report['consent_statistics']['active_consents']}건")
        print(f"   철회 동의: {report['consent_statistics']['withdrawn_consents']}건")
        print(f"   총 철회: {report['withdrawal_statistics']['total_withdrawals']}건")
        
        # 동의 유효성 요건 안내
        print(f"\n📋 유효한 동의의 4대 요건:")
        for requirement, details in self.validity_requirements.items():
            print(f"   • {requirement.value}: {details['description']}")

# 실행 예시
def demo_consent_management():
    print("📝 개인정보 동의 관리 시스템")
    print("=" * 60)
    
    # 동의 관리 시스템 시연
    consent_manager = ConsentManagementSystem()
    consent_manager.demonstrate_consent_management()

if __name__ == "__main__":
    demo_consent_management()
```

## 마무리

이번 25강에서는 **개인정보보호의 이해 (3)**을 다뤘습니다. **정보주체의 5대 권리**와 권리 행사 절차, **개인정보보호 10계명**과 실천 방안, **국가·지방자치단체의 개인정보보호 의무**, **개인정보 수집·이용·제공의 구체적 절차**, 그리고 **개인정보 동의 관리**까지 포괄적으로 학습했습니다.

이로써 해킹보안전문가 1급 과정의 **05_Information_Security_Management** 과목이 완료되었습니다. 정보보안 관리의 기본 개념부터 개인정보보호법의 세부적인 실무까지 체계적으로 이해할 수 있었습니다.

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*