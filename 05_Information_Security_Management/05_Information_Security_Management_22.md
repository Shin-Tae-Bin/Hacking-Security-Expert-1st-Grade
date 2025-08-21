# 22강: 정보보안의 역사 및 암호학 기초

## 개요
해킹보안전문가 1급 과정의 22강으로, 정보보안의 역사와 암호학의 발전 과정을 다룹니다. 고대의 스테가노그래피부터 현대의 비대칭키 암호화까지, 암호화 기술의 진화와 정보보안의 필요성을 학습합니다.

## 주요 학습 내용

### 1. 암호의 역사

#### 고대 암호 기법

##### 1. 스테가노그래피 (Steganography) - BC 480년
**최초의 암호** - 스파르타에서 추방된 데마라토스의 밀랍 암호

- **원리**: 실제 정보 자체를 숨기는 기법
- **어원**: 그리스어 'steganos(덮다)' + 'graphein(쓰다)'
- **방법**: 나무판에 메시지를 조각한 후 밀랍으로 덮어 은폐

```python
#!/usr/bin/env python3
# 현대적 스테가노그래피 구현

import base64
from PIL import Image
import numpy as np
import io

class ModernSteganography:
    """현대적 스테가노그래피 시스템"""
    
    def __init__(self):
        self.supported_formats = ['PNG', 'BMP']
    
    def hide_text_in_image(self, image_path, secret_text, output_path):
        """이미지에 텍스트 숨기기 (LSB 방식)"""
        try:
            # 이미지 로드
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # 이미지를 numpy 배열로 변환
            image_array = np.array(image)
            
            # 비밀 텍스트를 바이너리로 변환
            secret_binary = ''.join(format(ord(char), '08b') for char in secret_text)
            secret_binary += '1111111111111110'  # 종료 마커
            
            # 이미지 크기 확인
            total_pixels = image_array.shape[0] * image_array.shape[1] * 3
            if len(secret_binary) > total_pixels:
                return False, "이미지가 너무 작아서 텍스트를 숨길 수 없습니다"
            
            # LSB(Least Significant Bit)에 비밀 데이터 삽입
            flat_image = image_array.flatten()
            
            for i, bit in enumerate(secret_binary):
                # 각 픽셀의 LSB를 비밀 데이터 비트로 교체
                flat_image[i] = (flat_image[i] & 0xFE) | int(bit)
            
            # 배열을 이미지 형태로 복원
            modified_image = flat_image.reshape(image_array.shape)
            
            # 수정된 이미지 저장
            result_image = Image.fromarray(modified_image.astype('uint8'))
            result_image.save(output_path, 'PNG')
            
            return True, f"텍스트가 {output_path}에 성공적으로 숨겨졌습니다"
            
        except Exception as e:
            return False, f"오류 발생: {str(e)}"
    
    def extract_text_from_image(self, image_path):
        """이미지에서 숨겨진 텍스트 추출"""
        try:
            # 이미지 로드
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            image_array = np.array(image)
            flat_image = image_array.flatten()
            
            # LSB에서 비트 추출
            binary_data = ""
            for pixel_value in flat_image:
                binary_data += str(pixel_value & 1)
            
            # 8비트씩 묶어서 문자로 변환
            secret_text = ""
            for i in range(0, len(binary_data) - 15, 8):
                byte = binary_data[i:i+8]
                if binary_data[i:i+16] == '1111111111111110':  # 종료 마커 확인
                    break
                
                char = chr(int(byte, 2))
                secret_text += char
            
            return True, secret_text
            
        except Exception as e:
            return False, f"추출 실패: {str(e)}"
    
    def hide_file_in_image(self, image_path, file_path, output_path):
        """이미지에 파일 숨기기"""
        try:
            # 파일을 바이너리로 읽기
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Base64로 인코딩
            encoded_data = base64.b64encode(file_data).decode('ascii')
            
            # 파일명과 데이터를 결합
            filename = file_path.split('/')[-1]  # 경로에서 파일명만 추출
            secret_data = f"FILE:{filename}:{encoded_data}"
            
            return self.hide_text_in_image(image_path, secret_data, output_path)
            
        except Exception as e:
            return False, f"파일 숨기기 실패: {str(e)}"
    
    def extract_file_from_image(self, image_path, output_dir="./"):
        """이미지에서 숨겨진 파일 추출"""
        try:
            success, extracted_data = self.extract_text_from_image(image_path)
            
            if not success:
                return False, extracted_data
            
            # 파일 데이터 파싱
            if not extracted_data.startswith("FILE:"):
                return False, "숨겨진 파일이 아닌 텍스트입니다"
            
            parts = extracted_data[5:].split(':', 1)  # "FILE:" 제거 후 분할
            if len(parts) != 2:
                return False, "파일 데이터 형식이 올바르지 않습니다"
            
            filename, encoded_data = parts
            
            # Base64 디코딩
            file_data = base64.b64decode(encoded_data.encode('ascii'))
            
            # 파일 저장
            output_path = f"{output_dir}/{filename}"
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return True, f"파일이 {output_path}에 성공적으로 추출되었습니다"
            
        except Exception as e:
            return False, f"파일 추출 실패: {str(e)}"
    
    def create_sample_image_for_demo(self, width=200, height=200, filename="sample.png"):
        """데모용 샘플 이미지 생성"""
        import random
        
        # 랜덤 색상의 이미지 생성
        image_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        
        # 이미지 저장
        image = Image.fromarray(image_array)
        image.save(filename, 'PNG')
        
        return filename
    
    def analyze_image_capacity(self, image_path):
        """이미지의 데이터 숨기기 용량 분석"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            image_array = np.array(image)
            total_pixels = image_array.shape[0] * image_array.shape[1] * 3
            
            # 각 픽셀의 LSB 1비트 사용
            max_bits = total_pixels
            max_bytes = max_bits // 8
            max_chars = max_bytes  # ASCII 기준
            
            return {
                'image_size': f"{image_array.shape[1]}x{image_array.shape[0]}",
                'total_pixels': total_pixels,
                'max_hidden_bits': max_bits,
                'max_hidden_bytes': max_bytes,
                'max_hidden_chars': max_chars,
                'max_hidden_kb': max_bytes / 1024
            }
            
        except Exception as e:
            return {'error': str(e)}

# 데모 실행
def demo_steganography():
    stego = ModernSteganography()
    
    print("=== 현대적 스테가노그래피 데모 ===")
    
    # 1. 샘플 이미지 생성
    sample_image = stego.create_sample_image_for_demo(400, 300, "demo_image.png")
    print(f"샘플 이미지 생성: {sample_image}")
    
    # 2. 이미지 용량 분석
    capacity = stego.analyze_image_capacity(sample_image)
    print(f"이미지 정보: {capacity['image_size']}")
    print(f"최대 숨길 수 있는 문자: {capacity['max_hidden_chars']:,}개")
    print(f"최대 숨길 수 있는 데이터: {capacity['max_hidden_kb']:.1f}KB")
    
    # 3. 텍스트 숨기기
    secret_message = "이것은 BC 480년 데마라토스처럼 숨겨진 비밀 메시지입니다! 🔐"
    
    success, message = stego.hide_text_in_image(sample_image, secret_message, "hidden_message.png")
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ {message}")
        return
    
    # 4. 숨겨진 텍스트 추출
    success, extracted_text = stego.extract_text_from_image("hidden_message.png")
    if success:
        print(f"✅ 추출된 메시지: {extracted_text}")
    else:
        print(f"❌ 추출 실패: {extracted_text}")
    
    # 5. 파일 숨기기 (비밀 텍스트 파일 생성 후 숨기기)
    secret_file = "secret_document.txt"
    with open(secret_file, 'w', encoding='utf-8') as f:
        f.write("기밀 문서\n==========\n\n이것은 매우 중요한 기밀 정보입니다.\n페르시아의 침공 계획이 담겨 있습니다.")
    
    success, message = stego.hide_file_in_image(sample_image, secret_file, "hidden_file.png")
    if success:
        print(f"✅ {message}")
        
        # 숨겨진 파일 추출
        success, extraction_message = stego.extract_file_from_image("hidden_file.png", "./extracted/")
        if success:
            print(f"✅ {extraction_message}")
        else:
            print(f"❌ {extraction_message}")
    else:
        print(f"❌ {message}")
    
    print("\n스테가노그래피는 데이터를 숨기는 기술이지만, 암호화와 병행 사용을 권장합니다!")

if __name__ == "__main__":
    import os
    os.makedirs("./extracted/", exist_ok=True)
    demo_steganography()
```

##### 2. 시저 암호 (Caesar Cipher) - BC 50년
**전치법** - 율리우스 시저가 군사적 목적으로 사용

```python
#!/usr/bin/env python3
# 시저 암호 및 확장 구현

import string
import random
from collections import Counter

class CaesarCipherSystem:
    """시저 암호 및 관련 고전 암호 시스템"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.korean_consonants = "ㄱㄴㄷㄹㅁㅂㅅㅇㅈㅊㅋㅌㅍㅎ"
        self.korean_vowels = "ㅏㅑㅓㅕㅗㅛㅜㅠㅡㅣ"
    
    def caesar_encrypt(self, plaintext, shift):
        """시저 암호 암호화"""
        ciphertext = ""
        
        for char in plaintext.upper():
            if char in self.alphabet:
                # 알파벳 위치 찾기
                old_index = self.alphabet.index(char)
                new_index = (old_index + shift) % len(self.alphabet)
                ciphertext += self.alphabet[new_index]
            else:
                ciphertext += char  # 알파벳이 아닌 문자는 그대로
        
        return ciphertext
    
    def caesar_decrypt(self, ciphertext, shift):
        """시저 암호 복호화"""
        return self.caesar_encrypt(ciphertext, -shift)
    
    def caesar_brute_force(self, ciphertext):
        """시저 암호 무차별 대입 공격"""
        results = {}
        
        for shift in range(26):
            decrypted = self.caesar_decrypt(ciphertext, shift)
            results[shift] = decrypted
        
        return results
    
    def frequency_analysis(self, text):
        """빈도수 분석"""
        # 알파벳만 추출
        letters_only = ''.join([char.upper() for char in text if char.upper() in self.alphabet])
        
        if not letters_only:
            return {}
        
        # 빈도수 계산
        frequency = Counter(letters_only)
        total_letters = len(letters_only)
        
        # 백분율로 변환
        frequency_percent = {}
        for letter, count in frequency.items():
            frequency_percent[letter] = (count / total_letters) * 100
        
        return frequency_percent
    
    def substitution_cipher_encrypt(self, plaintext, key_mapping):
        """단순 치환 암호 암호화"""
        ciphertext = ""
        
        for char in plaintext.upper():
            if char in key_mapping:
                ciphertext += key_mapping[char]
            else:
                ciphertext += char
        
        return ciphertext
    
    def substitution_cipher_decrypt(self, ciphertext, key_mapping):
        """단순 치환 암호 복호화"""
        # 키 매핑 역순으로 생성
        reverse_mapping = {v: k for k, v in key_mapping.items()}
        
        plaintext = ""
        for char in ciphertext.upper():
            if char in reverse_mapping:
                plaintext += reverse_mapping[char]
            else:
                plaintext += char
        
        return plaintext
    
    def generate_substitution_key(self, keyword=None):
        """치환 암호 키 생성"""
        if keyword:
            # 키워드 기반 치환표 생성
            keyword = keyword.upper()
            # 중복 문자 제거
            unique_keyword = ""
            for char in keyword:
                if char not in unique_keyword and char in self.alphabet:
                    unique_keyword += char
            
            # 키워드 + 나머지 알파벳
            remaining_letters = [letter for letter in self.alphabet if letter not in unique_keyword]
            cipher_alphabet = unique_keyword + ''.join(remaining_letters)
        else:
            # 랜덤 치환표 생성
            cipher_alphabet = list(self.alphabet)
            random.shuffle(cipher_alphabet)
            cipher_alphabet = ''.join(cipher_alphabet)
        
        # 매핑 딕셔너리 생성
        key_mapping = {}
        for i, letter in enumerate(self.alphabet):
            key_mapping[letter] = cipher_alphabet[i]
        
        return key_mapping
    
    def vigenere_encrypt(self, plaintext, keyword):
        """비즈네르 암호 암호화"""
        plaintext = plaintext.upper()
        keyword = keyword.upper()
        ciphertext = ""
        keyword_index = 0
        
        for char in plaintext:
            if char in self.alphabet:
                # 평문 문자의 알파벳 인덱스
                plain_index = self.alphabet.index(char)
                # 키워드 문자의 알파벳 인덱스
                key_char = keyword[keyword_index % len(keyword)]
                key_index = self.alphabet.index(key_char)
                
                # 비즈네르 암호화 (두 인덱스의 합)
                cipher_index = (plain_index + key_index) % len(self.alphabet)
                ciphertext += self.alphabet[cipher_index]
                
                keyword_index += 1
            else:
                ciphertext += char
        
        return ciphertext
    
    def vigenere_decrypt(self, ciphertext, keyword):
        """비즈네르 암호 복호화"""
        ciphertext = ciphertext.upper()
        keyword = keyword.upper()
        plaintext = ""
        keyword_index = 0
        
        for char in ciphertext:
            if char in self.alphabet:
                # 암호문 문자의 알파벳 인덱스
                cipher_index = self.alphabet.index(char)
                # 키워드 문자의 알파벳 인덱스
                key_char = keyword[keyword_index % len(keyword)]
                key_index = self.alphabet.index(key_char)
                
                # 비즈네르 복호화 (암호문 인덱스에서 키 인덱스 빼기)
                plain_index = (cipher_index - key_index) % len(self.alphabet)
                plaintext += self.alphabet[plain_index]
                
                keyword_index += 1
            else:
                plaintext += char
        
        return plaintext
    
    def kasiski_examination(self, ciphertext, min_length=3):
        """카시스키 검사법 - 비즈네르 암호의 키 길이 추정"""
        ciphertext = ''.join([c for c in ciphertext.upper() if c in self.alphabet])
        
        # 반복되는 문자열 패턴 찾기
        patterns = {}
        
        for length in range(min_length, min(len(ciphertext) // 2, 10)):
            for i in range(len(ciphertext) - length):
                pattern = ciphertext[i:i+length]
                
                if pattern in patterns:
                    patterns[pattern].append(i)
                else:
                    patterns[pattern] = [i]
        
        # 2회 이상 나타나는 패턴만 선별
        repeated_patterns = {k: v for k, v in patterns.items() if len(v) >= 2}
        
        # 패턴 간격 계산
        distances = []
        for pattern, positions in repeated_patterns.items():
            for i in range(1, len(positions)):
                distance = positions[i] - positions[i-1]
                distances.append(distance)
        
        # 최대공약수 계산으로 키 길이 추정
        if distances:
            from math import gcd
            from functools import reduce
            
            key_length_estimate = reduce(gcd, distances)
            
            return {
                'estimated_key_length': key_length_estimate,
                'repeated_patterns': repeated_patterns,
                'distances': distances,
                'pattern_count': len(repeated_patterns)
            }
        else:
            return {
                'estimated_key_length': None,
                'message': '반복 패턴을 찾을 수 없습니다'
            }
    
    def demonstrate_historical_progression(self):
        """암호 기법의 역사적 발전 과정 시연"""
        print("=== 고대 암호 기법의 발전 과정 ===\n")
        
        original_message = "COME TO ROME IMMEDIATELY"
        
        # 1. 시저 암호 (BC 50년)
        print("1. 시저 암호 (BC 50년)")
        print(f"원문: {original_message}")
        
        caesar_encrypted = self.caesar_encrypt(original_message, 3)
        print(f"암호문: {caesar_encrypted}")
        
        caesar_decrypted = self.caesar_decrypt(caesar_encrypted, 3)
        print(f"복호문: {caesar_decrypted}")
        
        # 시저 암호 무차별 대입 공격
        print(f"\n시저 암호 취약성 - 26가지 경우만 시도하면 됨:")
        brute_force_results = self.caesar_brute_force(caesar_encrypted[:10] + "...")  # 일부만 표시
        for shift in range(5):  # 처음 5개만 표시
            print(f"  Shift {shift}: {brute_force_results[shift][:15]}...")
        
        # 2. 단순 치환 암호
        print(f"\n2. 단순 치환 암호 (개선된 방법)")
        substitution_key = self.generate_substitution_key("SECURITY")
        print(f"치환 키 (키워드: SECURITY): {list(substitution_key.items())[:5]}...")
        
        substitution_encrypted = self.substitution_cipher_encrypt(original_message, substitution_key)
        print(f"암호문: {substitution_encrypted}")
        
        # 빈도수 분석 취약성 시연
        longer_text = original_message * 5  # 텍스트를 길게 만들어 빈도수 분석
        longer_encrypted = self.substitution_cipher_encrypt(longer_text, substitution_key)
        
        freq_analysis = self.frequency_analysis(longer_encrypted)
        print(f"\n치환 암호 취약성 - 빈도수 분석:")
        sorted_freq = sorted(freq_analysis.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"가장 빈번한 문자들: {sorted_freq}")
        print(f"영어에서 가장 빈번한 문자는 E(12.7%), T(9.1%), A(8.2%)")
        
        # 3. 비즈네르 암호
        print(f"\n3. 비즈네르 암호 (AD 16세기)")
        vigenere_key = "KEY"
        vigenere_encrypted = self.vigenere_encrypt(original_message, vigenere_key)
        print(f"키워드: {vigenere_key}")
        print(f"암호문: {vigenere_encrypted}")
        
        vigenere_decrypted = self.vigenere_decrypt(vigenere_encrypted, vigenere_key)
        print(f"복호문: {vigenere_decrypted}")
        
        # 카시스키 검사법
        longer_vigenere = self.vigenere_encrypt(original_message * 3, vigenere_key)
        kasiski_result = self.kasiski_examination(longer_vigenere)
        print(f"\n비즈네르 암호 분석 - 카시스키 검사법:")
        if kasiski_result['estimated_key_length']:
            print(f"추정 키 길이: {kasiski_result['estimated_key_length']}")
            print(f"실제 키 길이: {len(vigenere_key)}")
        else:
            print(f"키 길이 추정 실패")
        
        print(f"\n=== 결론 ===")
        print(f"• 시저 암호: 키 공간이 작음 (26가지)")
        print(f"• 단순 치환: 빈도수 분석에 취약")
        print(f"• 비즈네르: 다중문자 치환으로 보안성 향상, 하지만 여전히 분석 가능")
        print(f"• 현대 암호의 필요성: 컴퓨터 시대에는 더 강력한 암호화 필요")

# 실행 예시
if __name__ == "__main__":
    caesar_system = CaesarCipherSystem()
    caesar_system.demonstrate_historical_progression()
```

#### 기계식 암호 시대

##### 에니그마 (Enigma) - 1918년
**회전하는 원반과 전기 회로를 사용한 암호화 장치**

```python
#!/usr/bin/env python3
# 에니그마 기계 시뮬레이터

import string
import random

class EnigmaMachine:
    """에니그마 기계 시뮬레이터"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        
        # 역사적 에니그마 로터 설정 (간소화된 버전)
        self.rotors = {
            'I': {
                'wiring': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
                'notch': 'Q'
            },
            'II': {
                'wiring': 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
                'notch': 'E'
            },
            'III': {
                'wiring': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
                'notch': 'V'
            }
        }
        
        # 반사판 (Reflector)
        self.reflector = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
        
        # 플러그보드 (간소화)
        self.plugboard = {}
        
        # 로터 위치 (A=0, B=1, ..., Z=25)
        self.rotor_positions = [0, 0, 0]  # 3개 로터
        self.rotor_order = ['I', 'II', 'III']  # 로터 순서
    
    def set_rotor_positions(self, positions):
        """로터 위치 설정 (예: 'ABC' -> [0, 1, 2])"""
        if len(positions) != 3:
            raise ValueError("3개의 로터 위치를 모두 지정해야 합니다")
        
        self.rotor_positions = [ord(pos) - ord('A') for pos in positions.upper()]
    
    def set_rotor_order(self, order):
        """로터 순서 설정"""
        if len(order) != 3 or not all(r in self.rotors for r in order):
            raise ValueError("유효한 3개의 로터를 지정해야 합니다")
        
        self.rotor_order = order
    
    def set_plugboard(self, pairs):
        """플러그보드 설정 (예: [('A', 'B'), ('C', 'D')])"""
        self.plugboard = {}
        
        for pair in pairs:
            if len(pair) != 2:
                continue
            
            a, b = pair[0].upper(), pair[1].upper()
            self.plugboard[a] = b
            self.plugboard[b] = a
    
    def advance_rotors(self):
        """로터 회전 (더블 스테핑 포함)"""
        # 오른쪽 로터는 항상 회전
        advance_middle = False
        advance_left = False
        
        # 오른쪽 로터 회전 및 중간 로터 체크
        if self.rotor_positions[2] == (ord(self.rotors[self.rotor_order[2]]['notch']) - ord('A')):
            advance_middle = True
        
        # 중간 로터의 더블 스테핑 체크
        if self.rotor_positions[1] == (ord(self.rotors[self.rotor_order[1]]['notch']) - ord('A')):
            advance_middle = True
            advance_left = True
        
        # 로터 위치 업데이트
        self.rotor_positions[2] = (self.rotor_positions[2] + 1) % 26
        
        if advance_middle:
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 26
        
        if advance_left:
            self.rotor_positions[0] = (self.rotor_positions[0] + 1) % 26
    
    def plugboard_swap(self, char):
        """플러그보드 교환"""
        return self.plugboard.get(char, char)
    
    def rotor_encode_forward(self, char, rotor_num):
        """로터를 통과하여 앞으로 (입력 -> 반사판 방향)"""
        rotor_type = self.rotor_order[rotor_num]
        position = self.rotor_positions[rotor_num]
        wiring = self.rotors[rotor_type]['wiring']
        
        # 로터 위치를 고려한 입력 조정
        input_pos = (ord(char) - ord('A') + position) % 26
        
        # 로터 와이어링을 통한 변환
        output_char = wiring[input_pos]
        
        # 로터 위치를 고려한 출력 조정
        output_pos = (ord(output_char) - ord('A') - position) % 26
        
        return chr(output_pos + ord('A'))
    
    def rotor_encode_backward(self, char, rotor_num):
        """로터를 통과하여 뒤로 (반사판 -> 출력 방향)"""
        rotor_type = self.rotor_order[rotor_num]
        position = self.rotor_positions[rotor_num]
        wiring = self.rotors[rotor_type]['wiring']
        
        # 로터 위치를 고려한 입력 조정
        input_pos = (ord(char) - ord('A') + position) % 26
        input_char = chr(input_pos + ord('A'))
        
        # 역방향 와이어링 찾기
        output_pos = wiring.index(input_char)
        
        # 로터 위치를 고려한 출력 조정
        final_pos = (output_pos - position) % 26
        
        return chr(final_pos + ord('A'))
    
    def reflector_encode(self, char):
        """반사판을 통한 변환"""
        pos = ord(char) - ord('A')
        return self.reflector[pos]
    
    def encode_char(self, char):
        """단일 문자 암호화/복호화"""
        if char not in self.alphabet:
            return char
        
        # 1. 로터 회전 (키 입력 전에)
        self.advance_rotors()
        
        # 2. 플러그보드 1차 교환
        char = self.plugboard_swap(char)
        
        # 3. 로터 통과 (오른쪽 -> 왼쪽)
        for rotor_num in [2, 1, 0]:
            char = self.rotor_encode_forward(char, rotor_num)
        
        # 4. 반사판 통과
        char = self.reflector_encode(char)
        
        # 5. 로터 통과 (왼쪽 -> 오른쪽, 역방향)
        for rotor_num in [0, 1, 2]:
            char = self.rotor_encode_backward(char, rotor_num)
        
        # 6. 플러그보드 2차 교환
        char = self.plugboard_swap(char)
        
        return char
    
    def encode_message(self, message):
        """메시지 전체 암호화/복호화"""
        result = ""
        
        for char in message.upper():
            if char in self.alphabet:
                result += self.encode_char(char)
            elif char == ' ':
                result += 'X'  # 공백을 X로 대체 (에니그마 관례)
            # 다른 문자는 무시
        
        return result
    
    def reset_to_initial_position(self, positions):
        """초기 위치로 리셋"""
        self.set_rotor_positions(positions)
    
    def demonstrate_enigma_vulnerabilities(self):
        """에니그마의 취약점 시연"""
        print("=== 에니그마 기계의 취약점 분석 ===\n")
        
        # 설정
        self.set_rotor_order(['I', 'II', 'III'])
        self.set_rotor_positions('ABC')
        self.set_plugboard([('A', 'B'), ('C', 'D')])
        
        original_message = "ATTACKATDAWN"
        print(f"원본 메시지: {original_message}")
        
        # 암호화
        self.reset_to_initial_position('ABC')
        encrypted = self.encode_message(original_message)
        print(f"암호화된 메시지: {encrypted}")
        
        # 같은 설정으로 복호화 (에니그마의 자기역원성)
        self.reset_to_initial_position('ABC')
        decrypted = self.encode_message(encrypted)
        print(f"복호화된 메시지: {decrypted}")
        
        print(f"\n=== 에니그마의 보안 특징과 취약점 ===")
        
        # 1. 자기역원성 (같은 설정으로 암호화하면 복호화됨)
        print(f"1. 자기역원성: 같은 설정으로 두 번 암호화하면 원문으로 복원")
        
        # 2. 문자가 자기 자신으로 암호화되지 않음
        print(f"2. 반사판 특성: 어떤 문자도 자기 자신으로 암호화되지 않음")
        single_char_tests = ['A', 'B', 'C', 'D', 'E']
        for char in single_char_tests:
            self.reset_to_initial_position('AAA')
            encoded = self.encode_char(char)
            print(f"   {char} -> {encoded} (항상 다른 문자)")
        
        # 3. 일일 키의 중요성
        print(f"\n3. 일일 키 설정의 중요성:")
        print(f"   - 로터 순서: {self.rotor_order}")
        print(f"   - 초기 위치: 암호화마다 변경")
        print(f"   - 플러그보드: 추가 보안층")
        
        # 4. 취약점
        print(f"\n4. 에니그마의 주요 취약점:")
        print(f"   - 키 공간의 한계 (약 10^23가지)")
        print(f"   - 운용상 실수 (같은 메시지 반복, 예측 가능한 텍스트)")
        print(f"   - 물리적 기계의 한계")
        print(f"   - 수학적 분석 가능성 (블레츨리 파크의 분석)")
        
        return encrypted, decrypted

class EnigmaBreaker:
    """에니그마 해독 시뮬레이터 (간소화된 버전)"""
    
    def __init__(self):
        self.common_words = ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'YOU', 'FOR']
        self.german_words = ['UND', 'DER', 'DIE', 'DAS', 'ICH', 'IST', 'MIT', 'AUS']
    
    def frequency_analysis(self, ciphertext):
        """빈도수 분석"""
        from collections import Counter
        
        # 문자 빈도수
        char_freq = Counter(ciphertext)
        
        # 2문자 조합 빈도수 (바이그램)
        bigrams = [ciphertext[i:i+2] for i in range(len(ciphertext)-1)]
        bigram_freq = Counter(bigrams)
        
        return {
            'char_frequency': char_freq.most_common(10),
            'bigram_frequency': bigram_freq.most_common(5)
        }
    
    def crib_attack_simulation(self, ciphertext, known_plaintext):
        """알려진 평문 공격 시뮬레이션"""
        print(f"=== Crib Attack 시뮬레이션 ===")
        print(f"암호문: {ciphertext[:30]}...")
        print(f"추정 평문: {known_plaintext}")
        
        # 간단한 패턴 매칭
        matches = []
        for i in range(len(ciphertext) - len(known_plaintext) + 1):
            cipher_segment = ciphertext[i:i+len(known_plaintext)]
            
            # 자기역원성 체크 (같은 문자가 나타나면 불가능)
            valid = True
            for j, (c_char, p_char) in enumerate(zip(cipher_segment, known_plaintext)):
                if c_char == p_char:  # 에니그마에서는 불가능
                    valid = False
                    break
            
            if valid:
                matches.append((i, cipher_segment))
        
        print(f"가능한 위치: {len(matches)}곳")
        for pos, segment in matches[:3]:  # 처음 3개만 표시
            print(f"  위치 {pos}: {segment}")
        
        return matches

# 데모 실행
def demo_enigma():
    print("=== 에니그마 기계 시뮬레이션 ===\n")
    
    # 에니그마 기계 생성
    enigma = EnigmaMachine()
    
    # 일일 키 설정 시뮬레이션
    print("일일 키 설정:")
    enigma.set_rotor_order(['III', 'I', 'II'])
    print(f"로터 순서: {enigma.rotor_order}")
    
    enigma.set_plugboard([('A', 'F'), ('B', 'G'), ('C', 'H'), ('D', 'J')])
    print(f"플러그보드: A-F, B-G, C-H, D-J")
    
    # 메시지 암호화
    messages = [
        "WEATHER REPORT RAIN EXPECTED",
        "ATTACK AT DAWN TOMORROW",
        "ALL QUIET ON WESTERN FRONT"
    ]
    
    print(f"\n=== 메시지 암호화 ===")
    encrypted_messages = []
    
    for i, message in enumerate(messages):
        # 각 메시지마다 다른 초기 위치 설정
        initial_position = chr(65 + i) + chr(65 + i) + chr(65 + i)  # AAA, BBB, CCC
        enigma.reset_to_initial_position(initial_position)
        
        encrypted = enigma.encode_message(message)
        encrypted_messages.append(encrypted)
        
        print(f"메시지 {i+1}: {message}")
        print(f"초기 위치: {initial_position}")
        print(f"암호문: {encrypted}")
        
        # 복호화 테스트
        enigma.reset_to_initial_position(initial_position)
        decrypted = enigma.encode_message(encrypted)
        print(f"복호문: {decrypted}")
        print(f"정확성: {'✅' if decrypted.replace('X', ' ').strip() == message.replace(' ', 'X') else '❌'}")
        print()
    
    # 에니그마 취약점 시연
    enigma.demonstrate_enigma_vulnerabilities()
    
    # 해독 시뮬레이션
    print(f"\n=== 에니그마 해독 시뮬레이션 ===")
    breaker = EnigmaBreaker()
    
    # 빈도수 분석
    long_ciphertext = ''.join(encrypted_messages)
    freq_analysis = breaker.frequency_analysis(long_ciphertext)
    
    print(f"빈도수 분석 결과:")
    print(f"가장 빈번한 문자: {freq_analysis['char_frequency'][:5]}")
    print(f"가장 빈번한 바이그램: {freq_analysis['bigram_frequency'][:3]}")
    
    # Crib Attack 시뮬레이션
    breaker.crib_attack_simulation(encrypted_messages[0], "WEATHER")
    
    print(f"\n=== 역사적 의의 ===")
    print(f"• 에니그마는 2차 대전 중 독일군의 주요 암호 시스템")
    print(f"• 블레츨리 파크의 앨런 튜링 등이 해독에 성공")
    print(f"• 컴퓨터 과학 발전에 큰 기여 (튜링 머신, 봄베 등)")
    print(f"• 현대 암호학의 출발점 역할")

if __name__ == "__main__":
    demo_enigma()
```

### 2. 현대 암호학의 발전

#### 대칭키 암호화 (Symmetric Cryptography)

```python
#!/usr/bin/env python3
# 현대 대칭키 암호화 시스템

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import time
import secrets

class ModernSymmetricCrypto:
    """현대 대칭키 암호화 시스템"""
    
    def __init__(self):
        self.algorithms = {
            'AES': algorithms.AES,
            'ChaCha20': algorithms.ChaCha20,
            'TripleDES': algorithms.TripleDES
        }
        
        self.modes = {
            'CBC': modes.CBC,
            'GCM': modes.GCM,
            'CTR': modes.CTR,
            'ECB': modes.ECB  # 데모용 (실제로는 비권장)
        }
    
    def generate_key(self, algorithm='AES', key_size=256):
        """암호화 키 생성"""
        if algorithm == 'AES':
            key_length = key_size // 8  # bits to bytes
            return os.urandom(key_length)
        elif algorithm == 'ChaCha20':
            return os.urandom(32)  # ChaCha20은 고정 32바이트
        elif algorithm == 'TripleDES':
            return os.urandom(24)  # 3DES는 24바이트
        else:
            raise ValueError(f"지원하지 않는 알고리즘: {algorithm}")
    
    def derive_key_from_password(self, password, salt=None, iterations=100000):
        """패스워드로부터 키 유도 (PBKDF2)"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=iterations,
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def aes_encrypt(self, plaintext, key=None, mode='CBC'):
        """AES 암호화"""
        if key is None:
            key = self.generate_key('AES')
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # 패딩 적용 (블록 암호의 경우)
        if mode in ['CBC', 'ECB']:
            padder = padding.PKCS7(128).padder()  # AES는 128비트 블록
            padded_data = padder.update(plaintext)
            padded_data += padder.finalize()
            plaintext = padded_data
        
        # IV 생성
        if mode == 'CBC':
            iv = os.urandom(16)  # AES 블록 크기
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif mode == 'GCM':
            iv = os.urandom(12)  # GCM 권장 IV 크기
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        elif mode == 'CTR':
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        elif mode == 'ECB':
            iv = b''  # ECB는 IV 불필요
            cipher = Cipher(algorithms.AES(key), modes.ECB())
        else:
            raise ValueError(f"지원하지 않는 모드: {mode}")
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # GCM 모드의 경우 인증 태그 포함
        auth_tag = None
        if mode == 'GCM':
            auth_tag = encryptor.tag
        
        return {
            'ciphertext': ciphertext,
            'key': key,
            'iv': iv,
            'mode': mode,
            'auth_tag': auth_tag
        }
    
    def aes_decrypt(self, encrypted_data):
        """AES 복호화"""
        ciphertext = encrypted_data['ciphertext']
        key = encrypted_data['key']
        iv = encrypted_data['iv']
        mode = encrypted_data['mode']
        auth_tag = encrypted_data.get('auth_tag')
        
        # 복호화 객체 생성
        if mode == 'CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif mode == 'GCM':
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag))
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        elif mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB())
        else:
            raise ValueError(f"지원하지 않는 모드: {mode}")
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 패딩 제거 (블록 암호의 경우)
        if mode in ['CBC', 'ECB']:
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    
    def demonstrate_confusion_and_diffusion(self):
        """혼돈(Confusion)과 확산(Diffusion) 원리 시연"""
        print("=== 혼돈과 확산 원리 시연 ===\n")
        
        plaintext1 = "Hello World!"
        plaintext2 = "Hello World?"  # 한 문자만 다름
        
        key = self.generate_key('AES')
        
        # 같은 키로 암호화
        encrypted1 = self.aes_encrypt(plaintext1, key, 'CBC')
        encrypted2 = self.aes_encrypt(plaintext2, key, 'CBC')
        
        cipher1_hex = encrypted1['ciphertext'].hex()
        cipher2_hex = encrypted2['ciphertext'].hex()
        
        print(f"평문1: {plaintext1}")
        print(f"평문2: {plaintext2}")
        print(f"차이: 마지막 문자 1개")
        print()
        print(f"암호문1: {cipher1_hex}")
        print(f"암호문2: {cipher2_hex}")
        
        # 차이 비교
        different_bits = sum(c1 != c2 for c1, c2 in zip(cipher1_hex, cipher2_hex))
        print(f"암호문 차이: {different_bits}/{len(cipher1_hex)}개 문자 ({different_bits/len(cipher1_hex)*100:.1f}%)")
        
        print(f"\n확산(Diffusion): 평문의 작은 변화가 암호문 전체에 큰 영향")
        print(f"혼돈(Confusion): 암호문으로부터 키나 평문을 추측하기 어려움")
    
    def performance_comparison(self):
        """암호화 알고리즘 성능 비교"""
        print(f"\n=== 대칭키 암호 알고리즘 성능 비교 ===\n")
        
        test_data = "A" * 1024 * 1024  # 1MB 데이터
        iterations = 10
        
        algorithms_to_test = [
            ('AES-256-CBC', lambda: self.aes_encrypt(test_data, self.generate_key('AES', 256), 'CBC')),
            ('AES-256-GCM', lambda: self.aes_encrypt(test_data, self.generate_key('AES', 256), 'GCM')),
            ('AES-128-CBC', lambda: self.aes_encrypt(test_data, self.generate_key('AES', 128), 'CBC'))
        ]
        
        results = {}
        
        for name, encrypt_func in algorithms_to_test:
            times = []
            
            for _ in range(iterations):
                start_time = time.time()
                encrypted = encrypt_func()
                end_time = time.time()
                times.append(end_time - start_time)
            
            avg_time = sum(times) / len(times)
            throughput = len(test_data) / avg_time / (1024 * 1024)  # MB/s
            
            results[name] = {
                'avg_time': avg_time,
                'throughput_mbs': throughput,
                'ciphertext_size': len(encrypted['ciphertext'])
            }
        
        print(f"{'알고리즘':<20} {'평균 시간(초)':<15} {'처리량(MB/s)':<15} {'암호문 크기(바이트)':<20}")
        print(f"{'='*70}")
        
        for name, result in results.items():
            print(f"{name:<20} {result['avg_time']:<15.4f} {result['throughput_mbs']:<15.1f} {result['ciphertext_size']:<20}")
        
        return results
    
    def demonstrate_mode_differences(self):
        """암호화 모드별 차이점 시연"""
        print(f"\n=== 암호화 모드별 특성 비교 ===\n")
        
        plaintext = "This is a secret message that demonstrates different encryption modes!"
        key = self.generate_key('AES')
        
        modes_to_test = ['ECB', 'CBC', 'CTR', 'GCM']
        
        for mode in modes_to_test:
            try:
                encrypted = self.aes_encrypt(plaintext, key, mode)
                decrypted = self.aes_decrypt(encrypted)
                
                print(f"모드: {mode}")
                print(f"IV 크기: {len(encrypted['iv'])} 바이트")
                print(f"암호문 크기: {len(encrypted['ciphertext'])} 바이트")
                print(f"인증 태그: {'있음' if encrypted['auth_tag'] else '없음'}")
                print(f"복호화 성공: {'✅' if decrypted == plaintext else '❌'}")
                print()
                
            except Exception as e:
                print(f"모드 {mode} 오류: {e}")
                print()
        
        # ECB 모드의 문제점 시연
        self.demonstrate_ecb_weakness()
    
    def demonstrate_ecb_weakness(self):
        """ECB 모드의 취약점 시연"""
        print(f"=== ECB 모드의 취약점 ===")
        
        # 반복되는 패턴이 있는 데이터
        plaintext = "HELLO WORLD! " * 10
        key = self.generate_key('AES')
        
        # ECB와 CBC 모드로 각각 암호화
        ecb_encrypted = self.aes_encrypt(plaintext, key, 'ECB')
        cbc_encrypted = self.aes_encrypt(plaintext, key, 'CBC')
        
        print(f"반복되는 평문: {plaintext[:40]}...")
        print(f"ECB 암호문: {ecb_encrypted['ciphertext'].hex()[:80]}...")
        print(f"CBC 암호문: {cbc_encrypted['ciphertext'].hex()[:80]}...")
        
        # 블록별로 분석
        ecb_blocks = [ecb_encrypted['ciphertext'][i:i+16].hex() 
                      for i in range(0, len(ecb_encrypted['ciphertext']), 16)]
        
        unique_ecb_blocks = len(set(ecb_blocks))
        total_ecb_blocks = len(ecb_blocks)
        
        print(f"ECB 모드: {total_ecb_blocks}개 블록 중 {unique_ecb_blocks}개가 유일")
        print(f"CBC 모드: 각 블록이 이전 블록과 XOR되어 모두 다름")
        print(f"결론: ECB는 패턴이 드러나므로 보안상 취약!")

# 실행 예시
if __name__ == "__main__":
    crypto = ModernSymmetricCrypto()
    
    print("=== 현대 대칭키 암호화 시스템 데모 ===")
    
    # 기본 AES 암호화 테스트
    message = "이것은 현대 대칭키 암호화 시스템의 데모입니다!"
    
    # 키 생성 및 암호화
    encrypted = crypto.aes_encrypt(message, mode='GCM')
    print(f"원본 메시지: {message}")
    print(f"암호화 키: {encrypted['key'].hex()}")
    print(f"암호문: {encrypted['ciphertext'].hex()}")
    
    # 복호화
    decrypted = crypto.aes_decrypt(encrypted)
    print(f"복호화 메시지: {decrypted}")
    print(f"복호화 성공: {'✅' if decrypted == message else '❌'}")
    
    # 패스워드 기반 암호화
    print(f"\n=== 패스워드 기반 암호화 ===")
    password = "MySecretPassword123!"
    key, salt = crypto.derive_key_from_password(password)
    
    pw_encrypted = crypto.aes_encrypt(message, key, 'CBC')
    pw_decrypted = crypto.aes_decrypt(pw_encrypted)
    
    print(f"패스워드: {password}")
    print(f"솔트: {salt.hex()}")
    print(f"유도된 키: {key.hex()}")
    print(f"복호화 성공: {'✅' if pw_decrypted == message else '❌'}")
    
    # 혼돈과 확산 원리 시연
    crypto.demonstrate_confusion_and_diffusion()
    
    # 성능 비교
    crypto.performance_comparison()
    
    # 모드별 특성 비교
    crypto.demonstrate_mode_differences()
```

#### 비대칭키 암호화 (Asymmetric Cryptography)

```python
#!/usr/bin/env python3
# 현대 비대칭키 암호화 시스템

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64
import time
import os

class ModernAsymmetricCrypto:
    """현대 비대칭키 암호화 시스템"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self, key_size=2048):
        """RSA 키 쌍 생성"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # 일반적으로 사용되는 값
            key_size=key_size,
        )
        self.public_key = self.private_key.public_key()
        
        return self.private_key, self.public_key
    
    def export_keys(self, password=None):
        """키를 PEM 형식으로 내보내기"""
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_keys_from_pem(self, private_pem, public_pem, password=None):
        """PEM 형식에서 키 로드"""
        if password:
            self.private_key = load_pem_private_key(private_pem, password.encode())
        else:
            self.private_key = load_pem_private_key(private_pem, None)
        
        self.public_key = load_pem_public_key(public_pem)
    
    def rsa_encrypt(self, plaintext, public_key=None):
        """RSA 암호화 (공개키로 암호화)"""
        if public_key is None:
            public_key = self.public_key
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # OAEP 패딩 사용 (보안성 향상)
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def rsa_decrypt(self, ciphertext, private_key=None):
        """RSA 복호화 (개인키로 복호화)"""
        if private_key is None:
            private_key = self.private_key
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    
    def rsa_sign(self, message, private_key=None):
        """RSA 디지털 서명 (개인키로 서명)"""
        if private_key is None:
            private_key = self.private_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def rsa_verify(self, message, signature, public_key=None):
        """RSA 서명 검증 (공개키로 검증)"""
        if public_key is None:
            public_key = self.public_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def hybrid_encrypt(self, plaintext):
        """하이브리드 암호화 (대칭키 + 비대칭키)"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # 1. AES 키 생성
        aes_key = os.urandom(32)  # 256비트
        iv = os.urandom(16)       # 128비트
        
        # 2. AES로 데이터 암호화
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # 패딩 적용
        from cryptography.hazmat.primitives import padding as sym_padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode())
        padded_data += padder.finalize()
        
        data_ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # 3. RSA로 AES 키 암호화
        key_ciphertext = self.rsa_encrypt(aes_key)
        
        return {
            'data_ciphertext': data_ciphertext,
            'key_ciphertext': key_ciphertext,
            'iv': iv
        }
    
    def hybrid_decrypt(self, encrypted_data):
        """하이브리드 복호화"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # 1. RSA로 AES 키 복호화
        aes_key = self.rsa_decrypt(encrypted_data['key_ciphertext']).encode('latin-1')
        
        # 2. AES로 데이터 복호화
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(encrypted_data['iv']))
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data['data_ciphertext']) + decryptor.finalize()
        
        # 패딩 제거
        from cryptography.hazmat.primitives import padding as sym_padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext.decode()
    
    def demonstrate_rsa_properties(self):
        """RSA의 특성 시연"""
        print("=== RSA 암호화 특성 시연 ===\n")
        
        # 키 생성
        self.generate_key_pair(1024)  # 데모용으로 작은 키 크기 사용
        
        message = "RSA 비대칭 암호화 테스트"
        print(f"원본 메시지: {message}")
        
        # 1. 기밀성: 공개키로 암호화, 개인키로 복호화
        print(f"\n1. 기밀성 (Confidentiality)")
        encrypted = self.rsa_encrypt(message)
        decrypted = self.rsa_decrypt(encrypted)
        
        print(f"암호화 (공개키): {base64.b64encode(encrypted).decode()[:50]}...")
        print(f"복호화 (개인키): {decrypted}")
        print(f"기밀성 확인: {'✅' if decrypted == message else '❌'}")
        
        # 2. 인증과 부인방지: 개인키로 서명, 공개키로 검증
        print(f"\n2. 인증 및 부인방지 (Authentication & Non-repudiation)")
        signature = self.rsa_sign(message)
        is_valid = self.rsa_verify(message, signature)
        
        print(f"디지털 서명: {base64.b64encode(signature).decode()[:50]}...")
        print(f"서명 검증: {'✅ 유효' if is_valid else '❌ 무효'}")
        
        # 서명 위조 시도
        fake_message = "위조된 메시지"
        is_fake_valid = self.rsa_verify(fake_message, signature)
        print(f"위조 메시지 검증: {'✅ 유효' if is_fake_valid else '❌ 무효'}")
        
        return encrypted, signature
    
    def performance_analysis(self):
        """성능 분석 (대칭키 vs 비대칭키)"""
        print(f"\n=== 성능 분석: 대칭키 vs 비대칭키 ===\n")
        
        # 대칭키 암호화 (AES)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        test_data = "A" * 1024  # 1KB 데이터
        iterations = 100
        
        # AES 성능 측정
        aes_key = os.urandom(32)
        aes_times = []
        
        for _ in range(iterations):
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            
            start_time = time.time()
            encryptor = cipher.encryptor()
            # 패딩 없이 간단히 측정
            ciphertext = encryptor.update(test_data.encode()[:16] * (len(test_data)//16))
            ciphertext += encryptor.finalize()
            end_time = time.time()
            
            aes_times.append(end_time - start_time)
        
        # RSA 성능 측정 (작은 데이터)
        rsa_data = "A" * 100  # RSA는 작은 데이터만 암호화 가능
        rsa_times = []
        
        for _ in range(10):  # RSA는 느리므로 적게 측정
            start_time = time.time()
            encrypted = self.rsa_encrypt(rsa_data)
            decrypted = self.rsa_decrypt(encrypted)
            end_time = time.time()
            
            rsa_times.append(end_time - start_time)
        
        aes_avg = sum(aes_times) / len(aes_times) * 1000  # ms
        rsa_avg = sum(rsa_times) / len(rsa_times) * 1000  # ms
        
        print(f"AES 암호화 평균 시간: {aes_avg:.2f}ms (1KB)")
        print(f"RSA 암호화 평균 시간: {rsa_avg:.2f}ms (100바이트)")
        print(f"속도 차이: RSA가 AES보다 약 {rsa_avg/aes_avg:.0f}배 느림")
        
        print(f"\n결론:")
        print(f"• 대칭키: 빠른 속도, 대용량 데이터 처리 가능")
        print(f"• 비대칭키: 느린 속도, 작은 데이터만 처리, 키 분배 문제 해결")
        print(f"• 실제 시스템: 하이브리드 방식 사용")
    
    def demonstrate_key_exchange_problem(self):
        """키 교환 문제와 해결책 시연"""
        print(f"\n=== 키 교환 문제와 RSA의 해결책 ===\n")
        
        print(f"문제상황: Alice와 Bob이 안전하게 통신하고 싶음")
        print(f"          하지만 도청자 Eve가 모든 통신을 감시 중")
        
        # Alice와 Bob의 키 생성
        alice_crypto = ModernAsymmetricCrypto()
        bob_crypto = ModernAsymmetricCrypto()
        
        alice_private, alice_public = alice_crypto.generate_key_pair()
        bob_private, bob_public = bob_crypto.generate_key_pair()
        
        print(f"\n1. Alice와 Bob이 각자 키 쌍 생성")
        print(f"2. Alice와 Bob이 공개키를 공개적으로 교환 (Eve가 볼 수 있음)")
        
        # Alice가 Bob에게 비밀 메시지 전송
        secret_message = "우리는 내일 오후 3시에 만납시다"
        print(f"\n3. Alice가 Bob의 공개키로 메시지 암호화")
        print(f"   비밀 메시지: {secret_message}")
        
        # Alice가 Bob의 공개키로 암호화
        encrypted_for_bob = bob_crypto.rsa_encrypt(secret_message, bob_public)
        print(f"   암호화된 메시지: {base64.b64encode(encrypted_for_bob).decode()[:50]}...")
        
        # Bob이 자신의 개인키로 복호화
        decrypted_by_bob = bob_crypto.rsa_decrypt(encrypted_for_bob, bob_private)
        print(f"4. Bob이 자신의 개인키로 복호화")
        print(f"   복호화된 메시지: {decrypted_by_bob}")
        print(f"   통신 성공: {'✅' if decrypted_by_bob == secret_message else '❌'}")
        
        # Eve의 공격 시도 (실패)
        print(f"\n5. Eve의 공격 시도:")
        print(f"   Eve는 암호화된 메시지와 공개키들을 알고 있음")
        print(f"   하지만 Bob의 개인키가 없어서 복호화 불가능")
        print(f"   → 기밀성 보장! 🔒")
        
        # 디지털 서명으로 인증
        print(f"\n6. Alice가 메시지에 디지털 서명 추가 (인증)")
        signature = alice_crypto.rsa_sign(secret_message, alice_private)
        signature_valid = alice_crypto.rsa_verify(secret_message, signature, alice_public)
        
        print(f"   Alice의 서명: {base64.b64encode(signature).decode()[:50]}...")
        print(f"   Bob이 서명 검증: {'✅ Alice가 보낸 것이 확실' if signature_valid else '❌ 위조된 메시지'}")
        
        return {
            'alice_keys': (alice_private, alice_public),
            'bob_keys': (bob_private, bob_public),
            'encrypted_message': encrypted_for_bob,
            'signature': signature
        }

# 실행 예시
def main():
    print("=== 현대 비대칭키 암호화 시스템 데모 ===")
    
    crypto = ModernAsymmetricCrypto()
    
    # RSA 특성 시연
    encrypted, signature = crypto.demonstrate_rsa_properties()
    
    # 성능 분석
    crypto.performance_analysis()
    
    # 키 교환 문제와 해결책
    exchange_demo = crypto.demonstrate_key_exchange_problem()
    
    # 하이브리드 암호화
    print(f"\n=== 하이브리드 암호화 (실용적 해결책) ===")
    large_message = "이것은 매우 긴 메시지입니다. " * 100  # 큰 데이터
    
    print(f"대용량 메시지 ({len(large_message)} 문자)")
    
    start_time = time.time()
    hybrid_encrypted = crypto.hybrid_encrypt(large_message)
    hybrid_decrypted = crypto.hybrid_decrypt(hybrid_encrypted)
    end_time = time.time()
    
    print(f"하이브리드 암호화/복호화 시간: {(end_time - start_time)*1000:.2f}ms")
    print(f"복호화 성공: {'✅' if hybrid_decrypted == large_message else '❌'}")
    
    print(f"\n하이브리드 방식의 장점:")
    print(f"• AES로 데이터 암호화 (빠른 속도)")
    print(f"• RSA로 AES 키 암호화 (안전한 키 분배)")
    print(f"• 두 방식의 장점 결합")
    
    # 키 저장 및 로드
    print(f"\n=== 키 관리 (저장 및 로드) ===")
    private_pem, public_pem = crypto.export_keys()
    
    print(f"개인키 (PEM): {private_pem.decode()[:100]}...")
    print(f"공개키 (PEM): {public_pem.decode()[:100]}...")
    
    # 새로운 인스턴스에서 키 로드
    crypto2 = ModernAsymmetricCrypto()
    crypto2.load_keys_from_pem(private_pem, public_pem)
    
    # 로드된 키로 테스트
    test_message = "키 로드 테스트"
    test_encrypted = crypto2.rsa_encrypt(test_message)
    test_decrypted = crypto2.rsa_decrypt(test_encrypted)
    
    print(f"키 로드 테스트: {'✅' if test_decrypted == test_message else '❌'}")

if __name__ == "__main__":
    main()
```

### 3. 정보보안의 필요성

#### 현대 사회에서의 정보보안 위협

```python
#!/usr/bin/env python3
# 현대 정보보안 위협 분석 시스템

import json
import random
from datetime import datetime, timedelta
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

class CyberThreatAnalyzer:
    """현대 사이버 위협 분석 시스템"""
    
    def __init__(self):
        self.threat_categories = {
            '맬웨어': ['바이러스', '웜', '트로이목마', '랜섬웨어', '스파이웨어'],
            '해킹': ['무차별대입공격', 'SQL인젝션', 'XSS', '피싱', '사회공학'],
            '내부자위협': ['권한남용', '정보유출', '악의적행위', '실수'],
            '고급지속위협': ['APT', '국가후원해킹', '제로데이공격'],
            'DDoS': ['서비스거부공격', '분산서비스거부공격'],
            '개인정보침해': ['개인정보유출', '프라이버시침해', '신원도용']
        }
        
        self.impact_levels = ['낮음', '보통', '높음', '매우높음', '심각']
        self.sectors = ['금융', '의료', '정부', '교육', '제조', '통신', '유통']
        
        self.historical_data = self._generate_historical_threat_data()
    
    def _generate_historical_threat_data(self):
        """역사적 위협 데이터 생성 (시뮬레이션)"""
        data = {}
        start_year = 2000
        current_year = 2024
        
        for year in range(start_year, current_year + 1):
            yearly_data = {}
            
            for category, threats in self.threat_categories.items():
                # 연도별 위협 증가 추세 반영
                base_incidents = 100 if year == start_year else data[year-1][category]['total_incidents']
                
                # 특정 위협은 특정 년도에 급증
                growth_factor = 1.1  # 기본 10% 증가
                
                if category == '맬웨어' and year >= 2017:  # 랜섬웨어 급증
                    growth_factor = 1.5
                elif category == '개인정보침해' and year >= 2018:  # GDPR 이후 보고 증가
                    growth_factor = 1.3
                elif category == '고급지속위협' and year >= 2010:  # APT 등장
                    growth_factor = 1.4
                
                total_incidents = int(base_incidents * growth_factor * random.uniform(0.8, 1.2))
                
                yearly_data[category] = {
                    'total_incidents': total_incidents,
                    'threats': {threat: random.randint(1, total_incidents//len(threats)*2) 
                              for threat in threats},
                    'sectors_affected': {sector: random.randint(0, total_incidents//4) 
                                       for sector in self.sectors}
                }
            
            data[year] = yearly_data
        
        return data
    
    def analyze_threat_trends(self):
        """위협 트렌드 분석"""
        print("=== 사이버 위협 트렌드 분석 ===\n")
        
        # 연도별 전체 사건 수 분석
        yearly_totals = {}
        for year, data in self.historical_data.items():
            yearly_totals[year] = sum(category_data['total_incidents'] 
                                    for category_data in data.values())
        
        print("연도별 사이버 보안 사건 증가 추세:")
        print(f"{'년도':<8} {'전체사건수':<12} {'전년대비증가율':<15}")
        print("=" * 40)
        
        prev_total = None
        for year in sorted(yearly_totals.keys())[-10:]:  # 최근 10년
            total = yearly_totals[year]
            if prev_total:
                growth_rate = ((total - prev_total) / prev_total) * 100
                growth_str = f"{growth_rate:+.1f}%"
            else:
                growth_str = "기준년도"
            
            print(f"{year:<8} {total:<12,} {growth_str:<15}")
            prev_total = total
        
        # 카테고리별 분석
        print(f"\n2024년 위협 카테고리별 분석:")
        current_data = self.historical_data[2024]
        
        for category, data in sorted(current_data.items(), 
                                   key=lambda x: x[1]['total_incidents'], 
                                   reverse=True):
            print(f"\n{category}: {data['total_incidents']:,}건")
            
            # 상위 위협 3개
            top_threats = sorted(data['threats'].items(), 
                               key=lambda x: x[1], reverse=True)[:3]
            for threat, count in top_threats:
                print(f"  • {threat}: {count:,}건")
        
        return yearly_totals
    
    def sector_vulnerability_analysis(self):
        """산업별 취약성 분석"""
        print(f"\n=== 산업별 사이버 보안 취약성 분석 ===\n")
        
        current_data = self.historical_data[2024]
        
        # 산업별 피해 집계
        sector_incidents = defaultdict(int)
        sector_threat_types = defaultdict(lambda: defaultdict(int))
        
        for category, data in current_data.items():
            for sector, incidents in data['sectors_affected'].items():
                sector_incidents[sector] += incidents
                sector_threat_types[sector][category] += incidents
        
        print(f"{'산업분야':<10} {'총사건수':<10} {'주요위협':<20} {'위험도':<10}")
        print("=" * 60)
        
        for sector in sorted(sector_incidents.keys(), 
                           key=lambda x: sector_incidents[x], reverse=True):
            total = sector_incidents[sector]
            
            # 주요 위협 찾기
            main_threat = max(sector_threat_types[sector].items(), 
                            key=lambda x: x[1])[0]
            
            # 위험도 계산
            if total > 1000:
                risk_level = "매우높음"
            elif total > 500:
                risk_level = "높음"
            elif total > 200:
                risk_level = "보통"
            else:
                risk_level = "낮음"
            
            print(f"{sector:<10} {total:<10,} {main_threat:<20} {risk_level:<10}")
        
        return sector_incidents, sector_threat_types
    
    def calculate_economic_impact(self):
        """경제적 피해 분석"""
        print(f"\n=== 사이버 보안 사건의 경제적 피해 분석 ===\n")
        
        # 위협별 평균 피해액 (가상 데이터, 실제는 다양한 보고서 기반)
        damage_per_incident = {
            '맬웨어': 50000,           # 평균 5만 달러
            '해킹': 100000,            # 평균 10만 달러
            '내부자위협': 200000,       # 평균 20만 달러
            '고급지속위협': 1000000,    # 평균 100만 달러
            'DDoS': 80000,             # 평균 8만 달러
            '개인정보침해': 150000      # 평균 15만 달러
        }
        
        current_data = self.historical_data[2024]
        total_damage = 0
        
        print(f"{'위협 유형':<15} {'사건 수':<10} {'평균 피해액':<15} {'총 피해액':<15}")
        print("=" * 65)
        
        for category, data in current_data.items():
            incidents = data['total_incidents']
            avg_damage = damage_per_incident[category]
            total_category_damage = incidents * avg_damage
            total_damage += total_category_damage
            
            print(f"{category:<15} {incidents:<10,} ${avg_damage:<14,} ${total_category_damage:<14,}")
        
        print("=" * 65)
        print(f"{'총계':<15} {'':<10} {'':<15} ${total_damage:<14,}")
        
        # GDP 대비 비교 (가상)
        estimated_gdp = 25000000000000  # 25조 달러
        damage_ratio = (total_damage / estimated_gdp) * 100
        
        print(f"\n경제적 영향 분석:")
        print(f"• 연간 총 사이버 보안 피해: ${total_damage:,}")
        print(f"• GDP 대비 피해 비율: {damage_ratio:.3f}%")
        print(f"• 일평균 피해액: ${total_damage/365:,.0f}")
        
        return total_damage
    
    def predict_future_threats(self):
        """미래 위협 예측"""
        print(f"\n=== 미래 사이버 위협 예측 ===\n")
        
        # 트렌드 기반 예측 (간단한 선형 회귀)
        years = list(self.historical_data.keys())[-5:]  # 최근 5년
        
        predictions = {}
        
        for category in self.threat_categories.keys():
            incidents = [self.historical_data[year][category]['total_incidents'] 
                        for year in years]
            
            # 간단한 선형 증가 예측
            growth_rate = (incidents[-1] - incidents[0]) / len(incidents)
            predicted_2025 = incidents[-1] + growth_rate
            predicted_2030 = incidents[-1] + growth_rate * 6
            
            predictions[category] = {
                '2025': int(predicted_2025),
                '2030': int(predicted_2030),
                'growth_rate': growth_rate
            }
        
        print(f"{'위협 유형':<15} {'2024 실제':<12} {'2025 예측':<12} {'2030 예측':<12} {'연평균증가':<12}")
        print("=" * 75)
        
        for category in self.threat_categories.keys():
            current = self.historical_data[2024][category]['total_incidents']
            pred_2025 = predictions[category]['2025']
            pred_2030 = predictions[category]['2030']
            growth = predictions[category]['growth_rate']
            
            print(f"{category:<15} {current:<12,} {pred_2025:<12,} {pred_2030:<12,} {growth:<12.0f}")
        
        # 새로운 위협 유형 예측
        print(f"\n예상되는 새로운 위협:")
        emerging_threats = [
            "AI 기반 공격 (DeepFake, AI 피싱)",
            "양자컴퓨터 위협 (현재 암호화 무력화)",
            "IoT 대규모 봇넷",
            "클라우드 네이티브 공격",
            "블록체인/암호화폐 관련 공격",
            "메타버스/VR 환경 공격"
        ]
        
        for i, threat in enumerate(emerging_threats, 1):
            print(f"{i}. {threat}")
        
        return predictions
    
    def generate_threat_visualization(self, yearly_totals):
        """위협 트렌드 시각화"""
        try:
            import matplotlib.pyplot as plt
            
            years = list(yearly_totals.keys())
            incidents = list(yearly_totals.values())
            
            plt.figure(figsize=(12, 8))
            
            # 전체 트렌드
            plt.subplot(2, 2, 1)
            plt.plot(years, incidents, 'b-', marker='o', linewidth=2)
            plt.title('사이버 보안 사건 연도별 추이')
            plt.xlabel('연도')
            plt.ylabel('사건 수')
            plt.grid(True, alpha=0.3)
            
            # 카테고리별 2024년 분포
            plt.subplot(2, 2, 2)
            current_data = self.historical_data[2024]
            categories = list(current_data.keys())
            category_incidents = [current_data[cat]['total_incidents'] for cat in categories]
            
            plt.pie(category_incidents, labels=categories, autopct='%1.1f%%')
            plt.title('2024년 위협 유형별 분포')
            
            # 산업별 피해 현황
            sector_incidents, _ = self.sector_vulnerability_analysis()
            plt.subplot(2, 2, 3)
            sectors = list(sector_incidents.keys())
            sector_values = list(sector_incidents.values())
            
            plt.bar(sectors, sector_values, color='red', alpha=0.7)
            plt.title('산업별 사이버 보안 사건 수')
            plt.xlabel('산업')
            plt.ylabel('사건 수')
            plt.xticks(rotation=45)
            
            # 최근 5년 증가율
            plt.subplot(2, 2, 4)
            recent_years = years[-5:]
            recent_incidents = incidents[-5:]
            growth_rates = []
            
            for i in range(1, len(recent_incidents)):
                growth = ((recent_incidents[i] - recent_incidents[i-1]) / recent_incidents[i-1]) * 100
                growth_rates.append(growth)
            
            plt.bar(recent_years[1:], growth_rates, color='orange', alpha=0.7)
            plt.title('연도별 증가율 (%)')
            plt.xlabel('연도')
            plt.ylabel('증가율 (%)')
            plt.axhline(y=0, color='black', linestyle='-', linewidth=0.5)
            
            plt.tight_layout()
            plt.savefig('cyber_threat_analysis.png', dpi=300, bbox_inches='tight')
            print(f"\n시각화 결과가 'cyber_threat_analysis.png'에 저장되었습니다.")
            
        except ImportError:
            print(f"\nMatplotlib가 설치되지 않아 시각화를 건너뜁니다.")
    
    def security_investment_roi(self, total_damage):
        """보안 투자 ROI 계산"""
        print(f"\n=== 정보보안 투자의 경제적 가치 ===\n")
        
        # 보안 투자 시나리오
        investment_scenarios = {
            '기본 보안': {
                'investment': total_damage * 0.05,  # 피해액의 5%
                'risk_reduction': 0.3  # 30% 위험 감소
            },
            '강화된 보안': {
                'investment': total_damage * 0.10,  # 피해액의 10%
                'risk_reduction': 0.6  # 60% 위험 감소
            },
            '최고 수준 보안': {
                'investment': total_damage * 0.20,  # 피해액의 20%
                'risk_reduction': 0.8  # 80% 위험 감소
            }
        }
        
        print(f"{'시나리오':<15} {'투자금액':<15} {'예상피해감소':<15} {'순이익':<15} {'ROI':<10}")
        print("=" * 75)
        
        for scenario, data in investment_scenarios.items():
            investment = data['investment']
            damage_reduction = total_damage * data['risk_reduction']
            net_benefit = damage_reduction - investment
            roi = (net_benefit / investment) * 100 if investment > 0 else 0
            
            print(f"{scenario:<15} ${investment:<14,.0f} ${damage_reduction:<14,.0f} ${net_benefit:<14,.0f} {roi:<9.1f}%")
        
        print(f"\n보안 투자의 중요성:")
        print(f"• 예방 1달러 투자 시 평균 4-7달러의 피해 방지 효과")
        print(f"• 사후 대응비용이 사전 예방비용의 10-100배")
        print(f"• 기업 신뢰도 및 브랜드 가치 보호")
        print(f"• 규제 준수 및 법적 리스크 완화")

# 실행 예시
def main():
    analyzer = CyberThreatAnalyzer()
    
    print("🔒 현대 사회의 정보보안 위협 분석 보고서 🔒")
    print("=" * 60)
    
    # 1. 위협 트렌드 분석
    yearly_totals = analyzer.analyze_threat_trends()
    
    # 2. 산업별 취약성 분석
    sector_data = analyzer.sector_vulnerability_analysis()
    
    # 3. 경제적 피해 분석
    total_damage = analyzer.calculate_economic_impact()
    
    # 4. 미래 위협 예측
    analyzer.predict_future_threats()
    
    # 5. 보안 투자 ROI
    analyzer.security_investment_roi(total_damage)
    
    # 6. 시각화 (옵션)
    analyzer.generate_threat_visualization(yearly_totals)
    
    print(f"\n" + "=" * 60)
    print(f"결론: 정보보안의 필요성")
    print(f"=" * 60)
    print(f"1. 사이버 위협은 매년 지속적으로 증가")
    print(f"2. 경제적 피해 규모가 GDP의 상당 부분을 차지")
    print(f"3. 모든 산업이 사이버 위협에 노출")
    print(f"4. 사전 예방이 사후 대응보다 경제적")
    print(f"5. 기술 발전과 함께 새로운 위협 지속 등장")
    
    print(f"\n권장사항:")
    recommendations = [
        "포괄적인 정보보안 정책 수립",
        "정기적인 보안 교육 및 인식 개선",
        "최신 보안 기술 도입 및 업데이트",
        "사고 대응 계획 수립 및 훈련",
        "공급망 보안 관리 강화",
        "국제 협력 및 정보 공유"
    ]
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")

if __name__ == "__main__":
    main()
```

## 마무리

이번 22강에서는 **정보보안의 역사 및 암호학 기초**를 다뤘습니다. **고대 암호부터 현대 암호까지의 발전 과정**, **대칭키와 비대칭키 암호화**, **에니그마 기계**, **현대 사회의 정보보안 위협** 등을 통해 정보보안 기술의 역사적 배경과 현재의 필요성을 이해했습니다.

다음 강의에서는 **개인정보보호의 기본 개념**을 학습하여 개인정보 보호의 중요성과 기본 원칙을 알아보겠습니다.

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*