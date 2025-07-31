#!/usr/bin/env python3
import requests 
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup, Comment
import argparse
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from tldextract import extract
import os
import sys
import random
import hashlib
from fake_useragent import UserAgent
import dns.resolver
import socket
import ssl
import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import csv
import xml.dom.minidom

class EliteSpider:
    def __init__(self, base_url, max_depth=5, delay=0.3, threads=15, output_dir="pentest_results", 
                 proxy=None, cookies=None, auth=None, extensions=None, brute=False):
        # Inicialize o UserAgent ANTES de qualquer outra coisa
        self.ua = UserAgent()
        
        # Agora continue com as outras inicializações
        self.base_url = self.normalize_url(base_url)
        self.domain_info = extract(base_url)
        self.domain = self.domain_info.fqdn
        self.visited = set()
        self.to_visit = set([(self.base_url, 0)])
        self.max_depth = max_depth
        self.delay = delay
        self.threads = threads
        self.output_dir = output_dir
        self.proxy = proxy
        self.cookies = cookies or {}
        self.auth = auth
        self.extensions = extensions or ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.json']
        self.brute = brute
        self.session = self.create_stealth_session() 
        self.ua = UserAgent()
        self.results = {
            'meta': {
                'target': self.base_url,
                'start_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'spider_version': 'EliteSpider 2.0'
            },
            'urls': [],
            'forms': [],
            'apis': [],
            'params': [],
            'tech_stack': [],
            'sensitive_files': [],
            'vulnerabilities': [],
            'network_info': {},
            'dns_info': {},
            'ssl_info': {},
            'subdomains': set(),
            'interesting_paths': []
        }
        self.create_output_dir()
        self.load_signatures()
        self.common_files = self.load_common_files()
        self.fuzz_params = self.load_fuzz_params()
        
    def load_signatures(self):
        """Carrega assinaturas para detecção de tecnologias e vulnerabilidades"""
        self.tech_signatures = {
            'wordpress': re.compile(r'wp-content|wp-includes|wordpress', re.I),
            'joomla': re.compile(r'joomla', re.I),
            'drupal': re.compile(r'drupal', re.I),
            'laravel': re.compile(r'laravel|_token', re.I),
            'asp_net': re.compile(r'__viewstate|asp.net', re.I),
            'php': re.compile(r'\.php\?|php_session', re.I),
            'nodejs': re.compile(r'node\.js|express', re.I)
        }
        
        self.vuln_signatures = {
            'sql_error': re.compile(r'sql.*error|syntax.*error|mysql.*error', re.I),
            'xss_possible': re.compile(r'<script>|alert\(|onerror=', re.I),
            'directory_listing': re.compile(r'index of /', re.I),
            'config_file': re.compile(r'config\.|database\.|settings\.', re.I)
        }
        
    def load_common_files(self):
        """Lista de arquivos comuns para verificar"""
        return [
            'robots.txt', '.htaccess', '.git/config', '.env', 
            'phpinfo.php', 'test.php', 'console', 'admin',
            'backup.zip', 'dump.sql', 'wp-config.php',
            'config.xml', 'web.config', 'crossdomain.xml'
        ]
    
    def load_fuzz_params(self):
        """Parâmetros comuns para fuzzing"""
        return {
            'sqli': ["'", "\"", "' OR '1'='1", "' OR 1=1--"],
            'xss': ["<script>alert(1)</script>", "\"><script>alert(1)</script>"],
            'lfi': ["../../../../etc/passwd", "....//....//....//....//etc/passwd"],
            'rce': [";id", "|id", "`id`", "$(id)"]
        }
    
    def create_output_dir(self):
        """Cria estrutura de diretórios para resultados"""
        subdirs = ['html', 'json', 'screenshots', 'reports']
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            for subdir in subdirs:
                os.makedirs(os.path.join(self.output_dir, subdir))
    
    def normalize_url(self, url):
        """Normaliza URLs para evitar duplicatas"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        path = parsed.path.rstrip('/') or '/'
        
        # Remove fragmentos e parâmetros de tracking
        clean_url = f"{parsed.scheme}://{parsed.netloc.lower()}{path}"
        return clean_url
    
    def create_stealth_session(self):
        """Cria sessão HTTP com técnicas de evasão"""
        session = requests.Session()
        
        # Configura proxies se especificado
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # Configura headers aleatórios
        session.headers = {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': 'https://www.google.com/',
            'DNT': str(random.randint(0, 1))
        }
        
        # Adiciona cookies se especificado
        if self.cookies:
            session.cookies.update(self.cookies)
        
        return session
    
    def is_same_domain(self, url):
        """Verifica se o URL pertence ao mesmo domínio ou subdomínio"""
        extracted = extract(url)
        return extracted.registered_domain == self.domain_info.registered_domain
    
    def get_network_info(self):
        """Coleta informações de rede do alvo"""
        try:
            # DNS Lookup
            answers = dns.resolver.resolve(self.domain, 'A')
            self.results['dns_info']['a_records'] = [str(r) for r in answers]
            
            # MX Records
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                self.results['dns_info']['mx_records'] = [str(r) for r in answers]
            except:
                pass
            
            # SSL Certificate Info
            hostname = self.domain_info.domain
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                cert = s.getpeercert(binary_form=True)
                x509cert = x509.load_der_x509_certificate(cert, default_backend())
                
                self.results['ssl_info'] = {
                    'issuer': dict(x509cert.issuer),
                    'subject': dict(x509cert.subject),
                    'version': x509cert.version,
                    'serial_number': x509cert.serial_number,
                    'not_valid_before': x509cert.not_valid_before.isoformat(),
                    'not_valid_after': x509cert.not_valid_after.isoformat(),
                    'signature_hash_algorithm': x509cert.signature_hash_algorithm.name
                }
                
        except Exception as e:
            print(f"[!] Erro ao coletar informações de rede: {e}", file=sys.stderr)
    
    def check_common_files(self):
        """Verifica arquivos comuns sensíveis"""
        for file in self.common_files:
            url = urljoin(self.base_url, file)
            try:
                response = self.session.head(url, timeout=10)
                if response.status_code == 200:
                    self.results['sensitive_files'].append({
                        'url': url,
                        'type': 'common_file',
                        'status': response.status_code
                    })
                    
                    # Se for robots.txt, faz parse
                    if file == 'robots.txt':
                        self.parse_robots(url)
            except:
                continue
    
    def parse_robots(self, url):
        """Faz parse do robots.txt e adiciona URLs interessantes"""
        try:
            response = self.session.get(url, timeout=10)
            for line in response.text.split('\n'):
                if line.startswith(('Allow:', 'Disallow:')):
                    path = line.split(':')[1].strip()
                    if path and not path.startswith('*'):
                        full_url = urljoin(self.base_url, path)
                        self.results['interesting_paths'].append(full_url)
                        if full_url not in self.visited:
                            self.to_visit.add((full_url, 0))
        except:
            pass
    
    def analyze_tech_stack(self, url, html):
        """Detecta tecnologias usadas pelo site"""
        detected = set()
        
        # Verifica tags meta
        soup = BeautifulSoup(html, 'html.parser')
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs and meta.attrs['name'].lower() == 'generator':
                detected.add(meta.attrs['content'].split()[0].lower())
        
        # Verifica comentários HTML
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            for tech, pattern in self.tech_signatures.items():
                if pattern.search(comment):
                    detected.add(tech)
        
        # Verifica URLs e scripts
        for tech, pattern in self.tech_signatures.items():
            if pattern.search(html):
                detected.add(tech)
        
        # Verifica headers HTTP
        response = self.session.get(url, timeout=10)
        server_header = response.headers.get('Server', '').lower()
        x_powered_by = response.headers.get('X-Powered-By', '').lower()
        
        if 'apache' in server_header:
            detected.add('apache')
        elif 'nginx' in server_header:
            detected.add('nginx')
        elif 'iis' in server_header:
            detected.add('iis')
        
        if 'php' in x_powered_by:
            detected.add('php')
        elif 'asp.net' in x_powered_by:
            detected.add('asp_net')
        
        # Adiciona ao resultado
        if detected:
            self.results['tech_stack'].append({
                'url': url,
                'technologies': list(detected)
            })
    
    def scan_for_vulnerabilities(self, url, html):
        """Verifica vulnerabilidades potenciais"""
        vulnerabilities = []
        
        # Verifica padrões de erro
        for vuln_type, pattern in self.vuln_signatures.items():
            if pattern.search(html):
                vulnerabilities.append(vuln_type)
        
        # Verifica formulários sem tokens CSRF
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            has_token = False
            for input_tag in form.find_all('input'):
                if input_tag.get('name', '').lower() in ('csrf_token', '_token', 'authenticity_token'):
                    has_token = True
                    break
            
            if not has_token and form.get('method', '').upper() == 'POST':
                vulnerabilities.append('potential_csrf')
        
        # Adiciona ao resultado
        if vulnerabilities:
            self.results['vulnerabilities'].append({
                'url': url,
                'types': vulnerabilities
            })
    
    def fuzz_parameters(self, url):
        """Testa parâmetros para vulnerabilidades básicas"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        if not params:
            return
        
        for param_name in params.keys():
            for vuln_type, payloads in self.fuzz_params.items():
                for payload in payloads:
                    try:
                        # Cria URL com payload fuzzado
                        fuzzed_params = params.copy()
                        fuzzed_params[param_name] = [payload]
                        fuzzed_query = '&'.join(
                            f"{k}={quote(v[0])}" for k, v in fuzzed_params.items()
                        )
                        fuzzed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{fuzzed_query}"
                        
                        # Envia requisição
                        time.sleep(self.delay)
                        response = self.session.get(fuzzed_url, timeout=10)
                        
                        # Verifica se o payload teve efeito
                        if vuln_type == 'sqli' and any(
                            term in response.text.lower() 
                            for term in ['sql', 'syntax', 'error']
                        ):
                            self.results['vulnerabilities'].append({
                                'url': url,
                                'param': param_name,
                                'type': 'possible_sqli',
                                'payload': payload,
                                'status': response.status_code
                            })
                        
                        elif vuln_type == 'xss' and payload in response.text:
                            self.results['vulnerabilities'].append({
                                'url': url,
                                'param': param_name,
                                'type': 'possible_xss',
                                'payload': payload,
                                'status': response.status_code
                            })
                        
                    except Exception as e:
                        print(f"[!] Erro ao testar {param_name} em {url}: {e}", file=sys.stderr)
    
    def extract_endpoints(self, html):
        """Extrai endpoints de APIs de arquivos JavaScript"""
        endpoints = set()
        
        # Padrões comuns de endpoints API
        patterns = [
            re.compile(r'fetch\(["\'](.*?)["\']'),
            re.compile(r'axios\.get\(["\'](.*?)["\']'),
            re.compile(r'\.ajax\(.*?url:\s*["\'](.*?)["\']'),
            re.compile(r'https?://[^"\'\s]+/api/[^"\'\s]+')
        ]
        
        for pattern in patterns:
            matches = pattern.findall(html)
            for match in matches:
                if not match.startswith(('http://', 'https://')):
                    match = urljoin(self.base_url, match)
                if self.is_same_domain(match):
                    endpoints.add(match)
        
        return endpoints
    
    def process_page(self, url, depth):
        """Processa uma página individual com todas as análises"""
        try:
            time.sleep(self.delay)
            
            # Salva o HTML para análise offline
            html_filename = os.path.join(self.output_dir, 'html', f"{hashlib.md5(url.encode()).hexdigest()}.html")
            
            response = self.session.get(url, timeout=15)
            
            # Verifica códigos de status interessantes
            if response.status_code in (401, 403):
                self.results['vulnerabilities'].append({
                    'type': 'access_control',
                    'url': url,
                    'status': response.status_code
                })
            elif response.status_code >= 500:
                self.results['vulnerabilities'].append({
                    'type': 'server_error',
                    'url': url,
                    'status': response.status_code
                })
            
            # Salva HTML
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Analisa tecnologias
            self.analyze_tech_stack(url, response.text)
            
            # Verifica vulnerabilidades
            self.scan_for_vulnerabilities(url, response.text)
            
            # Fuzz parâmetros se houver
            if '?' in url:
                self.fuzz_parameters(url)
            
            # Extrai endpoints API
            api_endpoints = self.extract_endpoints(response.text)
            for endpoint in api_endpoints:
                if endpoint not in self.results['apis']:
                    self.results['apis'].append(endpoint)
            
            # Extrai links
            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()
            
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'form'], href=True):
                full_url = urljoin(url, tag['href'])
                normalized = self.normalize_url(full_url)
                if self.is_same_domain(normalized):
                    links.add((normalized, depth + 1))
            
            # Analisa formulários
            for form in soup.find_all('form'):
                form_action = form.get('action', url)
                form_method = form.get('method', 'GET').upper()
                form_fields = []
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    field = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_fields.append(field)
                
                self.results['forms'].append({
                    'url': url,
                    'action': form_action,
                    'method': form_method,
                    'fields': form_fields
                })
            
            # Analisa URLs com parâmetros
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                self.results['params'].append({
                    'url': url,
                    'params': params,
                    'method': 'GET'
                })
            
            return links
        
        except Exception as e:
            print(f"[!] Erro ao processar {url}: {str(e)[:100]}", file=sys.stderr)
            return set()
    
    def brute_force_paths(self):
        """Realiza brute force de paths comuns se ativado"""
        if not self.brute:
            return
            
        common_paths = [
            'admin', 'login', 'wp-admin', 'administrator',
            'backup', 'config', 'phpmyadmin', 'dbadmin',
            'test', 'dev', 'api', 'graphql'
        ]
        
        for path in common_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.head(url, timeout=10)
                if response.status_code in (200, 301, 302, 403):
                    self.results['interesting_paths'].append(url)
                    if url not in self.visited:
                        self.to_visit.add((url, 0))
            except:
                continue
    
    def crawl(self):
        """Executa o crawling com múltiplas threads"""
        print(f"[*] Iniciando spider em {self.base_url} com profundidade {self.max_depth}")
        print(f"[*] Coletando informações de rede...")
        self.get_network_info()
        
        print(f"[*] Verificando arquivos comuns...")
        self.check_common_files()
        
        print(f"[*] Realizando brute force de paths...")
        self.brute_force_paths()
        
        print(f"[*] Iniciando crawling com {self.threads} threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            while self.to_visit or futures:
                # Submete novas tarefas enquanto houver URLs para visitar
                while self.to_visit and len(futures) < self.threads * 2:
                    url, depth = self.to_visit.pop()
                    if url not in self.visited and depth <= self.max_depth:
                        future = executor.submit(self.process_page, url, depth)
                        futures[future] = (url, depth)
                
                # Processa tarefas concluídas
                for future in as_completed(futures):
                    url, depth = futures.pop(future)
                    self.visited.add(url)
                    self.results['urls'].append(url)
                    
                    try:
                        new_links = future.result()
                        for link, new_depth in new_links:
                            if link not in self.visited and new_depth <= self.max_depth:
                                self.to_visit.add((link, new_depth))
                    except Exception as e:
                        print(f"[!] Erro ao processar resultados de {url}: {e}", file=sys.stderr)
        
        print("[*] Crawling concluído. Gerando relatórios...")
    
    def generate_reports(self):
        """Gera vários formatos de relatório"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Relatório JSON completo
        json_file = os.path.join(self.output_dir, 'json', f'scan_results_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Relatório HTML
        html_file = os.path.join(self.output_dir, 'reports', f'report_{timestamp}.html')
        self.generate_html_report(html_file)
        
        # Relatório CSV para planilhas
        csv_file = os.path.join(self.output_dir, 'reports', f'urls_{timestamp}.csv')
        self.generate_csv_report(csv_file)
        
        # Relatório XML para integração
        xml_file = os.path.join(self.output_dir, 'reports', f'report_{timestamp}.xml')
        self.generate_xml_report(xml_file)
        
        print(f"\n[+] Relatórios gerados em:")
        print(f"    - JSON completo: {json_file}")
        print(f"    - HTML: {html_file}")
        print(f"    - CSV: {csv_file}")
        print(f"    - XML: {xml_file}")
    
    def generate_html_report(self, filename):
        """Gera relatório HTML visual"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório de Pentest - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .vulnerability {{ background-color: #ffecec; padding: 10px; margin: 10px 0; border-left: 3px solid #ff6b6b; }}
        .tech {{ background-color: #e7f5ff; padding: 5px 10px; display: inline-block; margin: 2px; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>Relatório de Pentest - {self.domain}</h1>
    <p><strong>Data:</strong> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <h2>Resumo</h2>
    <ul>
        <li><strong>URLs encontradas:</strong> {len(self.results['urls'])}</li>
        <li><strong>Formulários encontrados:</strong> {len(self.results['forms'])}</li>
        <li><strong>APIs encontradas:</strong> {len(self.results['apis'])}</li>
        <li><strong>Vulnerabilidades encontradas:</strong> {len(self.results['vulnerabilities'])}</li>
    </ul>
    
    <h2>Tecnologias Detectadas</h2>
    <div>
                """)
            
            techs = set()
            for entry in self.results['tech_stack']:
                for tech in entry['technologies']:
                    techs.add(tech)
            
            for tech in techs:
                f.write(f'<span class="tech">{tech}</span> ')
            
            f.write("""
    </div>
    
    <h2>Vulnerabilidades</h2>
                """)
            
            for vuln in self.results['vulnerabilities']:
                f.write(f"""
    <div class="vulnerability">
        <h3>{vuln.get('type', 'Vulnerabilidade')}</h3>
        <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
        <p><strong>Detalhes:</strong> {json.dumps(vuln, indent=2)}</p>
    </div>
                """)
            
            f.write("""
    <h2>URLs Encontradas</h2>
    <table>
        <tr><th>URL</th></tr>
                """)
            
            for url in sorted(self.results['urls']):
                f.write(f"<tr><td>{url}</td></tr>")
            
            f.write("""
    </table>
</body>
</html>
            """)
    
    def generate_csv_report(self, filename):
        """Gera relatório CSV de URLs"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Tecnologias', 'Vulnerabilidades'])
            
            for url in self.results['urls']:
                techs = []
                for entry in self.results['tech_stack']:
                    if entry['url'] == url:
                        techs.extend(entry['technologies'])
                
                vulns = []
                for entry in self.results['vulnerabilities']:
                    if entry.get('url') == url:
                        vulns.append(entry.get('type'))
                
                writer.writerow([
                    url,
                    '200',  # Poderia ser verificado, mas simplificando
                    ', '.join(techs),
                    ', '.join(vulns)
                ])
    
    def generate_xml_report(self, filename):
        """Gera relatório XML para integração com outras ferramentas"""
        root = ET.Element("pentest_report")
        meta = ET.SubElement(root, "meta")
        ET.SubElement(meta, "target").text = self.base_url
        ET.SubElement(meta, "date").text = time.strftime("%Y-%m-%d %H:%M:%S")
        
        urls = ET.SubElement(root, "urls")
        for url in self.results['urls']:
            ET.SubElement(urls, "url").text = url
        
        vulns = ET.SubElement(root, "vulnerabilities")
        for vuln in self.results['vulnerabilities']:
            v = ET.SubElement(vulns, "vulnerability")
            ET.SubElement(v, "type").text = vuln.get('type', '')
            ET.SubElement(v, "url").text = vuln.get('url', '')
            ET.SubElement(v, "details").text = json.dumps(vuln)
        
        # Formata o XML para legibilidade
        xml_str = ET.tostring(root, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)
    
    def run(self):
        """Executa o spider completo"""
        start_time = time.time()
        
        try:
            self.crawl()
            self.generate_reports()
            
            elapsed = time.time() - start_time
            print(f"\n[+] Scan concluído em {elapsed:.2f} segundos")
            print(f"[+] Total de URLs encontradas: {len(self.results['urls'])}")
            print(f"[+] Vulnerabilidades encontradas: {len(self.results['vulnerabilities'])}")
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrompido pelo usuário. Salvando resultados parciais...")
            self.generate_reports()
        except Exception as e:
            print(f"\n[!] Erro fatal: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🕷️ EliteSpider - Ferramenta Avançada de Web Crawling e Pentest",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("url", help="URL alvo (ex: https://bancocn.com)")
    parser.add_argument("-d", "--depth", type=int, default=5, 
                       help="Profundidade máxima de crawling")
    parser.add_argument("-t", "--threads", type=int, default=15,
                       help="Número de threads paralelas")
    parser.add_argument("-o", "--output", default="pentest_results",
                       help="Diretório de saída para os resultados")
    parser.add_argument("--delay", type=float, default=0.3,
                       help="Atraso entre requisições (em segundos)")
    parser.add_argument("--proxy", 
                       help="Proxy a ser usado (ex: http://127.0.0.1:8080)")
    parser.add_argument("--cookies", 
                       help="Cookies em formato JSON (ex: '{\"session\":\"value\"}')")
    parser.add_argument("--auth", 
                       help="Credenciais de autenticação (user:pass)")
    parser.add_argument("--brute", action="store_true",
                       help="Ativar brute force de paths comuns")
    
    args = parser.parse_args()
    
    # Configura cookies se fornecidos
    cookies = {}
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print("[!] Formato de cookies inválido. Use JSON.", file=sys.stderr)
            sys.exit(1)
    
    # Configura autenticação se fornecida
    auth = None
    if args.auth:
        if ':' in args.auth:
            username, password = args.auth.split(':', 1)
            auth = (username, password)
        else:
            print("[!] Formato de autenticação inválido. Use user:pass", file=sys.stderr)
            sys.exit(1)
    
    print(f"""
    ███████╗██╗     ██╗████████╗███████╗
    ██╔════╝██║     ██║╚══██╔══╝██╔════╝
    █████╗  ██║     ██║   ██║   █████╗  
    ██╔══╝  ██║     ██║   ██║   ██╔══╝  
    ███████╗███████╗██║   ██║   ███████╗
    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝
    EliteSpider 2.0 - Spider de Pentest Avançado
    Alvo: {args.url}
    """)
    
    spider = EliteSpider(
        base_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        threads=args.threads,
        output_dir=args.output,
        proxy=args.proxy,
        cookies=cookies,
        auth=auth,
        brute=args.brute
    )
    
    spider.run()