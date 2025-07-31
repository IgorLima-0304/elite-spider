# 📜 EliteSpider - Web Crawler para Pentest

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**EliteSpider** é um crawler inteligente para testes de penetração web, projetado para mapear aplicações e identificar vulnerabilidades comuns automaticamente.
Feito para estudo em segurança da informação.

## 🚀 Funcionalidades

- ✔️ Crawling profundo com controle de profundidade
- ✔️ Detecção automática de tecnologias (CMS, frameworks)
- ✔️ Identificação de vulnerabilidades (SQLi, XSS, CSRF)
- ✔️ Varredura de arquivos sensíveis (robots.txt, .env)
- ✔️ Análise de certificados SSL/TLS
- ✔️ Relatórios em múltiplos formatos (HTML, JSON, CSV)

## 📦 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/elitespider.git
cd elitespider
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## 🛠 Uso Básico

```bash
python spider.py https://exemplo.com --depth 3 --threads 10 --output scan_resultados
```

### Parâmetros Principais:
| Opção        | Descrição                          | Padrão  |
|--------------|------------------------------------|---------|
| `--depth`    | Profundidade máxima de crawling    | 2       |
| `--threads`  | Número de threads paralelas        | 15      |
| `--output`   | Diretório de saída                 | results |
| `--brute`    | Ativar brute force em paths        | False   |

## 🧩 Funcionalidades Avançadas

### Autenticação Básica
```bash
python spider.py https://exemplo.com --auth usuario:senha
```

### Fuzzing de Parâmetros
Ative o modo brute force para testar paths comuns:
```bash
python spider.py https://exemplo.com --brute
```

## 📊 Saída do Projeto

Estrutura de diretórios gerada:
```
results/
├── html/           # Cópias locais das páginas
├── json/           # Dados completos em JSON
├── reports/        # Relatórios formatados
│   ├── report.html # Relatório visual
│   ├── urls.csv    # Lista de URLs
│   └── scan.xml    # Saída em XML
└── screenshots/    # Capturas de tela (opcional)
```

## ⚠️ Avisos Importantes

1. Use apenas em sistemas com **permissão explícita**
2. Configure um delay adequado entre requisições
3. Verifique as leis locais antes de utilizar

## 📄 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🤝 Como Contribuir

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/incrivel`)
3. Commit suas mudanças (`git commit -m 'Adiciona feature incrível'`)
4. Push para a branch (`git push origin feature/incrível`)
5. Abra um Pull Request

---

> **Nota**: Este projeto é destinado apenas para fins legais de teste de segurança. O uso não autorizado em sistemas sem permissão é estritamente proibido.
