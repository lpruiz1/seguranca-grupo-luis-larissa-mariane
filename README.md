# seguranca - Integridade SHA-256 e Assinatura Ed25519

Ferramenta CLI para calcular/comparar hashes SHA-256 e gerar/verificar assinaturas digitais Ed25519.
Relatório técnico: [docs/RELATORIO_TECNICO.md](docs/RELATORIO_TECNICO.md).

## Requisitos

- Python 3.9+
- Dependências: `cryptography`, `pytest` (ver `requirements.txt`)

## Instalação

```bash
git clone https://github.com/lpruiz1/seguranca-grupo-luis-larissa-mariane
cd seguranca-grupo-luis-larissa-mariane
```

Crie e ative o ambiente virtual conforme o sistema:

| Sistema / terminal | Criar | Ativar |
|---|---|---|
| Linux / macOS | `python3 -m venv venv` | `source venv/bin/activate` |
| Windows (PowerShell) | `python -m venv venv` | `venv\Scripts\Activate.ps1` |
| Windows (cmd) | `python -m venv venv` | `venv\Scripts\activate.bat` |

Com o ambiente ativado, instale as dependências:

```bash
pip install -r requirements.txt
```

Com o ambiente ativado, o comando `python` funciona em todos os sistemas (inclusive Linux/macOS), por isso é usado no resto deste README.

Se o PowerShell bloquear a ativação ("execução de scripts foi desabilitada"), rode antes:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Execução

Forma exata de execução (a partir da raiz do repositório):

```bash
python src/seguranca.py <comando> [argumentos]
```

| Comando | Uso | Saída |
|---|---|---|
| `keygen` | `python src/seguranca.py keygen chave_privada.pem chave_publica.pem` | Gera PKCS#8 (privada) e SubjectPublicKeyInfo (pública), PEM |
| `hash` | `python src/seguranca.py hash documento.txt` | Hash SHA-256 (64 hex minúsculos) |
| `check` | `python src/seguranca.py check documento.txt HASH_REFERENCIA` | `OK` / `FALHA` |
| `sign` | `python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig` | Arquivo binário de 64 bytes |
| `verify` | `python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig` | `VÁLIDA` / `INVÁLIDA` |

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Sucesso (hash confere / assinatura válida) |
| `1` | Verificação falhou (hash divergente / assinatura inválida) |
| `2` | Erro (arquivo inexistente, chave inválida ou incompatível, argumentos incorretos) |

## Exemplo completo

Os comandos abaixo funcionam igual no Linux, macOS e Windows (PowerShell ou cmd). As chaves e a assinatura geradas em `exemplos/` são ignoradas pelo git.

```bash
cd exemplos
python ../src/seguranca.py keygen priv.pem pub.pem
python ../src/seguranca.py hash declaracao_ficticia.txt
python ../src/seguranca.py check declaracao_ficticia.txt 74700ad4fd7a7a9933f8af12fc8fe1631186e16b96f44f383caf9c6602afd749
python ../src/seguranca.py sign declaracao_ficticia.txt priv.pem assinatura.sig
python ../src/seguranca.py verify declaracao_ficticia.txt pub.pem assinatura.sig   # VÁLIDA, exit 0
echo "alteracao" >> declaracao_ficticia.txt
python ../src/seguranca.py verify declaracao_ficticia.txt pub.pem assinatura.sig   # INVÁLIDA, exit 1
git checkout declaracao_ficticia.txt   # desfaz a alteração
```

Para ver o código de saída do último comando:

| Sistema / terminal | Comando |
|---|---|
| Linux / macOS | `echo $?` |
| Windows (PowerShell) | `echo $LASTEXITCODE` |
| Windows (cmd) | `echo %ERRORLEVEL%` |

## Testes

```bash
python -m pytest -v
```

Cobrem TI01 - TI06 do enunciado, verificação de interoperabilidade (assinatura Ed25519 sobre os bytes originais) e tratamento de erros.

## Contrato de interoperabilidade

- Hash: SHA-256, 64 caracteres hexadecimais minúsculos (`check` aceita referência em maiúsculas).
- Assinatura: Ed25519 puro sobre os bytes originais do arquivo, sem pré-hash.
- Chave pública: PEM SubjectPublicKeyInfo. Chave privada: PEM PKCS#8, sem senha.
- Assinatura: arquivo binário com exatamente 64 bytes.
- Arquivos lidos em modo binário, sem alteração.