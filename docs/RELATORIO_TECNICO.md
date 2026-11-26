# Relatório Técnico - Etapa 1

## 1. Identificação

- **Integrantes:** Luís Phillipe Ruiz Gama, Larissa Ribeiro Savino, Mariane dos Santos Oliveira
- **Turma:** 5
- **Linguagem:** Python 3
- **Repositório:** https://github.com/lpruiz1/seguranca-grupo-luis-larissa-mariane
- **Divisão:** Luís Phillipe - estrutura, CLI base, `keygen`/`hash`/`check` (R01-R03), README; Larissa Savino - `sign`/`verify` (R04-R06), relatório; Mariane Oliveira - testes TI01-TI06, testes de erro, exemplos e evidências.

## 2. Descrição da Solução

- **Biblioteca:** `cryptography` (PyCA), para Ed25519 e serialização PEM; `hashlib` (biblioteca padrão) para SHA-256; `pytest` para testes.
- **Organização:** `src/seguranca.py` (CLI com `argparse`, um subcomando por operação); `tests/test_seguranca.py` (testes que executam a CLI via subprocess); `exemplos/` (documento fictício).
- **Decisões técnicas:**
  - Ed25519 puro (`sign(data)` sobre os bytes do arquivo), sem pré-hash, conforme o contrato.
  - Hash calculado em blocos de 64 KiB, permitindo arquivos grandes.
  - Comparação de hash com `hmac.compare_digest`; referência validada (64 hex) e normalizada para minúsculas.
  - Tipo da chave validado após o carregamento, rejeitando chaves não Ed25519 ou trocadas (pública ↔ privada).
  - Assinatura com tamanho diferente de 64 bytes é rejeitada antes da verificação.
  - Códigos de saída: `0` sucesso, `1` verificação falhou, `2` erro. Erros vão para stderr com prefixo `ERRO:`.

## 3. Funcionalidades Implementadas

| Req. | Descrição | Implementação |
|---|---|---|
| R01 | Gerar par Ed25519 | `keygen` (PKCS#8 / SPKI, PEM) |
| R02 | Calcular SHA-256 | `hash` |
| R03 | Comparar com referência | `check` |
| R04 | Assinar com chave privada | `sign` |
| R05 | Verificar com chave pública | `verify` |
| R06 | Rejeitar assinaturas inválidas | `verify` retorna `INVÁLIDA` e código 1 |

## 4. Testes Realizados

Execução: `python -m pytest -v` (evidência: `docs/evidencias/pytest.txt`).

| ID | Teste | Esperado | Resultado |
|---|---|---|---|
| TI01 | SHA-256 de um arquivo | Hash correto | Aprovado |
| TI02 | Modificar arquivo e comparar | Divergência | Aprovado |
| TI03 | Gerar par de chaves | PEM válidos | Aprovado |
| TI04 | Assinar e verificar original | Válida | Aprovado |
| TI05 | Alterar após assinatura | Inválida | Aprovado |
| TI06 | Verificar com outra chave pública | Inválida | Aprovado |
| Extra | Interoperabilidade, arquivo inexistente, hash malformado, chaves trocadas, assinatura com tamanho incorreto, diretório como arquivo | Erro / Inválida | Aprovado |

Também validado contra OpenSSL (`sha256sum` e `openssl pkeyutl -verify -rawin`).

## 5. Análise Técnica e Conclusão

**Limitações:** chave privada armazenada sem senha; sem vínculo entre chave pública e identidade (não há certificado/ICP); sem carimbo de tempo; o arquivo é lido inteiro na memória para assinar (Ed25519 puro exige a mensagem completa).

**1. Por que um hash SHA-256 isolado não comprova autoria?**
O hash só depende do conteúdo e qualquer pessoa pode calculá-lo. Ele detecta alteração, mas não envolve nenhum segredo; quem altera o documento pode simplesmente publicar o novo hash.

**2. Função das chaves pública e privada?**
A privada, conhecida apenas pelo signatário, gera a assinatura. A pública, distribuída livremente, permite a qualquer um verificar que a assinatura foi produzida pela privada correspondente, sem poder gerar novas assinaturas.

**3. Por que alterar o documento invalida a assinatura?**
A assinatura é calculada sobre os bytes exatos do documento. Na verificação, qualquer alteração (mesmo de um bit) faz a equação de verificação do Ed25519 falhar, e produzir uma assinatura válida para o novo conteúdo exigiria a chave privada.

**4. Cuidados adicionais para produção?**
Proteger a chave privada (senha/criptografia, HSM ou cofre de chaves, permissões restritas); vincular a chave pública à instituição via certificado digital (ICP-Brasil); carimbo de tempo; procedimento de revogação e rotação de chaves; registro de auditoria; distribuição da chave pública por canal confiável.
