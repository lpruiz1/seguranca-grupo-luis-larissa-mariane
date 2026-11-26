import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CLI = Path(__file__).resolve().parent.parent / "src" / "seguranca.py"
CONTEUDO = b"Declaracao ficticia: Fulano de Tal concluiu o curso XYZ.\n"


def run(*args):
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


@pytest.fixture
def doc(tmp_path):
    f = tmp_path / "documento.txt"
    f.write_bytes(CONTEUDO)
    return f


@pytest.fixture
def chaves(tmp_path):
    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    assert run("keygen", priv, pub).returncode == 0
    return priv, pub


# TI01
def test_ti01_hash_correto(doc):
    r = run("hash", doc)
    assert r.returncode == 0
    esperado = hashlib.sha256(CONTEUDO).hexdigest()
    assert r.stdout.strip() == esperado
    assert len(esperado) == 64 and esperado == esperado.lower()


# TI02
def test_ti02_arquivo_modificado_diverge(doc):
    original = run("hash", doc).stdout.strip()
    assert run("check", doc, original).returncode == 0
    doc.write_bytes(CONTEUDO + b"x")
    r = run("check", doc, original)
    assert r.returncode != 0
    assert "NÃO" in r.stdout


# TI03
def test_ti03_pem_validos(chaves):
    priv, pub = chaves
    assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")      # PKCS#8
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")        # SPKI
    k_priv = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    k_pub = serialization.load_pem_public_key(pub.read_bytes())
    assert isinstance(k_priv, Ed25519PrivateKey)
    assert isinstance(k_pub, Ed25519PublicKey)


# TI04
def test_ti04_assina_e_verifica(doc, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    assert run("sign", doc, priv, sig).returncode == 0
    assert len(sig.read_bytes()) == 64
    r = run("verify", doc, pub, sig)
    assert r.returncode == 0
    assert "VÁLIDA" in r.stdout and "INVÁLIDA" not in r.stdout


# TI05
def test_ti05_alteracao_apos_assinatura(doc, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    run("sign", doc, priv, sig)
    doc.write_bytes(CONTEUDO.replace(b"XYZ", b"ABC"))
    r = run("verify", doc, pub, sig)
    assert r.returncode != 0
    assert "INVÁLIDA" in r.stdout


# TI06
def test_ti06_outra_chave_publica(doc, chaves, tmp_path):
    priv, _ = chaves
    outra_priv, outra_pub = tmp_path / "p2.pem", tmp_path / "pub2.pem"
    run("keygen", outra_priv, outra_pub)
    sig = tmp_path / "assinatura.sig"
    run("sign", doc, priv, sig)
    r = run("verify", doc, outra_pub, sig)
    assert r.returncode != 0
    assert "INVÁLIDA" in r.stdout


# Interoperabilidade: assinatura deve ser Ed25519 puro sobre os bytes originais
def test_interop_assinatura_bytes_originais(doc, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    run("sign", doc, priv, sig)
    k_pub = serialization.load_pem_public_key(pub.read_bytes())
    k_pub.verify(sig.read_bytes(), CONTEUDO)  # levanta exceção se inválida


# Tratamento de erros
def test_erro_arquivo_inexistente(tmp_path):
    r = run("hash", tmp_path / "nao_existe.txt")
    assert r.returncode != 0 and "ERRO" in r.stderr


def test_erro_hash_referencia_malformado(doc):
    r = run("check", doc, "abc")
    assert r.returncode != 0 and "ERRO" in r.stderr


def test_erro_chave_trocada(doc, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "s.sig"
    assert run("sign", doc, pub, sig).returncode != 0        # pública no lugar da privada
    run("sign", doc, priv, sig)
    assert run("verify", doc, priv, sig).returncode != 0     # privada no lugar da pública


def test_erro_assinatura_tamanho_errado(doc, chaves, tmp_path):
    _, pub = chaves
    sig = tmp_path / "s.sig"
    sig.write_bytes(b"\x00" * 10)
    r = run("verify", doc, pub, sig)
    assert r.returncode != 0 and "INVÁLIDA" in r.stdout


def test_erro_diretorio_como_arquivo(tmp_path):
    r = run("hash", tmp_path)
    assert r.returncode != 0 and "ERRO" in r.stderr
