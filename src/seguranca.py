import argparse
import hashlib
import hmac
import re
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_FAIL = 1   # verificação falhou (hash divergente/assinatura inválida)
EXIT_ERROR = 2  # erro de uso, arquivo, chave etc

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class ToolError(Exception):
    """Erro apresentável ao usuário."""


def read_bytes(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise ToolError(f"arquivo não encontrado: {path}")
    if not p.is_file():
        raise ToolError(f"caminho não é um arquivo: {path}")
    try:
        return p.read_bytes()
    except OSError as e:
        raise ToolError(f"não foi possível ler '{path}': {e.strerror}") from e


def write_bytes(path: str, data: bytes) -> None:
    p = Path(path)
    if p.parent and not p.parent.exists():
        raise ToolError(f"diretório inexistente: {p.parent}")
    try:
        p.write_bytes(data)
    except OSError as e:
        raise ToolError(f"não foi possível escrever '{path}': {e.strerror}") from e


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    p = Path(path)
    if not p.exists():
        raise ToolError(f"arquivo não encontrado: {path}")
    if not p.is_file():
        raise ToolError(f"caminho não é um arquivo: {path}")
    try:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        raise ToolError(f"não foi possível ler '{path}': {e.strerror}") from e
    return h.hexdigest()


# ---------- comandos ----------

def cmd_hash(args) -> int:
    print(sha256_file(args.arquivo))
    return EXIT_OK


def cmd_check(args) -> int:
    ref = args.hash_referencia.strip()
    if not HEX64.match(ref):
        raise ToolError("hash de referência inválido: esperado 64 caracteres hexadecimais")
    calc = sha256_file(args.arquivo)
    if hmac.compare_digest(calc, ref.lower()):
        print("OK: o hash corresponde à referência")
        return EXIT_OK
    print("FALHA: o hash NÃO corresponde à referência")
    print(f"  calculado:  {calc}")
    print(f"  referência: {ref.lower()}")
    return EXIT_FAIL


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seguranca",
        description="Integridade SHA-256 e assinatura digital Ed25519.",
    )
    sub = p.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("hash", help="calcula SHA-256 de um arquivo")
    s.add_argument("arquivo")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("check", help="compara SHA-256 com valor de referência")
    s.add_argument("arquivo")
    s.add_argument("hash_referencia")
    s.set_defaults(func=cmd_check)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ToolError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
