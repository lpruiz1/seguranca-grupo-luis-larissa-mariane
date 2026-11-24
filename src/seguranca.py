import argparse
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_FAIL = 1   # verificação falhou (hash divergente/assinatura inválida)
EXIT_ERROR = 2  # erro de uso, arquivo, chave etc


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seguranca",
        description="Integridade SHA-256 e assinatura digital Ed25519.",
    )
    p.add_subparsers(dest="comando", required=True)
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
