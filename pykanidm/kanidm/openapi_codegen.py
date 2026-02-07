"""Generate the OpenAPI client package for pykanidm.

This module supports both command-line and programmatic use.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
import importlib
import os
import shutil
import ssl
import tempfile
from pathlib import Path
from typing import Any, Sequence
from urllib.request import urlopen


DEFAULT_SPEC_URL = "https://localhost:8443/docs/v1/openapi.json"
DEFAULT_PACKAGE = "kanidm_openapi_client"
DEFAULT_GENERATOR_IMAGE = "openapitools/openapi-generator-cli"
DEFAULT_LIBRARY = "asyncio"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / DEFAULT_PACKAGE
DEFAULT_CA_PATH_ENV = os.getenv("KANIDM_CA_PATH")


def _load_docker_module() -> Any:
    try:
        return importlib.import_module("docker")
    except ImportError as exc:
        raise RuntimeError(
            "OpenAPI codegen requires the optional feature 'openapi_codegen'. Install with: pip install 'kanidm[openapi_codegen]'"
        ) from exc


def _download_spec(url: str, dest: Path, verify_tls: bool, ca_file: Path | None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)

    if verify_tls:
        if ca_file is None:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context(cafile=str(ca_file))
    else:
        context = ssl._create_unverified_context()

    with urlopen(url, context=context) as response:
        dest.write_bytes(response.read())


@lru_cache()
def _get_project_version() -> str:
    # Attempt to get the version from the package metadata
    try:
        import importlib.metadata

        return importlib.metadata.version("kanidm")
    except (importlib.metadata.PackageNotFoundError, ImportError):
        return "0.0.0"


def _run_generator(
    spec_path: Path,
    output_dir: Path,
    package_name: str,
    image: str,
    library: str,
) -> None:
    docker = _load_docker_module()

    additional_properties = [
        f"packageName={package_name}",
        "projectName=kanidm",
        f"packageVersion={_get_project_version()}",
        "hideGenerationTimestamp=false",
        f"httpUserAgent=kanidm-python/{_get_project_version()}",
    ]
    if library:
        additional_properties.append(f"library={library}")

    command = [
        "generate",
        "-g",
        "python",
        "-i",
        "/spec/openapi.json",
        "-o",
        "/out",
        "--additional-properties",
        ",".join(additional_properties),
    ]

    client = docker.from_env()
    try:
        client.containers.run(
            image=image,
            command=command,
            remove=True,
            volumes={
                str(spec_path.parent): {"bind": "/spec", "mode": "ro"},
                str(output_dir): {"bind": "/out", "mode": "rw"},
            },
        )
    except docker.errors.ContainerError as exc:
        logs = ""
        if exc.stderr is not None:
            logs = exc.stderr.decode("utf-8", errors="replace")
        elif exc.stdout is not None:
            logs = exc.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAPI generator container failed: {logs}") from exc
    finally:
        client.close()


def _write_notice(target: Path, spec_source: str) -> None:
    notice = target / "_GENERATED_NOTICE.txt"
    notice.write_text(
        "\n".join(
            [
                "This package is auto-generated. Do not edit by hand.",
                f"Spec source: {spec_source}",
                "Generator: kanidm_openapi_codegen",
                "",
                "To regenerate:",
                "  uv run kanidm_openapi_codegen",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def generate_openapi_client(
    *,
    spec_url: str = DEFAULT_SPEC_URL,
    spec_file: Path | None = None,
    verify_tls: bool = False,
    ca_file: Path | None = None,
    output: Path = DEFAULT_OUTPUT,
    package_name: str = DEFAULT_PACKAGE,
    generator_image: str = DEFAULT_GENERATOR_IMAGE,
    library: str = DEFAULT_LIBRARY,
) -> Path:
    """Generate the OpenAPI package and return the generated output directory."""
    output_dir = output.resolve()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        spec_path = tmp_path / "openapi.json"

        if spec_file is not None:
            spec_path.write_bytes(spec_file.read_bytes())
            spec_source = str(spec_file)
        else:
            _download_spec(spec_url, spec_path, verify_tls=verify_tls, ca_file=ca_file)
            spec_source = spec_url

        gen_out = tmp_path / "out"
        gen_out.mkdir(parents=True, exist_ok=True)

        _run_generator(
            spec_path=spec_path,
            output_dir=gen_out,
            package_name=package_name,
            image=generator_image,
            library=library,
        )

        generated_pkg = gen_out / package_name
        if not generated_pkg.exists():
            raise FileNotFoundError(f"Expected generated package not found: {generated_pkg}")

        if output_dir.exists():
            shutil.rmtree(output_dir)
        shutil.copytree(generated_pkg, output_dir)
        _write_notice(output_dir, spec_source=spec_source)

    return output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the OpenAPI client package for pykanidm.")
    parser.add_argument(
        "--spec-url",
        default=os.getenv("KANIDM_OPENAPI_SPEC_URL", DEFAULT_SPEC_URL),
        help=f"OpenAPI spec URL (default: {DEFAULT_SPEC_URL})",
    )
    parser.add_argument(
        "--spec-file",
        type=Path,
        help="Use a local OpenAPI spec file instead of downloading.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS when downloading the spec (default: disabled).",
    )
    parser.add_argument(
        "--ca-file",
        type=Path,
        default=Path(DEFAULT_CA_PATH_ENV) if DEFAULT_CA_PATH_ENV is not None else None,
        help="CA file path for TLS verification (default: KANIDM_CA_PATH if set).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory for the generated package (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--package-name",
        default=DEFAULT_PACKAGE,
        help=f"Generated Python package name (default: {DEFAULT_PACKAGE}).",
    )
    parser.add_argument(
        "--generator-image",
        default=os.getenv("KANIDM_OPENAPI_GENERATOR_IMAGE", DEFAULT_GENERATOR_IMAGE),
        help=f"OpenAPI generator Docker image (default: {DEFAULT_GENERATOR_IMAGE}).",
    )
    parser.add_argument(
        "--library",
        default=os.getenv("KANIDM_OPENAPI_LIBRARY", DEFAULT_LIBRARY),
        help=f"OpenAPI generator library (default: {DEFAULT_LIBRARY}).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    generate_openapi_client(
        spec_url=args.spec_url,
        spec_file=args.spec_file,
        verify_tls=args.verify_tls,
        ca_file=args.ca_file,
        output=args.output,
        package_name=args.package_name,
        generator_image=args.generator_image,
        library=args.library,
    )
    print(f"Success! Wrote code to {args.output}")
    return 0
