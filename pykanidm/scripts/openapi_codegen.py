#!/usr/bin/env python3
"""Generate the OpenAPI client package for pykanidm.

This downloads the OpenAPI spec (or uses a local file) and runs the
OpenAPI Generator via Docker. The generated package is copied into
pykanidm/kanidm_openapi_client.
"""

from __future__ import annotations

import argparse
import os
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path
from urllib.request import urlopen


DEFAULT_SPEC_URL = "https://localhost:8443/docs/v1/openapi.json"
DEFAULT_PACKAGE = "kanidm_openapi_client"
DEFAULT_GENERATOR = "python"
DEFAULT_GENERATOR_IMAGE = "openapitools/openapi-generator-cli"
DEFAULT_LIBRARY = "asyncio"


def _download_spec(url: str, dest: Path, verify_tls: bool) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    context = None if verify_tls else ssl._create_unverified_context()
    with urlopen(url, context=context) as response:
        dest.write_bytes(response.read())


def _run_generator(
    spec_path: Path,
    output_dir: Path,
    package_name: str,
    generator: str,
    image: str,
    library: str,
) -> None:
    additional_properties = [
        f"packageName={package_name}",
        "projectName=kanidm-openapi-client",
        "packageVersion=0.0.0",
        "hideGenerationTimestamp=true",
    ]
    if library:
        additional_properties.append(f"library={library}")
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{spec_path.parent}:/spec",
        "-v",
        f"{output_dir}:/out",
        image,
        "generate",
        "-g",
        generator,
        "-i",
        "/spec/openapi.json",
        "-o",
        "/out",
        "--additional-properties",
        ",".join(additional_properties),
    ]
    subprocess.run(cmd, check=True)


def _write_notice(target: Path, spec_url: str, generator: str) -> None:
    notice = target / "_GENERATED_NOTICE.txt"
    notice.write_text(
        "\n".join(
            [
                "This package is auto-generated. Do not edit by hand.",
                f"Spec URL: {spec_url}",
                f"Generator: {generator}",
                "",
                "To regenerate:",
                "  python pykanidm/scripts/openapi_codegen.py",
            ]
        )
        + "\n"
    )


def main() -> int:
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
        "--output",
        type=Path,
        default=Path("pykanidm") / DEFAULT_PACKAGE,
        help=f"Output directory for the generated package (default: pykanidm/{DEFAULT_PACKAGE}).",
    )
    parser.add_argument(
        "--package-name",
        default=DEFAULT_PACKAGE,
        help=f"Generated Python package name (default: {DEFAULT_PACKAGE}).",
    )
    parser.add_argument(
        "--generator",
        default=DEFAULT_GENERATOR,
        help=f"OpenAPI generator name (default: {DEFAULT_GENERATOR}).",
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

    args = parser.parse_args()

    output_dir = args.output.resolve()
    spec_url = args.spec_url

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        spec_path = tmp_path / "openapi.json"
        if args.spec_file is not None:
            spec_path.write_bytes(args.spec_file.read_bytes())
        else:
            _download_spec(spec_url, spec_path, verify_tls=args.verify_tls)

        gen_out = tmp_path / "out"
        gen_out.mkdir(parents=True, exist_ok=True)

        _run_generator(spec_path, gen_out, args.package_name, args.generator, args.generator_image, args.library)

        generated_pkg = gen_out / args.package_name
        if not generated_pkg.exists():
            raise FileNotFoundError(f"Expected generated package not found: {generated_pkg}")

        if output_dir.exists():
            shutil.rmtree(output_dir)
        shutil.copytree(generated_pkg, output_dir)
        _write_notice(output_dir, spec_url, args.generator)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
