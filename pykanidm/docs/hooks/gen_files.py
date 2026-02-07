import sys
from pathlib import Path

import mkdocs_gen_files


def main() -> None:

    pykanidm_dir = Path(__file__).parent.parent.parent
    docs_dir = pykanidm_dir / "docs"
    readme_src = pykanidm_dir / "README.md"
    target_index = Path("index.md")
    # target_readme = Path("pykanidm") / "README.md"
    if not readme_src.exists():
        raise FileNotFoundError(readme_src)

    readme_text = readme_src.read_text(encoding="utf-8")
    with mkdocs_gen_files.open(target_index, "w", encoding="utf-8") as fp:
        fp.write(readme_text)
        print(f"Generated README.md for documentation at {docs_dir / target_index}", file=sys.stderr)

    # with mkdocs_gen_files.open(target_readme, "w", encoding="utf-8") as fp:
    #     fp.write(readme_text)
    #     print(f"Generated README.md for documentation at {docs_dir / target_readme}", file=sys.stderr)

    mkdocs_gen_files.set_edit_path(target_index, readme_src)
    # mkdocs_gen_files.set_edit_path(target_readme, readme_src)

    workspace_dir = pykanidm_dir.parent
    logo_small = workspace_dir / "artwork/logo-small.png"
    target_logo = docs_dir / "assets/logo-small.png"

    if target_logo.exists():
        print(f"logo-small.png already exists at {target_logo}, skipping generation", file=sys.stderr)
    else:
        if logo_small.exists():
            if not target_logo.parent.exists():
                target_logo.parent.mkdir(parents=True)
            with mkdocs_gen_files.open(target_logo, "wb") as fp:
                fp.write(logo_small.read_bytes())
                print(f"Generated logo-small.png for documentation at {target_logo}", file=sys.stderr)

            mkdocs_gen_files.set_edit_path(target_logo, logo_small)
        else:
            print(f"Warning: logo-small.png not found at {logo_small}", file=sys.stderr)


main()
