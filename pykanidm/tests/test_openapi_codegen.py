from pathlib import Path

from kanidm.openapi_codegen import _patch_generated_to_json_model_dump_json


def test_patch_generated_to_json_model_dump_json(tmp_path: Path) -> None:
    package_dir = tmp_path / "kanidm_openapi_client"
    models_dir = package_dir / "models"
    models_dir.mkdir(parents=True)

    model_file = models_dir / "sample_model.py"
    model_file.write_text(
        """import json

class Sample:
    def to_json(self) -> str:
        \"\"\"Returns the JSON representation of the model using alias\"\"\"
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())
""",
        encoding="utf-8",
    )

    replacements = _patch_generated_to_json_model_dump_json(package_dir)
    assert replacements == 1

    patched = model_file.read_text(encoding="utf-8")
    assert "# TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead" not in patched
    assert "return self.model_dump_json(by_alias=True, exclude_unset=True)" in patched
    assert "return json.dumps(self.to_dict())" not in patched

    # Re-running should be idempotent.
    assert _patch_generated_to_json_model_dump_json(package_dir) == 0
