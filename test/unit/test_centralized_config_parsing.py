import pathlib


def test_config_parsing_only_in_config_py():
    """
    Ensure that all direct ConfigParser usage or readSetting() calls
    are only present in lib/Config.py. Other library files should
    use the Configuration class, instead. Test files are ignored.
    """
    offending_patterns = [
        ("ConfigParser.", "Direct ConfigParser usage"),
        ("readSetting(", "Direct readSetting() call"),
    ]

    base_path = pathlib.Path(__file__).parent.parent.parent
    offending_files = set()

    for py_file in base_path.rglob("*.py"):
        rel_path = py_file.relative_to(base_path)

        # Skip lib/Config.py and test files
        if str(rel_path) == "lib/Config.py":
            continue
        if str(rel_path).startswith("test/"):
            continue

        content = py_file.read_text()
        for pattern, description in offending_patterns:
            if pattern in content:
                offending_files.add(f"{rel_path}: {description}")

    assert not offending_files, (
        "Direct configuration parsing found outside lib/Config.py:\n\n"
        + "\n".join(sorted(offending_files))
        + "\n\nPlease use the Configuration class instead."
    )
