"""The schema must accept the good example and reject each bad one."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import validate as V

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(scope="module")
def validator():
    schema = V.load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def load(name):
    return json.loads((EXAMPLES / name).read_text())


def test_schema_is_draft_2020_12():
    assert V.load_schema()["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_valid_example_is_accepted(validator):
    assert list(validator.iter_errors(load("valid-entry.json"))) == []


def test_valid_example_passes_house_rules():
    entry = load("valid-entry.json")
    assert V.check_house_rules(EXAMPLES / "RS-9999-0001.json", entry) == []


@pytest.mark.parametrize(
    "name,expected_field",
    [
        ("invalid-no-primary-source.json", "sources"),
        ("invalid-bad-id.json", "id"),
        ("invalid-unknown-field.json", ""),
        ("invalid-no-indicators.json", "indicators"),
        ("invalid-bad-indicator.json", "indicators"),
    ],
)
def test_invalid_examples_are_rejected(validator, name, expected_field):
    errors = list(validator.iter_errors(load(name)))
    assert errors, f"{name} should have failed schema validation"
    paths = {str(e.absolute_path[0]) if e.absolute_path else "" for e in errors}
    assert expected_field in paths


def test_missing_primary_source_names_the_sources_field(validator):
    errors = list(validator.iter_errors(load("invalid-no-primary-source.json")))
    assert any("sources" in str(e.absolute_path) or e.validator == "contains" for e in errors)


def test_long_summary_is_rejected_by_house_rules():
    entry = load("invalid-long-summary.json")
    fails = V.check_house_rules(Path("RS-9999-0001.json"), entry)
    assert any("sentences" in f for f in fails)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("One sentence.", 1),
        ("One sentence. Two sentences.", 2),
        ("Versions 1.0.16 and later were affected. That is one.", 2),
        ("A name like foo.js in the middle does not end a sentence.", 1),
    ],
)
def test_sentence_counting(text, expected):
    assert V.count_sentences(text) == expected
