import pytest

from domains.mta_sts import MtaStsRecord


class TestParse:
    def test_parse__returns_the_tags(self):
        assert MtaStsRecord.parse("v=STSv1; id=abc123") == {"id": "abc123"}

    def test_parse__strips_whitespace_and_a_trailing_semicolon(self):
        assert MtaStsRecord.parse("v=STSv1; id=abc ; ext=value ; ") == {
            "id": "abc",
            "ext": "value",
        }

    def test_parse__accepts_extension_tags(self):
        assert MtaStsRecord.parse("v=STSv1; id=a; x-tag=!#$%") == {
            "id": "a",
            "x-tag": "!#$%",
        }

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "v=STSv1",
            "v=TLSRPTv1; id=abc",
            "v=STSv1; id",
            "v=STSv1; id=a; id=b",
            "v=STSv1; id=with-dash",
            "v=STSv1; id=a; -bad=value",
            "v=STSv1; id=a; ext=has space",
            "v=STSv1; ext=value",
        ],
    )
    def test_parse__rejects_malformed_records(self, value):
        assert MtaStsRecord.parse(value) is None


class TestMatches:
    def test_matches__exact_hostname(self):
        assert MtaStsRecord.matches("mx1.example.com.", "mx1.example.com")

    def test_matches__is_case_insensitive(self):
        assert MtaStsRecord.matches("MX1.Example.COM", "mx1.example.com.")

    def test_matches__wildcard_matches_one_label(self):
        assert MtaStsRecord.matches("mx1.example.com", "*.example.com")

    def test_matches__wildcard_needs_a_first_label(self):
        assert not MtaStsRecord.matches("example.com", "*.example.com")

    def test_matches__wildcard_does_not_cross_labels(self):
        assert not MtaStsRecord.matches("mx1.mail.example.com", "*.example.com")

    def test_matches__different_hostname(self):
        assert not MtaStsRecord.matches("mx2.example.com", "mx1.example.com")
