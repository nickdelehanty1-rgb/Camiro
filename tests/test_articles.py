"""Unit tests for app.utils.articles.format_articles."""
import pytest
from app.utils.articles import format_articles


def test_single_article():
    assert format_articles(["Art. 13"]) == "Article 13"


def test_single_article_variants():
    assert format_articles(["Article 22"]) == "Article 22"
    assert format_articles(["GDPR Art. 9"]) == "Article 9"


def test_range():
    assert format_articles(["Art. 13", "Art. 14"]) == "Articles 13–14"


def test_longer_range():
    assert format_articles(["Art. 13", "Art. 14", "Art. 15"]) == "Articles 13–15"


def test_mixed_list():
    # Non-consecutive numbers
    assert format_articles(["Art. 5", "Art. 13"]) == "Articles 5 and 13"


def test_mixed_list_with_range():
    # 5 is isolated, 13-14 form a range
    assert format_articles(["Art. 5", "Art. 13", "Art. 14"]) == "Articles 5 and 13–14"


def test_duplicates_removed():
    assert format_articles(["Art. 13", "Art. 13", "Art. 14"]) == "Articles 13–14"


def test_duplicates_identical_strings():
    assert format_articles(["Art. 13", "Art. 13"]) == "Article 13"


def test_empty_list():
    assert format_articles([]) == ""


def test_empty_strings_ignored():
    assert format_articles(["", "Art. 5", ""]) == "Article 5"


def test_three_part_list():
    result = format_articles(["Art. 5", "Art. 9", "Art. 22"])
    assert result == "Articles 5, 9 and 22"


def test_complex_mixed():
    # 5 isolated, 13-15 range, 22 isolated
    result = format_articles(["Art. 13", "Art. 14", "Art. 5", "Art. 22", "Art. 15"])
    assert result == "Articles 5, 13–15 and 22"


def test_plural_for_two():
    # "Articles" for 2+ article numbers
    result = format_articles(["Art. 13", "Art. 14"])
    assert result.startswith("Articles")


def test_singular_for_one():
    # "Article" for exactly one number
    result = format_articles(["Art. 9"])
    assert result.startswith("Article ")
    assert not result.startswith("Articles")
