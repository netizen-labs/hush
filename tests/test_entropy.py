import math

import pytest

from hush.entropy import is_high_entropy, shannon_entropy


def test_empty_string_has_zero_entropy():
    assert shannon_entropy("") == 0.0


def test_uniform_repeat_has_zero_entropy():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_two_equal_symbols_is_one_bit():
    assert shannon_entropy("ab") == pytest.approx(1.0)


def test_four_equal_symbols_is_two_bits():
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_never_exceeds_log2_of_alphabet():
    data = "the quick brown fox jumps over the lazy dog"
    distinct = len(set(data))
    assert shannon_entropy(data) <= math.log2(distinct) + 1e-9


def test_ordinary_identifier_is_not_high_entropy():
    assert not is_high_entropy("this_is_a_normal_variable_name")


def test_random_base64_blob_is_high_entropy():
    assert is_high_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def test_short_random_token_below_min_length_is_ignored():
    assert not is_high_entropy("aB9xQ", min_length=20)


def test_long_hex_digest_is_high_entropy():
    assert is_high_entropy("d41d8cd98f00b204e9800998ecf8427e" * 2)
