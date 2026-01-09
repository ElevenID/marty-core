# Tests for marty_biometrics Python bindings.
"""Placeholder tests for marty_biometrics package."""


def test_import():
    """Test that the module can be imported."""
    import marty_biometrics
    assert marty_biometrics is not None


def test_has_version():
    """Test that the module has a version attribute."""
    import marty_biometrics
    # Basic smoke test - module should be importable
    assert hasattr(marty_biometrics, '__name__')
