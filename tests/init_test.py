from unittest.mock import patch

import pytest

from uiauth import _totp


def test_invalid_command_trigger():
    with patch("uiauth.sys.argv", ["python"]):
        with pytest.raises(AssertionError, match="Invalid commandline trigger"):
            _totp()


def test_help_option_prints_help_and_exits():
    with (
        patch("uiauth.sys.argv", ["uiauth-totp", "--help"]),
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as exc:
            _totp()

    assert exc.value.code == 0

    printed = "".join(str(arg) for arg in mock_print.call_args[0])
    assert "Usage: uiauth-totp" in printed
    assert "--user" in printed
    assert "--app" in printed


def test_missing_required_options_exits():
    with (
        patch("uiauth.sys.argv", ["uiauth-totp"]),
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as exc:
            _totp()

    assert exc.value.code == 1

    printed = "".join(
        str(arg)
        for call in mock_print.call_args_list
        for arg in call.args
    )

    assert "Missing required options" in printed


@patch("uiauth.generate_qr")
def test_success_with_equals_syntax(mock_generate_qr):
    argv = [
        "uiauth-totp",
        "--user=test@example.com",
        "--app=MyApp",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print"),
    ):
        _totp()

    mock_generate_qr.assert_called_once()

    kwargs = mock_generate_qr.call_args.kwargs

    assert kwargs["show_qr"] is False
    assert kwargs["config"].authenticator_user == "test@example.com"
    assert kwargs["config"].authenticator_app == "MyApp"
    assert kwargs["config"].qr_filename == "otp_qr.png"


@patch("uiauth.generate_qr")
def test_success_with_space_syntax(mock_generate_qr):
    argv = [
        "uiauth-totp",
        "--user",
        "test@example.com",
        "--app",
        "MyApp",
        "--file",
        "custom.png",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print"),
    ):
        _totp()

    kwargs = mock_generate_qr.call_args.kwargs

    assert kwargs["config"].authenticator_user == "test@example.com"
    assert kwargs["config"].authenticator_app == "MyApp"
    assert kwargs["config"].qr_filename == "custom.png"


@patch("uiauth.generate_qr")
def test_show_flag_without_value(mock_generate_qr):
    argv = [
        "uiauth-totp",
        "--user=test@example.com",
        "--app=MyApp",
        "--show",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print"),
    ):
        _totp()

    kwargs = mock_generate_qr.call_args.kwargs

    assert kwargs["show_qr"] is True


@patch("uiauth.generate_qr")
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_show_flag_with_value(mock_generate_qr, value, expected):
    argv = [
        "uiauth-totp",
        "--user=test@example.com",
        "--app=MyApp",
        f"--show={value}",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print"),
    ):
        _totp()

    kwargs = mock_generate_qr.call_args.kwargs

    assert kwargs["show_qr"] is expected


@patch("uiauth.generate_qr")
def test_short_options(mock_generate_qr):
    argv = [
        "uiauth-totp",
        "-U=user@example.com",
        "-A=MyApp",
        "-F=myqr.png",
        "-S=true",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print"),
    ):
        _totp()

    kwargs = mock_generate_qr.call_args.kwargs

    assert kwargs["show_qr"] is True
    assert kwargs["config"].authenticator_user == "user@example.com"
    assert kwargs["config"].authenticator_app == "MyApp"
    assert kwargs["config"].qr_filename == "myqr.png"


@patch("uiauth.generate_qr")
def test_prints_configuration_summary(mock_generate_qr):
    argv = [
        "uiauth-totp",
        "--user=test@example.com",
        "--app=MyApp",
    ]

    with (
        patch("uiauth.sys.argv", argv),
        patch("builtins.print") as mock_print,
    ):
        _totp()

    output = "\n".join(
        str(arg)
        for call in mock_print.call_args_list
        for arg in call.args
    )

    assert "Filename:" in output
    assert "User:" in output
    assert "App:" in output
    assert "Show QR:" in output
