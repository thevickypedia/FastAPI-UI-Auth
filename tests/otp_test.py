from unittest.mock import MagicMock, patch

from uiauth.otp import OTPConfig, display_secret, generate_qr


def test_display_secret_prints_secret_and_filename(capsys):
    config = OTPConfig(
        qr_filename="test_qr.png",
        authenticator_user="user@example.com",
        authenticator_app="TestApp",
        secret="TESTSECRET123",
    )

    display_secret(config)

    captured = capsys.readouterr()

    assert "TESTSECRET123" in captured.out
    assert "test_qr.png" in captured.out
    assert "TOTP secret key" in captured.out


@patch("uiauth.otp.display_secret")
@patch("uiauth.otp.pyotp.random_base32")
@patch("uiauth.otp.pyotp.TOTP")
def test_generate_qr_success(
    mock_totp,
    mock_random_base32,
    mock_display_secret,
):
    secret = "MYSECRETKEY"
    mock_random_base32.return_value = secret

    mock_totp_instance = MagicMock()
    mock_totp_instance.provisioning_uri.return_value = "otpauth://test-uri"
    mock_totp.return_value = mock_totp_instance

    mock_qr = MagicMock()

    config = OTPConfig(
        qr_filename="qr.png",
        authenticator_user="user@example.com",
        authenticator_app="MyApp",
    )

    with patch.dict(
        "sys.modules",
        {"qrcode": MagicMock(make=MagicMock(return_value=mock_qr))},
    ):
        generate_qr(False, config)

    mock_totp.assert_called_once_with(secret)

    mock_totp_instance.provisioning_uri.assert_called_once_with(
        name="user@example.com",
        issuer_name="MyApp",
    )

    mock_qr.save.assert_called_once_with("qr.png")
    mock_qr.show.assert_not_called()

    assert config.secret == secret
    mock_display_secret.assert_called_once_with(config)


@patch("builtins.print")
def test_generate_qr_without_qrcode_module(mock_print):
    config = OTPConfig(
        qr_filename="qr.png",
        authenticator_user="user@example.com",
        authenticator_app="MyApp",
    )

    original_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "qrcode":
            raise ModuleNotFoundError("No module named qrcode")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        generate_qr(False, config)

    mock_print.assert_called()

    printed_text = "".join(
        str(arg)
        for call in mock_print.call_args_list
        for arg in call.args
    )

    assert "qrcode" in printed_text
    assert "pip install qrcode[pil]" in printed_text


@patch("uiauth.otp.display_secret")
@patch("uiauth.otp.pyotp.random_base32")
@patch("uiauth.otp.pyotp.TOTP")
def test_generate_qr_show_qr_calls_show(
    mock_totp,
    mock_random_base32,
    mock_display_secret,
):
    mock_random_base32.return_value = "SECRET"

    mock_totp_instance = MagicMock()
    mock_totp_instance.provisioning_uri.return_value = "otpauth://test-uri"
    mock_totp.return_value = mock_totp_instance

    mock_qr = MagicMock()

    config = OTPConfig(
        qr_filename="qr.png",
        authenticator_user="user@example.com",
        authenticator_app="MyApp",
    )

    with patch.dict(
        "sys.modules",
        {"qrcode": MagicMock(make=MagicMock(return_value=mock_qr))},
    ):
        generate_qr(True, config)

    mock_qr.show.assert_called_once()
    mock_qr.save.assert_called_once_with("qr.png")
    mock_display_secret.assert_called_once_with(config)


def test_display_secret_fallback_terminal_size(capsys):
    config = OTPConfig(
        qr_filename="test.png",
        authenticator_user="user",
        authenticator_app="app",
        secret="SECRET",
    )

    with patch("uiauth.otp.os.get_terminal_size", side_effect=OSError):
        display_secret(config)

    output = capsys.readouterr().out

    assert "SECRET" in output
    assert "test.png" in output
