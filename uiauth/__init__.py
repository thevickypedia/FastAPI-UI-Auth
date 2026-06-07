import sys

from uiauth.enums import APIEndpoints  # noqa: F401,E402
from uiauth.models import Fallback  # noqa: F401,E402
from uiauth.otp import OTPConfig, generate_qr
from uiauth.service import FastAPIUIAuth as _authProduct  # noqa: F401,E402
from uiauth.version import version  # noqa: F401,E402

protect = _authProduct


def _totp() -> None:
    """Commandline trigger for TOTP QR code generation."""
    assert sys.argv[0].endswith("totp"), "Invalid commandline trigger!!"
    options = {
        "--user | -U": "Username for the TOTP setup (e.g., your email or username)",
        "--app | -A": "Issuer name for the TOTP setup (e.g., your app or company name)",
        "--file | -F": "Filename for the generated QR code image (default: 'otp_qr.png')",
        "--show | -S": "Show the generated QR code after creation (default: False)",
        "--help | -H": "Prints the help section.",
    }
    # weird way to increase spacing to keep all values monotonic
    _longest_key = max(len(k) for k in options)
    _pretext = "\n\t* "
    choices = _pretext + _pretext.join(
        f"{k} {'·' * (_longest_key - len(k) + 8)}→ {v}".expandtabs()
        for k, v in options.items()
    )
    args = [arg for arg in sys.argv[1:]]
    if any(a.lower() in ("help", "--help", "-h") for a in args):
        print(
            f"Usage: uiauth-totp [arbitrary-command]\nOptions (and corresponding behavior):{choices}"
        )
        raise SystemExit(0)

    app = None
    user = None
    show_qr = False
    filename = "otp_qr.png"

    for idx, arg in enumerate(args):
        if (
            arg.startswith("--file=")
            or arg.startswith("-F=")
            or (arg in ("--file", "-F") and idx + 1 < len(args))
        ):
            filename = arg.split("=", 1)[1] if "=" in arg else args[idx + 1]
        elif (
            arg.startswith("--user=")
            or arg.startswith("-U=")
            or (arg in ("--user", "-U") and idx + 1 < len(args))
        ):
            user = arg.split("=", 1)[1] if "=" in arg else args[idx + 1]
        elif (
            arg.startswith("--app=")
            or arg.startswith("-A=")
            or (arg in ("--app", "-A") and idx + 1 < len(args))
        ):
            app = arg.split("=", 1)[1] if "=" in arg else args[idx + 1]
        elif (
            arg in ("--show", "-S")
            or arg.startswith("--show=")
            or arg.startswith("-S=")
        ):
            if "=" in arg:
                show_qr = arg.split("=", 1)[1].lower() in ("true", "1", "yes")
            else:
                show_qr = (
                    args[idx + 1].lower() in ("true", "1", "yes")
                    if idx + 1 < len(args)
                    else True
                )

    if not all((app, user)):
        print(
            "Missing required options. Using default values for missing options:\n"
            f"Please choose from {choices}"
        )
        raise SystemExit(1)

    config = OTPConfig(
        qr_filename=filename, authenticator_user=user, authenticator_app=app
    )

    print(
        "Using values:\n"
        f"  - Filename: {config.qr_filename}\n"
        f"  - User: {config.authenticator_user}\n"
        f"  - App: {config.authenticator_app}\n"
        f"  - Show QR: {show_qr}\n"
    )
    generate_qr(show_qr=show_qr, config=config)
