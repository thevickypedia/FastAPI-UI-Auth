import dotenv

dotenv.load_dotenv(dotenv_path=dotenv.find_dotenv(), override=True)

from fastapiauthenticator.service import Authenticator  # noqa: F401
from fastapiauthenticator.version import version  # noqa: F401
