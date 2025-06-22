# FastAPIAuthenticator

Python module to add username and password authentication to specific FastAPI routes

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]

## Installation

```bash
pip install FastAPIAuthenticator
```

## Usage

```python
import fastapiauthenticator

from fastapi import FastAPI, Depends

app = FastAPI()


@app.get("/public")
def public_route():
    return {"message": "This is a public route"}


def private_route():
    return {"message": "This is a private route"}


fastapiauthenticator.Authenticator(app=app, secure_function=private_route)
```

## Coding Standards
Docstring format: [`Google`][google-docs] <br>
Styling conventions: [`PEP 8`][pep8] and [`isort`][isort]

## Linting

**Requirement**
```shell
python -m pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][license]

[//]: # (Labels)

[3.11]: https://docs.python.org/3/whatsnew/3.11.html
[license]: https://github.com/thevickypedia/FastAPIAuthenticator/blob/main/LICENSE
[google-docs]: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
[pep8]: https://www.python.org/dev/peps/pep-0008/
[isort]: https://pycqa.github.io/isort/

[label-pyversion]: https://img.shields.io/badge/python-3.11%20%7C%203.12-blue
[label-platform]: https://img.shields.io/badge/Platform-Linux|macOS|Windows-1f425f.svg
