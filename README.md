# FastAPIUIAuth

Python module to add username and password authentication to specific FastAPI routes

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]

**Deployments**

[![pypi][label-actions-pypi]][gha_pypi]

[![Pypi][label-pypi]][pypi]
[![Pypi-format][label-pypi-format]][pypi-files]
[![Pypi-status][label-pypi-status]][pypi]

## Installation

```shell
pip install FastAPI-UI-Auth
```

## Usage

```python
import uiauth

from fastapi import FastAPI

app = FastAPI()

@app.get("/public")
async def public_route():
    return {"message": "This is a public route"}

async def private_route():
    return {"message": "This is a private route"}

uiauth.protect(
    app=app,
    params=uiauth.Parameters(
        path="/private",
        function=private_route
    )
)
```

> `FastAPI-UI-Auth` supports both `APIRoute` and `APIWebSocketRoute` routes.<br>
> Refer [samples] directory for different use-cases.

## Coding Standards
Docstring format: [`Google`][google-docs] <br>
Styling conventions: [`PEP 8`][pep8] and [`isort`][isort]

## [Release Notes][release-notes]
**Requirement**
```shell
python -m pip install gitverse
```

**Usage**
```shell
gitverse-release reverse -f release_notes.rst -t 'Release Notes'
```

## Linting

**Requirement**
```shell
python -m pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

## Pypi Package
[![pypi-module][label-pypi-package]][pypi-repo]

[https://pypi.org/project/FastAPI-UI-Auth/][pypi]

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][license]

[//]: # (Labels)

[3.11]: https://docs.python.org/3/whatsnew/3.11.html
[license]: https://github.com/thevickypedia/FastAPI-UI-Auth/blob/main/LICENSE
[google-docs]: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
[pep8]: https://www.python.org/dev/peps/pep-0008/
[isort]: https://pycqa.github.io/isort/
[samples]: https://github.com/thevickypedia/FastAPI-UI-Auth/tree/main/samples

[label-actions-pypi]: https://github.com/thevickypedia/FastAPI-UI-Auth/actions/workflows/python-publish.yml/badge.svg
[label-pypi]: https://img.shields.io/pypi/v/FastAPI-UI-Auth
[label-pypi-format]: https://img.shields.io/pypi/format/FastAPI-UI-Auth
[label-pypi-status]: https://img.shields.io/pypi/status/FastAPI_UI_Auth
[label-pypi-package]: https://img.shields.io/badge/Pypi%20Package-FastAPI_UI_Auth-blue?style=for-the-badge&logo=Python
[label-pyversion]: https://img.shields.io/badge/python-3.11%20%7C%203.12-blue
[label-platform]: https://img.shields.io/badge/Platform-Linux|macOS|Windows-1f425f.svg
[release-notes]: https://github.com/thevickypedia/FastAPI-UI-Auth/blob/main/release_notes.rst

[gha_pypi]: https://github.com/thevickypedia/FastAPI-UI-Auth/actions/workflows/python-publish.yml

[pypi]: https://pypi.org/project/FastAPI-UI-Auth
[pypi-files]: https://pypi.org/project/FastAPI-UI-Auth/#files
[pypi-repo]: https://packaging.python.org/tutorials/packaging-projects/
