Release Notes
=============

v0.4.0 (06/07/2026)
-------------------
- `2e05b47 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/2e05b471a20bb96ec962e367ca64b6a5c1d6c770>`_ chore: Release ``v0.4.0``
- `64d4913 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/64d4913595e64ce3991aad5ddbde52edd009352b>`_ test: Update unit tests to extend code coverage
- `9ac9664 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/9ac9664bc808cc875883af62f418af55e04b97d2>`_ lint: Run and update linter
- `f21e579 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/f21e579f247d5af1b5d1e46a0e3792c4814592e4>`_ ci: Update GHA workflows for a fully automated release process
- `9f6935b <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/9f6935bb649aaf966de5c4a2edda59d059b31e3d>`_ feat: Add an option to generate TOTP token via CLi
- `7e7ef38 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/7e7ef38cbf5265854975a6789801e13f0fb75093>`_ chore: Update ``.gitignore``
- `86307dc <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/86307dc8c7115857bb29d8c81bcc92de63858f79>`_ refactor: Add fallback options as a model parameter instead of individual strings
- `6fd4a7b <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/6fd4a7ba176c5b42ba8625b40db5daf9b1f5fd4a>`_ test: Update existing test cases and add new ones for TOTP
- `9f11049 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/9f1104903e446cca047695b83d8f990e5fb51763>`_ chore: Set an upper bound value for session timeout
- `5452cb9 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/5452cb9ea0b4701e1fffce9515c4b94f099aa895>`_ chore: Add a warning message when instantiated without 2FA using TOTP
- `092574d <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/092574d351a9692f634ed6c6a19387972a565fe0>`_ ci: Extend python-publish GHA to include auto-update release notes
- `1584b11 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/1584b116451c60eabaf85dad34d72c74466551b7>`_ chore: Bump dev and test dependencies
- `ecf11fb <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/ecf11fb316e3a1c1fc8135b2c0bf9d39a5931559>`_ ci: Bump dependency versions in code coverage GHA
- `f2dd92f <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/f2dd92f02be84e79774182f41ab27b820685387b>`_ chore: Update release notes manually
- `0574ed9 <https://github.com/thevickypedia/FastAPI-UI-Auth/commit/0574ed9c7113f197f571f0e541f6c127df97d6ab>`_ feat: Implement an OTP auth mechanism for optional extra layer of protection

v0.3.2 (03/22/2026)
-------------------
- fix: Fix missing ``request`` param for ``TemplateResponse`` required by ``starlette==1.0.0``
- **Full Changelog**: https://github.com/thevickypedia/FastAPI-UI-Auth/compare/v0.3.1...v0.3.2

v0.3.1 (03/06/2026)
-------------------
- **fix**: Avoid ``AttributeError`` when the server restarts and there are no stored tokens in memory
- **refactor**: Hide all routes added by ``FastAPI-UI-Auth`` in the documentation schema
- **feat**: Dynamically mirror route attributes when registering secure routes
- **ci**: Ensure tests pass before publishing and fix intermittent workflow failures
- **ci**: Avoid running unit tests during version bumps
- **Full Changelog**: https://github.com/thevickypedia/FastAPI-UI-Auth/compare/v0.3.0...v0.3.1

v0.3.0 (03/05/2026)
-------------------
- **refactor**: Replace custom ``APIParameters`` with actual ``FastAPI`` route objects
- **perf** Replace ``Timer`` to track session expiry with a server side validation
- **tests** Add unit tests with 100% code coverage
- **ci**: Add Github Actions workflow for testing and code coverage
- **Full Changelog**: https://github.com/thevickypedia/FastAPI-UI-Auth/compare/v0.2.3...v0.3.0

v0.2.3 (03/05/2026)
-------------------
- **fix**: Avoid env vars overriding kwargs
- **refactor**: Remove ``dotenv`` dependency
- **Full Changelog**: https://github.com/thevickypedia/FastAPI-UI-Auth/compare/v0.2.2...v0.2.3

v0.2.2 (02/05/2026)
-------------------
- **fix**: Remove dependency version pinning to avoid conflicts
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.2.1...v0.2.2

v0.2.1 (11/25/2025)
-------------------
- **fix**: Avoid pre-mature validation for username and password fields
- **chore**: Upgrade requirements
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.2.0...v0.2.1

v0.2.0 (07/03/2025)
-------------------
- **feature**: Includes an option to pass custom logger
- **chore**: Redefined project structure to adapt pypi packaging
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.1.1...v0.2.0

v0.1.1 (06/24/2025)
-------------------
- **chore**: Reduces overhead and removes code redundancy
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.1.0...v0.1.1

v0.1.0 (06/23/2025)
-------------------
- **feature**: Includes support for websockets authentication
- **fix**: Fix breakage on multiple sessions
- **chore**: Uses all HTML templates for appropriate responses
- **chore**: Includes a parameter loader to support multiple endpoints
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.0.1...v0.1.0

v0.0.1 (06/22/2025)
-------------------
- Create a base python module to enable ``username``/``password`` authentication for any specific route
- Transmits ``username`` and ``password`` securely by encrypting ``credentials`` → ``hex`` → ``hash + timestamp``
- Includes basic templates for UI authentication
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/compare/v0.0.0-a...v0.0.1

v0.0.0-a (06/21/2025)
---------------------
- Release alpha version
- **Full Changelog**: https://github.com/thevickypedia/FastAPIAuthenticator/commits/v0.0.0-a
