Release Notes
=============

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
