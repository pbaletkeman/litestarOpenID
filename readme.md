# About #

Sample website programmed in Python using the [Litestar](https://litestar.dev) framework secured with OKTA as as the OpenID/OIDC provider.

#### Requires: ####
- Python 3.11.x
- OKTA OIDC/OpenID (may work with not OKTA providers) 

### Run command ###
`litestar --app main:app run --debug`

### .env file expectations ### 
- CLIENT_ID=*&lt;Value From OKTA&gt;*
- CLIENT_SECRET=*&lt;Value From OKTA&gt;*
- OKTA_DOMAIN=*&lt;dev-73804109.okta.com&gt;*
- REDIRECT_URL=*&lt;Setup in OKTA and refers to this site/project&gt;*<br/>
**e.g. http://localhost:8000/authorization-code/callback**<br/><br/>
- ***OKTA_PROMPT***=
  - If no ***OKTA_PROMPT*** parameter is specified, the standard behavior occurs:
     - If an Okta session already exists, the user is silently authenticated. Otherwise, the user is prompted to authenticate.
     - If scopes are requested that require consent and consent isn't yet given by the authenticated user, the user is prompted to give consent.

  - Other possible values for ***OKTA_PROMPT*** parameter:
     - `none`: Don't prompt for authentication or consent. If an Okta session already exists, the user is silently authenticated. Otherwise, an error is returned.
     - `login`: Always prompt the user for authentication, regardless of whether they have an Okta session.
     - `consent`: Depending on the values set for consent_method in the app and consent on the scope, display the Okta consent dialog, even if the user has already given consent. User consent is available for Custom Authorization Servers (requires the API Access Management feature and the User Consent feature enabled).
     - `login consent` or `consent login` (order doesn't matter): The user is always prompted for authentication, and the user consent dialog appears depending on the values set for consent_method in the app and consent on the scope, even if the user has already given consent.<br/>
See https://developer.okta.com/docs/reference/api/oidc/#parameter-details for more details about PROMPT.
