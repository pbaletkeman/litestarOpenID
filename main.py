import os
import base64
import hashlib
import urllib.parse
from pathlib import Path

import requests
import secrets

from os import environ
from typing import Any, Optional

from litestar.handlers import HTTPRouteHandler
from litestar.params import Parameter
from litestar.response import Redirect

from litestar.contrib.mako import MakoTemplateEngine
from litestar.openapi import OpenAPIController
from litestar.response import Template
from litestar.static_files import StaticFilesConfig
from litestar.template import TemplateConfig
from pydantic import BaseModel, EmailStr

from litestar import Litestar, Request, Response, get, post, Controller, HttpMethod
from litestar.connection import ASGIConnection
from litestar.openapi.config import OpenAPIConfig
from litestar.security.jwt import OAuth2Login, OAuth2PasswordBearerAuth, Token
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.config.cors import CORSConfig

from datetime import datetime

session_config = CookieBackendConfig(secret=os.urandom(16))

# Simulate user database
USERS_DB = {}

cors_config = CORSConfig(allow_origins=["*"])

APP_STATE = 'Wy4-t7v1dKCFCq_n5hw-yJl9ofqkXduk8X_uLVh2nHrSjMfb3I58TdV68gMXCLQzyXN6aALPw3lj66gzIDbd8w'
CODE_VERIFIER = 'uzhtxkdmC_k0HmSLkqL8qfamEQZD_IZ5UODPmAdZsLEMzyPy-lPkZyPUai5SKam8UiJWx_YewKh3zdCYsqhPow'


def write_to_file(lines: str) -> None:
    f = open("log.txt", "a")
    f.write(str(datetime.now()) + '\n')
    f.write(lines + '\n')
    f.write('*' * 20 + '\n')
    f.close()


# Let's assume we have a User model that is a pydantic model.
# This though is not required - we need some sort of user class -
# but it can be any arbitrary value, e.g. an SQLAlchemy model, a representation of a MongoDB  etc.
class User(BaseModel):
    """
    user class
    """

    def __init__(self, id, name, email, /, **data: Any):
        super().__init__(**data)
        self.id = id
        self.name = name
        self.email = email

    def claims(self):
        """
        something about user's claims
        :return: user claim
        """
        return {'name': self.name, 'email': self.email}.items()

    @staticmethod
    def get(user_id: str):
        return USERS_DB.get(user_id)

    @staticmethod
    def create(user_id, name, email):
        USERS_DB[user_id] = User(user_id, name, email)


class Item(BaseModel):
    id: int
    name: str


MOCK_DB: dict[str, User] = {}

your_okta_domain = 'dev-73804109.okta.com'
client_id = '0oaf3qsm0fCKukhMD5d7'
client_secret = 'WQCRZieBEJIFbvpUhsi4tmgL1_X3VC3EW15-BQSb5c9pp8Mx7lFf65esYTblEhtO'
redirect_uri = 'http://localhost:8000/authorization-code/callback'

config: dict[str, str] = {
    'SECRET_KEY': secrets.token_hex(64),
    'auth_uri': 'https://' + your_okta_domain + '/oauth2/default/v1/authorize',
    'client_id': client_id,
    'client_secret': client_secret,
    'redirect_uri': redirect_uri,
    'issuer': 'https://' + your_okta_domain + '/oauth2/default',
    'token_uri': 'https://' + your_okta_domain + '/oauth2/default/v1/token',
    'userinfo_uri': 'https://' + your_okta_domain + '/oauth2/default/v1/userinfo'
}


class MockController(Controller):
    path = '/oauth2/default'

    @get('/v1/authorize')
    async def method1(self) -> str:
        return 'test - /v1/authorize'

    @get('/v1/token')
    async def method2(self) -> str:
        return 'test - /v1/token'

    @get('/v1/userinfo')
    async def method3(self) -> str:
        return 'test - /v1/userinfo'

    @get()
    async def method4(self) -> str:
        return 'test issue'


def logout_user():
    write_to_file('log out user')
    print('log out user')


def login_user(user: User) -> Any:
    write_to_file('create user')
    print('create user')
    print(user)


# OAuth2PasswordBearerAuth requires a retrieve handler callable that receives the JWT token model and
# the ASGI connection and returns the 'User' instance correlating to it.
#
# Notes:
# - 'User' can be any arbitrary value you decide upon.
# - The callable can be either sync or async - both will work.
async def retrieve_user_handler(token: "Token", connection: "ASGIConnection[Any, Any, Any, Any]") -> Optional[User]:
    # logic here to retrieve the user instance
    return MOCK_DB.get(token.sub)


def dict_to_query_string(val: dict[str, str]) -> str:
    write_to_file('dict to str\n' + str(val))
    x = str(val).replace("', '", '&').replace("': '", '=')[2:-2]
    x = x.replace("': URL('", '=').replace("'), '", '?')
    return x


oauth2_auth = OAuth2PasswordBearerAuth[User](
    retrieve_user_handler=retrieve_user_handler,
    token_secret=environ.get("JWT_SECRET", "abcd123"),
    # we are specifying the URL for retrieving a JWT access token
    token_url="/login",
    # we are specifying which endpoints should be excluded from authentication. In this case the login endpoint
    # and our openAPI docs.
    exclude=["/login", "/schema"],
)


@get(path='/profile')
async def profile(name: Optional[str]) -> Template:
    write_to_file('profile')
    return Template(template_name='profile.mako.html', context={"name": name})


@get(path='/')
async def index(name: Optional[str]) -> Template:
    write_to_file('home page')
    return Template(template_name='signin.mako.html', context={"name": name})


# Given an instance of 'OAuth2PasswordBearerAuth' we can create a login handler function:
@post("/login")
async def login_handler(request: "Request[Any, Any, Any]", data: "User") -> "Response[OAuth2Login]":
    write_to_file('login')
    MOCK_DB[str(data.id)] = data
    # if we do not define a response body, the login process will return a standard OAuth2 login response.
    # Note the `Response[OAuth2Login]` return type.

    # you can do whatever you want to update the response instance here
    # e.g. response.set_cookie(...)
    return oauth2_auth.login(identifier=str(data.id))


@HTTPRouteHandler(path="/sign-in", http_method=[HttpMethod.GET, HttpMethod.POST])
async def sign_in(request: Request) -> Any:
    # store app state and code verifier in session
    request.set_session({"app_state": secrets.token_urlsafe(64), "code_verifier": secrets.token_urlsafe(64)})
    # request.set_session({"app_state": APP_STATE, "code_verifier": CODE_VERIFIER})

    write_to_file('sign in\napp_state: ' + request.session.get('app_state')
                  + '\ncode_verifier: ' + request.session.get('code_verifier'))

    # calculate code challenge
    hashed = hashlib.sha256(request.session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {'client_id': config['client_id'],
                    'redirect_uri': 'raw_redirect_uri',
                    'scope': 'openid email profile',
                    'state': request.session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    encoded_params = (urllib.parse.quote(dict_to_query_string(query_params))
                      .replace('raw_redirect_uri', config['redirect_uri']))
    encoded_params = str(encoded_params).replace('callback%26', 'callback%3F')
    write_to_file('encoded param ' + encoded_params)
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=encoded_params
    )
    write_to_file('request_url: ' + request_uri)
    return Redirect(request_uri)
    # print(request.session)
    # return 'pete'


# We also have some other routes, for example:
@HTTPRouteHandler(path="/sign-out", http_method=[HttpMethod.GET, HttpMethod.POST])
async def sign_out() -> Redirect:
    write_to_file('sign-out')
    logout_user()
    return Redirect('/')


@get('/read-items')
async def read_items() -> list[Item]:
    items: list[Item] = []
    for i in range(5):
        items.append(Item(id=i, name='item ' + str(i)))
    return items


@get('/authorization-code/callback')
async def callback(request: Request
                   # okta_scope: str = Parameter(query='scope', required=False),
                   # okta_state: str = Parameter(query='state', required=False),
                   # code_challenge: str = Parameter(query='code_challenge', required=False),
                   # code_challenge_method: str = Parameter(query='code_challenge_method', required=False),
                   # code: str = Parameter(query='code', default='200', required=False),
                   # response_type: str = Parameter(query='response_type', required=False),
                   # response_mode: str = Parameter(query='response_mode', required=False)
                   ) -> Any:
    okta_scope: str = request.query_params.get('scope')
    okta_state: str = request.query_params.get('state')
    code_challenge: str = request.query_params.get('code_challenge')
    code_challenge_method: str = request.query_params.get('code_challenge_method')
    code: str = request.query_params.get('code')
    response_type: str = request.query_params.get('response_type')
    response_mode: str = request.query_params.get('response_mode')
    write_to_file('callback')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # print(str(request.query_params))
    app_state = request.query_params.get('state')

    write_to_file('query_params: ' + str(request.query_params))
    try:
        # request.set_session({"app_state": APP_STATE, "code_verifier": CODE_VERIFIER})
        write_to_file(
            'session app_state: ' + str(request.session.get('app_state')) + '\nquery app_state : ' + app_state)
        write_to_file('code: ' + code + '\ncode_verifier: ' + request.session.get('code_verifier'))
    except Exception as ex:
        print(ex)
    write_to_file('base url: ' + str(request.base_url))

    if app_state != request.session.get('app_state'):
        write_to_file('app state not matched')
        print('The app state does not match')
        return 'The app state does not match'

    if not code:
        write_to_file('code issue')
        print('The code was not return or is not accessible')
        return 'The code was not return or is not accessible'
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': request.session.get('code_verifier')
                    }
    # query_params = urllib.parse.quote(dict_to_query_string(query_params))
    write_to_file('query params :' + dict_to_query_string(query_params))
    write_to_file('client_id : ' + config.get('client_id') + ' secret:' + config.get('client_secret'))
    exchange = requests.post(
        config.get('token_uri'),
        headers=headers,
        data=query_params,
        auth=(config.get('client_id'), config.get('client_secret'))
    ).json()
    print('query params')
    print(query_params)
    print('exchange')
    print(exchange)
    print('d' * 10)
    write_to_file('token type: ' + exchange.get('token_type') + '\naccess token :' +
                  exchange.get('access_token') + '\nid_token: ' + exchange.get('id_token'))
    write_to_file('exchange: ' + exchange)
    # get token and validate
    if not exchange.get('token_type'):
        return 'unsupported token type, should be "Bearer"'
    access_token = exchange.get('access_token')
    id_token = exchange.get('id_token')

    # authorization flow successful, get userinfo and sign in user
    write_to_file('userinfo_uri: ' + config.get('userinfo_uri') + '\naccess_token: ' + access_token)
    user_response = requests.get(config.get('userinfo_uri'),
                                 headers={'Authorization': f'Bearer {access_token}'}
                                 ).json()

    write_to_file(str(user_response))
    unique_id = user_response.get('sub')
    user_email = user_response.get('email')
    user_name = user_response.get('given_name')

    user = User(unique_id, user_name, user_email)

    if not User.get(unique_id):
        return 'create user'

    login_user(user)

    return Redirect('/profile')


# We create our OpenAPIConfig as usual - the JWT security scheme will be injected into it.
class OpenAPIControllerExtra(OpenAPIController):
    favicon_url = 'static-files/favicon.ico'


# We initialize the app instance and pass the oauth2_auth 'on_app_init' handler to the constructor.
# The hook handler will inject the JWT middleware and openapi configuration into the app.
app = Litestar(
    route_handlers=[login_handler, read_items, profile, index, sign_in, sign_out, callback, MockController],
    # on_app_init=[oauth2_auth.on_app_init],
    openapi_config=OpenAPIConfig(
        title='My API', version='1.0.0',
        root_schema_site='elements',  # swagger, elements, redoc, rapidoc
        path='/docs',
        create_examples=False,
        openapi_controller=OpenAPIControllerExtra,
        use_handler_docstrings=True,
    ),
    static_files_config=[StaticFilesConfig(
        path='static-files',
        directories=['static-files']
    )],
    template_config=TemplateConfig(
        directory=Path('templates'),
        engine=MakoTemplateEngine,
    ),
    middleware=[session_config.middleware],
    cors_config=cors_config
)
