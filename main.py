import base64
import hashlib
import urllib.parse
from pathlib import Path

import requests
import secrets

from os import environ
from typing import Any, Optional
from litestar.response import Redirect

from litestar.contrib.mako import MakoTemplateEngine
from litestar.openapi import OpenAPIController
from litestar.response import Template
from litestar.static_files import StaticFilesConfig
from litestar.template import TemplateConfig
from pydantic import BaseModel, EmailStr

from litestar import Litestar, Request, Response, get, post, Controller
from litestar.connection import ASGIConnection
from litestar.openapi.config import OpenAPIConfig
from litestar.security.jwt import OAuth2Login, OAuth2PasswordBearerAuth, Token

# Simulate user database
USERS_DB = {}


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

your_okta_domain = 'localhost:8000'
client_id = 'pete-client-id'
client_secret = 'pete-client-secret'
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
    print('log out user')


def login_user(user: User) -> Any:
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
    return str(val).replace("', '", '&').replace("': '", '=')[2:-2]


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
    return Template(template_name='profile.mako.html', context={"name": name})


@get(path='/')
async def index(name: Optional[str]) -> Template:
    return Template(template_name='signin.mako.html', context={"name": name})


# Given an instance of 'OAuth2PasswordBearerAuth' we can create a login handler function:
@post("/login")
async def login_handler(request: "Request[Any, Any, Any]", data: "User") -> "Response[OAuth2Login]":
    MOCK_DB[str(data.id)] = data
    # if we do not define a response body, the login process will return a standard OAuth2 login response.
    # Note the `Response[OAuth2Login]` return type.

    # you can do whatever you want to update the response instance here
    # e.g. response.set_cookie(...)
    return oauth2_auth.login(identifier=str(data.id))


@post("/sign-in")
async def sign_in(request: Request) -> Any:
    # store app state and code verifier in session
    request.set_session({"app_state": secrets.token_urlsafe(64), "code_verifier": secrets.token_urlsafe(64)})

    # calculate code challenge
    hashed = hashlib.sha256(request.session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {'client_id': config['client_id'],
                    'redirect_uri': config['redirect_uri'],
                    'scope': 'openid email profile',
                    'state': request.session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=urllib.parse.quote(dict_to_query_string(query_params))
    )

    return Redirect(request_uri)


# We also have some other routes, for example:
@get("/sign-out")
async def sign_out() -> Redirect:
    logout_user()
    return Redirect('/')


@get('/read-items')
async def read_items() -> list[Item]:
    items: list[Item] = []
    for i in range(5):
        items.append(Item(id=i, name='item ' + str(i)))
    return items


@get('/authorization-code/callback')
async def callback(request: Request) -> Any:
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # print(str(request.query_params))
    code = request.query_params.get('code')
    app_state = request.query_params.get('state')
    if app_state != request.session.get('app_state'):
        return 'The app state does not match'
    if not code:
        return 'The code was not return or is not accessible'
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': request.session.get('code_verifier')
                    }
    query_params = urllib.parse.quote(dict_to_query_string(query_params))
    exchange = requests.post(
        config.get('token_uri'),
        headers=headers,
        data=query_params,
        auth=(config.get('client_id'), config.get('client_secret'))
    ).json()

    # get token and validate
    if not exchange.get('token_type'):
        return 'unsupported token type, should be "Bearer"'
    access_token = exchange.get('access_token')
    id_token = exchange.get('id_token')

    # authorization flow successful, get userinfo and sign in user
    user_response = requests.get(config.get('userinfo_uri'),
                                 headers={'Authorization': f'Bearer {access_token}'}
                                 ).json()

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
)
