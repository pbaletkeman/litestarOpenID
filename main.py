from datetime import datetime
from dotenv import load_dotenv

import os
from pathlib import Path
import requests
import secrets
from typing import Any, Optional

from litestar import Litestar, Request, Response, get, post, Controller, HttpMethod
from litestar.handlers import HTTPRouteHandler
from litestar.connection import ASGIConnection
from litestar.contrib.mako import MakoTemplateEngine
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.response import Template, Redirect
from litestar.static_files import StaticFilesConfig
from litestar.template import TemplateConfig
from litestar.openapi import OpenAPIController
from litestar.openapi.config import OpenAPIConfig
from litestar.security.jwt import OAuth2Login, OAuth2PasswordBearerAuth, Token
from litestar.status_codes import HTTP_302_FOUND

from pydantic import BaseModel, EmailStr

load_dotenv()

session_config = CookieBackendConfig(secret=os.urandom(16))


def write_to_file(lines: str) -> None:
    """
    quick dirty way to write to a log file
    helpful when a third party makes an endpoint request

    :param lines: data to write to the log file
    :return:
    """
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
    This can be whatever we want, don't have to use these properties
    """
    id: str
    name: str
    email: EmailStr
    token: dict[str, Any]

    def claims(self):
        """
        something about user's claims
        :return: user claim
        """
        return {'name': self.name, 'email': self.email}.items()


USERS_DB: dict[str, User] = {}


class Item(BaseModel):
    id: int
    name: str


@get('/read-items')
async def read_items() -> list[Item]:
    items: list[Item] = []
    for i in range(5):
        items.append(Item(id=i, name='item ' + str(i)))
    return items


# OAuth2PasswordBearerAuth requires a retrieve handler callable that receives the JWT token model and
# the ASGI connection and returns the 'User' instance correlating to it.
#
# Notes:
# - 'User' can be any arbitrary value you decide upon.
# - The callable can be either sync or async - both will work.
async def retrieve_user_handler(token: "Token", connection: "ASGIConnection[Any, Any, Any, Any]") -> Optional[User]:
    # logic here to retrieve the user instance
    return USERS_DB.get(token.sub)


oauth2_auth = OAuth2PasswordBearerAuth[User](
    retrieve_user_handler=retrieve_user_handler,
    token_secret=os.getenv("JWT_SECRET", os.urandom(16)),
    # we are specifying the URL for retrieving a JWT access token
    token_url="/login",
    # we are specifying which endpoints should be excluded from authentication.
    # note that this is a list regex patterns
    exclude=[
        "/login",
        "/docs",
        "/healthz",
        "^/$",
        "/metrics",
        "/static-files",
        "/sign-in",
        "/sign-out",
        "/authorization-code/callback",
        "/profile"
    ],
)


class SSO(Controller):
    APP_STATE = str(secrets.token_hex(64))
    NONCE = str(secrets.token_hex(64))

    OKTA_DOMAIN = os.getenv('OKTA_DOMAIN')
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    REDIRECT_URL = os.getenv('REDIRECT_URL')
    PROMPT = os.getenv('OKTA_PROMPT', None)

    config: dict[str, str] = {
        'SECRET_KEY': secrets.token_hex(64),
        'auth_uri': 'https://' + OKTA_DOMAIN + '/oauth2/default/v1/authorize',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URL,
        'issuer': 'https://' + OKTA_DOMAIN + '/oauth2/default',
        'token_uri': 'https://' + OKTA_DOMAIN + '/oauth2/default/v1/token',
        'userinfo_uri': 'https://' + OKTA_DOMAIN + '/oauth2/default/v1/userinfo'
    }

    @get(path='/profile/')
    async def profile(self, request: Request) -> Template:
        user_id = ''
        try:
            user_id = request.session.get('user', None)
            if user_id:
                user_id = user_id.get('id', None)
        except AttributeError as ex:
            print(ex)
        return Template(template_name='profile.mako.html', context={"user": USERS_DB.get(user_id, None)})

    @get(path='/')
    async def index(self, request: Request) -> Template:
        return Template(template_name='signin.mako.html',
                        context={
                            "action": request.query_params.get('sign-out', None),
                            "user": request.session.get('user', None)
                        })

    # Given an instance of 'OAuth2PasswordBearerAuth' we can create a login handler function:
    @post("/login")
    async def login_handler(self,  data: "User") -> "Response[OAuth2Login]":
        # async def sign_in(self, request: Request) -> Redirect:
        USERS_DB[str(data.id)] = data
        # if we do not define a response body, the login process will return a standard OAuth2 login response.
        # Note the `Response[OAuth2Login]` return type.

        # you can do whatever you want to update the response instance here
        # e.g. response.set_cookie(...)
        return oauth2_auth.login(identifier=str(data.id))

    @HTTPRouteHandler(path="/sign-in", http_method=[HttpMethod.GET, HttpMethod.POST], status_code=HTTP_302_FOUND)
    async def sign_in(self) -> Redirect:
        # async def sign_in(self, request: Request) -> Redirect:
        # get request params
        query_params = {'client_id': self.config['client_id'],
                        'redirect_uri': self.config['redirect_uri'],
                        'scope': 'openid email profile',
                        'state': self.APP_STATE,
                        'nonce': self.NONCE,
                        'response_type': 'code',
                        'response_mode': 'query'}

        if self.PROMPT:
            query_params = {'client_id': self.config['client_id'],
                            'redirect_uri': self.config['redirect_uri'],
                            'scope': 'openid email profile',
                            'state': self.APP_STATE,
                            'nonce': self.NONCE,
                            'prompt': self.PROMPT,
                            'response_type': 'code',
                            'response_mode': 'query'}

        # build request_uri
        encoded_params = (requests.compat.urlencode(query_params))
        request_uri = "{base_url}?{query_params}".format(
            base_url=self.config["auth_uri"],
            query_params=encoded_params
        )
        return Redirect(request_uri)

    # We also have some other routes, for example:
    @HTTPRouteHandler(path="/sign-out", http_method=[HttpMethod.GET, HttpMethod.POST], status_code=HTTP_302_FOUND)
    async def sign_out(self, request: Request) -> Redirect:
        user = request.session.get('user', None)
        if user:
            USERS_DB.pop(user.get('id'), None)
            request.session.pop('user', None)
        return Redirect('/?sign-out=t')

    @get('/authorization-code/callback')
    async def callback(self, request: Request) -> str | Response[Any]:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        code: str = request.query_params.get('code')
        app_state = request.query_params.get('state')

        if app_state != self.APP_STATE:
            print('The app state does not match')
            return 'The app state does not match'

        if not code:
            print('The code was not return or is not accessible')
            return 'The code was not return or is not accessible'
        query_params = {'grant_type': 'authorization_code',
                        'code': code,
                        'redirect_uri': self.config.get('redirect_uri')
                        }
        query_params = requests.compat.urlencode(query_params)

        exchange = requests.post(
            self.config.get('token_uri'),
            headers=headers,
            data=query_params,
            auth=(self.config.get('client_id'), self.config.get('client_secret'))
        ).json()
        # print('exchange')
        # print(exchange)
        # get token and validate
        if not exchange.get('token_type'):
            return 'unsupported token type, should be "Bearer"'
        access_token = exchange.get('access_token')
        id_token = exchange.get('id_token')

        # authorization flow successful, get userinfo and sign in user
        user_response = requests.get(self.config.get('userinfo_uri'),
                                     headers={'Authorization': f'Bearer {access_token}'}
                                     ).json()
        # print('*' * 20)
        # print('user_response')
        # print(user_response)
        unique_id = user_response.get('sub')
        user_email = user_response.get('email')
        user_name = user_response.get('given_name')

        auth_user = oauth2_auth.login(identifier=str(unique_id))

        user = User(
            id=unique_id,
            name=user_name,
            email=user_email,
            token=auth_user.content
        )

        if not USERS_DB.get(unique_id):
            USERS_DB[unique_id] = user

        request.set_session({"user": user})
        # print('use the following token to access endpoints')
        # print(auth_user.content)

        return Redirect('/profile')


# We create our OpenAPIConfig as usual - the JWT security scheme will be injected into it.
class OpenAPIControllerExtra(OpenAPIController):
    favicon_url = 'static-files/favicon.ico'


# We initialize the app instance and pass the oauth2_auth 'on_app_init' handler to the constructor.
# The hook handler will inject the JWT middleware and openapi configuration into the app.
app = Litestar(
    route_handlers=[SSO, read_items],
    on_app_init=[oauth2_auth.on_app_init],
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
    middleware=[session_config.middleware]
)
