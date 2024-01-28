import os.path
import pprint
import socket
import struct
import subprocess
import sys
import time
import typing
from dataclasses import dataclass
from dataclasses import field
from http import HTTPStatus
from typing import Any
from typing import Optional
from typing import Self
from uuid import uuid4

import jwt
import sqlalchemy
from dataclasses_jsonschema import JsonSchemaMixin
from dataclasses_jsonschema import ValidationError
from flask import current_app
from flask import Flask
from flask import jsonify
from flask import request
from flask import Request
from flask import Response
from flask_bcrypt import Bcrypt  # pyright: ignore[reportMissingTypeStubs]
from flask_bcrypt import check_password_hash  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from flask_bcrypt import generate_password_hash  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from flask_sqlalchemy import SQLAlchemy

from lobby.config import Config
from lobby.config import ConfigValue
from lobby.synchronized import Synchronized

_DATABASE_PATH = os.path.realpath("database.sqlite")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{_DATABASE_PATH}"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


with app.app_context():
    db.create_all()


@dataclass
class Lobby:
    id: str
    name: str
    size: int
    host_id: str
    timestamp: float = field(default_factory=time.monotonic)
    player_ids: list[str] = field(default_factory=list)
    gameserver_port: Optional[int] = field(default=None)

    def touch(self) -> None:
        self.timestamp = time.monotonic()


@dataclass
class JwtPayload(JsonSchemaMixin):
    user_id: str


active_lobbies: Synchronized[dict[str, Lobby]] = Synchronized(dict())


def create_response(code: HTTPStatus, *args: Any, **kwargs: Any) -> tuple[Response, HTTPStatus]:
    return jsonify(*args, **kwargs), code


def create_ok_response(*args: Any, **kwargs: Any) -> tuple[Response, HTTPStatus]:
    return create_response(HTTPStatus.OK, *args, **kwargs)


def create_error_response(message: str, code: HTTPStatus) -> tuple[Response, HTTPStatus]:
    return create_response(code, {'message': message})


@dataclass
class PlayerInfo(JsonSchemaMixin):
    id: str
    name: str

    @classmethod
    def from_id(cls, id_: str) -> Self:
        user = typing.cast(Optional[User], User.query.filter_by(id=id_).first())
        if user is None:
            raise KeyError(f"User with id {id_} not found")
        assert isinstance(user, User)
        return cls(id_, user.username)


def try_authenticate(client_request: Request) -> User | tuple[Response, HTTPStatus]:
    if "Authorization" not in client_request.headers:
        return create_error_response("Unauthorized", HTTPStatus.UNAUTHORIZED)

    parts = client_request.headers["Authorization"].split(" ")
    if len(parts) != 2:
        return create_error_response("Invalid authorization header", HTTPStatus.UNAUTHORIZED)

    token_type, token = parts
    if token_type != "Bearer":
        return create_error_response("Invalid authorization header", HTTPStatus.UNAUTHORIZED)
    try:
        payload = JwtPayload.from_dict(
            jwt.decode(token, current_app.config[ConfigValue.JWT_SECRET.value], algorithms=["HS256"])
        )
    except jwt.exceptions.DecodeError:
        return create_error_response("Invalid token", HTTPStatus.UNAUTHORIZED)
    except ValidationError as e:
        return create_error_response(f"Invalid JWT payload format: {e}", HTTPStatus.INTERNAL_SERVER_ERROR)

    print(f"{payload = }")
    user = User.query.filter_by(id=payload.user_id).first()
    if user is None:
        return create_error_response("User not found", HTTPStatus.INTERNAL_SERVER_ERROR)

    return user


@app.route("/lobbies", methods=["GET"])
def lobby_list() -> tuple[Response, HTTPStatus]:
    @dataclass
    class LobbyInfo(JsonSchemaMixin):
        id: str
        name: str
        size: int
        num_players_in_lobby: int
        host_info: PlayerInfo

    @dataclass
    class LobbyListResponse(JsonSchemaMixin):
        lobbies: list[LobbyInfo]

    with active_lobbies.lock() as locked:
        lobbies = [
            LobbyInfo(lobby.id, lobby.name, lobby.size, len(lobby.player_ids) + 1, PlayerInfo.from_id(lobby.host_id))
            for
            lobby
            in locked.get().values()
        ]

    response = LobbyListResponse(lobbies)

    return create_ok_response(response.to_dict())


@app.route("/lobbies/<lobby_id>", methods=["POST"])
def join_lobby(lobby_id: str) -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    with active_lobbies.lock() as locked:
        lobby = locked.get().get(lobby_id)
        if lobby is None:
            return create_error_response(f"there is no active lobby with id {lobby_id}", HTTPStatus.NOT_FOUND)

        if len(lobby.player_ids) + 1 >= lobby.size:
            return create_error_response("Lobby is already full.", HTTPStatus.BAD_REQUEST)

        if any(lobby.host_id == user.id or user.id in lobby.player_ids for lobby in locked.get().values()):
            return create_error_response("This user is already inside another lobby.", HTTPStatus.BAD_REQUEST)

        lobby.player_ids.append(user.id)

    return create_response(HTTPStatus.NO_CONTENT)


@app.route("/lobbies/<lobby_id>", methods=["GET"])
def lobby_detail(lobby_id: str) -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    with active_lobbies.lock() as locked:
        lobby = locked.get().get(lobby_id)

    if lobby is None:
        return create_error_response(f"there is no active lobby with id {lobby_id}", HTTPStatus.NOT_FOUND)

    @dataclass
    class LobbyResponse(JsonSchemaMixin):
        name: str
        size: int
        host_info: PlayerInfo
        player_infos: list[PlayerInfo]
        gameserver_port: Optional[int]

    host_user = typing.cast(Optional[User], User.query.filter(User.id == lobby.host_id).first())
    assert host_user is not None
    host_info = PlayerInfo(lobby.host_id, host_user.username)

    player_users = typing.cast(list[User], User.query.filter(User.id.in_(lobby.player_ids)).all())
    assert len(player_users) == len(lobby.player_ids)
    player_infos = [PlayerInfo(player.id, player.username) for player in player_users]

    response = LobbyResponse(lobby.name, lobby.size, host_info, player_infos)

    return create_ok_response(response.to_dict())


@app.route("/lobbies/<lobby_id>", methods=["DELETE"])
def delete_lobby(lobby_id: str) -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    with active_lobbies.lock() as locked:
        if lobby_id not in locked.get():
            return create_error_response("Lobby not found", HTTPStatus.NOT_FOUND)

        lobby = locked.get()[lobby_id]
        if lobby.host_id != user.id:
            return create_error_response("You are not the host of this lobby", HTTPStatus.FORBIDDEN)

        locked.get().pop(lobby_id)

        return create_response(HTTPStatus.NO_CONTENT)


@app.route("/lobbies/<lobby_id>/leave", methods=["PUT"])
def leave_lobby(lobby_id: str) -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    with active_lobbies.lock() as locked:
        if lobby_id not in locked.get():
            return create_error_response("Lobby not found", HTTPStatus.NOT_FOUND)

        lobby = locked.get()[lobby_id]
        if user.id not in lobby.player_ids:
            return create_error_response("You are not a player in this lobby", HTTPStatus.FORBIDDEN)

        lobby.player_ids.remove(user.id)

    return create_response(HTTPStatus.NO_CONTENT)


@app.route("/lobbies/<lobby_id>/start", methods=["POST"])
def start_gameserver(lobby_id: str) -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    with active_lobbies.lock() as locked:
        if lobby_id not in locked.get():
            return create_error_response("Lobby not found", HTTPStatus.NOT_FOUND)

        lobby = locked.get()[lobby_id]
        if lobby.host_id != user.id:
            return create_error_response("You are not the host of this lobby", HTTPStatus.FORBIDDEN)

        if lobby.gameserver_port is not None:
            return create_error_response("Server is already running", HTTPStatus.BAD_REQUEST)

        gameserver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gameserver_socket.bind(("127.0.0.1", 0))
        gameserver_socket.listen(1)
        socket_port = str(gameserver_socket.getsockname()[1])
        subprocess.Popen([current_app.config[ConfigValue.GAMESERVER_EXECUTABLE.value], socket_port])
        client_socket, _ = gameserver_socket.accept()
        client_socket.send(struct.pack("!H", lobby.size))

        with client_socket.makefile("rb") as file:
            data = file.read(2)
        gameserver_port = int(struct.unpack("!H", data)[0])
        lobby.gameserver_port = gameserver_port
        print(f"started gameserver on port {gameserver_port}")
        
        return create_response(HTTPStatus.NO_CONTENT)


@app.route("/lobbies", methods=["POST"])
def create_lobby() -> tuple[Response, HTTPStatus]:
    user = try_authenticate(request)
    if not isinstance(user, User):
        return user

    if not request.is_json:
        return create_error_response("Request is not JSON", HTTPStatus.BAD_REQUEST)

    @dataclass
    class CreateLobbyRequest(JsonSchemaMixin):
        name: str
        size: int

    try:
        create_lobby_request = CreateLobbyRequest.from_dict(request.get_json())
    except ValidationError as e:
        return create_error_response(str(e), HTTPStatus.BAD_REQUEST)

    with active_lobbies.lock() as locked:
        if any(lobby.host_id == user.id or user.id in lobby.player_ids for lobby in locked.get().values()):
            return create_error_response("This user is already inside another lobby.", HTTPStatus.BAD_REQUEST)

        new_id = str(uuid4())
        new_lobby = Lobby(id=new_id, name=create_lobby_request.name, size=create_lobby_request.size, host_id=user.id)
        locked.get()[new_id] = new_lobby

    @dataclass
    class LobbyCreationResponse(JsonSchemaMixin):
        id: str

    response = LobbyCreationResponse(id=new_id)
    return create_response(HTTPStatus.CREATED, response.to_dict())


@app.route("/users", methods=["GET"])
def get_users() -> tuple[Response, HTTPStatus]:
    users = User.query.all()
    user_infos = [PlayerInfo(user.id, user.username) for user in users]

    @dataclass
    class UserList(JsonSchemaMixin):
        users: list[PlayerInfo]

    response = UserList(user_infos)

    return create_ok_response(response.to_dict())


@app.route("/login", methods=["POST"])
def login() -> tuple[Response, HTTPStatus]:
    if not request.is_json:
        return create_error_response("Request is not JSON", HTTPStatus.BAD_REQUEST)

    @dataclass
    class Credentials(JsonSchemaMixin):
        username: str
        password: str

    try:
        credentials = Credentials.from_dict(request.get_json())
    except ValidationError as e:
        return create_error_response(str(e), HTTPStatus.BAD_REQUEST)

    user = User.query.filter_by(username=credentials.username).first()
    if user is None or not check_password_hash(user.password, credentials.password):
        return create_error_response("Invalid credentials", HTTPStatus.UNAUTHORIZED)

    json_web_token = jwt.encode(
        JwtPayload(user.id).to_dict(),
        current_app.config[ConfigValue.JWT_SECRET.value],
        algorithm="HS256"
    )

    @dataclass
    class LoginResponse(JsonSchemaMixin):
        jwt: str

    return create_ok_response(LoginResponse(jwt=json_web_token).to_dict())


@app.route("/register", methods=["POST"])
def register() -> tuple[Response, HTTPStatus]:
    if not request.is_json:
        return create_error_response("Request is not JSON", HTTPStatus.BAD_REQUEST)

    @dataclass
    class RegisterRequest(JsonSchemaMixin):
        username: str
        password: str

    try:
        register_request = RegisterRequest.from_dict(request.get_json())
    except ValidationError as e:
        return create_error_response(str(e), HTTPStatus.BAD_REQUEST)

    new_id = str(uuid4())
    hashed_password = generate_password_hash(register_request.password).decode("utf-8")
    new_user = User(
        id=new_id,
        username=register_request.username,
        password=hashed_password
    )  # pyright: ignore[reportGeneralTypeIssues]

    try:
        db.session.add(new_user)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        return create_error_response("Username already exists.", HTTPStatus.CONFLICT)

    return create_response(HTTPStatus.NO_CONTENT)


def main() -> None:
    config = Config.from_file("config.json")
    app.config.update(config.to_dict())
    pprint.pprint(app.config)
    if len(sys.argv) >= 2 and sys.argv[1] == "production":
        from waitress import serve
        serve(app, host="0.0.0.0", port=1717)  # todo: fetch the port from some config file
    else:
        app.run(debug=True)


if __name__ == "__main__":
    main()
