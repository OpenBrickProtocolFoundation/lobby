import os.path
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

import sqlalchemy
from dataclasses_jsonschema import JsonSchemaMixin
from dataclasses_jsonschema import ValidationError
from flask import Flask
from flask import jsonify
from flask import request
from flask import Response
from flask_bcrypt import Bcrypt  # pyright: ignore[reportMissingTypeStubs]
from flask_bcrypt import check_password_hash  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from flask_bcrypt import generate_password_hash  # pyright: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from flask_sqlalchemy import SQLAlchemy

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

    def touch(self) -> None:
        self.timestamp = time.monotonic()


active_lobbies: dict[str, Lobby] = dict()


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


@app.route("/health", methods=["GET"])
def health_check():
    return create_ok_response({})


@app.route("/lobbies", methods=["GET"])
def lobby_list():
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

    lobbies = [
        LobbyInfo(lobby.id, lobby.name, lobby.size, len(lobby.player_ids) + 1, PlayerInfo.from_id(lobby.host_id))
        for
        lobby
        in active_lobbies.values()
    ]

    response = LobbyListResponse(lobbies)

    return create_ok_response(response.to_dict())


@app.route("/lobbies/<lobby_id>", methods=["GET"])
def lobby_detail(lobby_id: str):
    lobby = active_lobbies.get(lobby_id)
    if lobby is None:
        return create_error_response(f"there is no active lobby with id {lobby_id}", HTTPStatus.NOT_FOUND)

    @dataclass
    class LobbyResponse(JsonSchemaMixin):
        name: str
        size: int
        host_info: PlayerInfo
        player_infos: list[PlayerInfo]

    host_user = typing.cast(Optional[User], User.query.filter(User.id == lobby.host_id).first())
    assert host_user is not None
    host_info = PlayerInfo(lobby.host_id, host_user.username)

    player_users = typing.cast(list[User], User.query.filter(User.id.in_(lobby.player_ids)).all())
    assert len(player_users) == len(lobby.player_ids)
    player_infos = [PlayerInfo(player.id, player.username) for player in player_users]

    response = LobbyResponse(lobby.name, lobby.size, host_info, player_infos)

    return create_ok_response(response.to_dict())


@app.route("/lobbies", methods=["POST"])
def create_lobby():
    if not request.is_json:
        return create_error_response("Request is not JSON", HTTPStatus.BAD_REQUEST)

    @dataclass
    class CreateLobbyRequest(JsonSchemaMixin):
        name: str
        size: int
        host_username: str
        host_password: str

    try:
        create_lobby_request = CreateLobbyRequest.from_dict(request.get_json())
    except ValidationError as e:
        return create_error_response(str(e), HTTPStatus.BAD_REQUEST)

    user = typing.cast(Optional[User], User.query.filter_by(username=create_lobby_request.host_username).first())
    if user is None or not check_password_hash(user.password, create_lobby_request.host_password):
        return create_error_response("Invalid host credentials.", HTTPStatus.BAD_REQUEST)

    new_id = str(uuid4())
    new_lobby = Lobby(id=new_id, name=create_lobby_request.name, size=create_lobby_request.size, host_id=user.id)
    active_lobbies[new_id] = new_lobby

    @dataclass
    class CreateLobbyResponse(JsonSchemaMixin):
        id: str

    response = CreateLobbyResponse(id=new_id)
    return create_response(HTTPStatus.CREATED, response.to_dict())


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

    return create_response(HTTPStatus.CREATED, {"id": new_user.id})


# this runs, when you launch this file manually, otherwise flask imports this file and ignores this
if __name__ == "__main__":
    print(sys.argv)
    if len(sys.argv) >= 2 and sys.argv[1] == "prod":
        from waitress import serve
        serve(app, host="0.0.0.0", port=1717)
    else:
        app.run(debug=True)
