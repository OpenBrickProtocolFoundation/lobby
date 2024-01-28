import json
from dataclasses import dataclass
from enum import Enum
from typing import Self

from dataclasses_jsonschema import JsonSchemaMixin


class ConfigValue(Enum):
    JWT_SECRET = "jwt_secret"
    GAMESERVER_EXECUTABLE = "gameserver_executable"


@dataclass
class Config(JsonSchemaMixin):
    jwt_secret: str
    gameserver_executable: str
    
    @classmethod
    def from_file(cls, filename: str) -> Self:
        with open(filename) as file:
            data = json.load(file)
            return cls.from_dict(data)
