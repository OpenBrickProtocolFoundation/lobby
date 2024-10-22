import json
from dataclasses import dataclass
from enum import Enum
from typing import Self
import os

from dataclasses_jsonschema import JsonSchemaMixin


class ConfigValue(Enum):
    JWT_SECRET = "jwt_secret"
    GAMESERVER_EXECUTABLE = "gameserver_executable"
    SIMULATOR_LIBRARY_PATH = "simulator_library_path"


@dataclass
class BaseConfig(JsonSchemaMixin):
    jwt_secret: str

    @classmethod
    def from_file(cls, filename: str) -> Self:
        with open(filename) as file:
            data = json.load(file)
            return cls.from_dict(data)

@dataclass
class Config(BaseConfig):
    gameserver_executable: str
    simulator_library_path: str

    @classmethod
    def from_file(cls, filename: str) -> Self:
        is_docker = len(os.environ.get("OBPF_IS_DOCKER",""))>= 1
        if is_docker:
            data = BaseConfig.from_file(filename).to_dict()
            data[ConfigValue.GAMESERVER_EXECUTABLE.value] = os.environ["OBBF_GAMESERVER_EXECUTABLE"] 
            data[ConfigValue.SIMULATOR_LIBRARY_PATH.value] = os.environ["OBBF_SIMULATOR_LIBRARY_PATH"] 
            return cls.from_dict(data)
        else:
            with open(filename) as file:
                data = json.load(file)
                return cls.from_dict(data)
