[![python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![Logo](assets/lobby.png)

# The Lob(b)y Server Everybody Asked For!

More to come here...

## Deploy with docker compose

You need a running docker service and docker compose installed

Then build the image with docker compose:

```bash
docker compose build
```

After this you can run the whole app with docker compose: 

```bash
docker compose up -d
```

Note: the port is 1717 to proxy it through something like e.g. nginx.

There are two volumes defined:

```yaml
./files/:/app/files/
./config.json:/app/config/config.json
```

The first one maps the database content out of the container, so that it's persistent, You can inspect the database there if you want to.
The second one is for you to provide a config.json in the root folder. To see the exact schema look into `lobby/config.py`
NOTE: `SIMULATOR_LIBRARY_PATH` and `GAMESERVER_EXECUTABLE` don't need to be set, as the docker environment provides thos and sets them via environment variables.
