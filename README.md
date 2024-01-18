![Logo](assets/lobby.png)

# The Lob(b)y Server Everybody Asked For!

More to come here...


## Deploy with docker compose

You need a running docker service and docker compose installed


Then build the image:

```bash
docker build -t obpf-lobby .
```

Now you can run the docker compose file.

```bash
docker compose up -d
```
Note: the port is 1717 to proxy it through something like nginx.


Other common docker compose comands include:
```bash
docker compose down # stop all containers
docker compose ps # get details about running containers
docker compose logs -f # see the logs of all containers  (-f watches them)
```
