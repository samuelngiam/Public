# Docker
## Useful Links
- https://docs.docker.com/engine/install/ubuntu/
- https://hub.docker.com/

## Basic Docker
- Use `sudo`.
- `<image>` can be `<account_name>/<application_name>:<tag>`.
  - `<tag>` is optional, default is `latest`.
  - Non Docker official images must be prefixed by the account e.g. `docker/whalesay` vs `ubuntu`.
- `<container>` can be `<container_name>` or `<container_id>`.

```
docker version
docker run docker/whalesay cowsay Hello-World!
```

```
docker ps
docker ps -a
docker ps -a -q ==> only show <container_id> column

docker stop <container>
docker start <container>
docker rm <container>
docker rm $(docker ps -a -q)
```

```
docker pull <image>
docker images
docker rmi <image> ==> delete all dependent containers first
docker rmi $(docker images -q)
```

```
docker run -p <host_port>:<container_port> <image>
docker run -v <host_directory>:<container_directory> <image>
```

```
docker run <image>

docker run -d <image>
docker attach <container>

docker run --name <container_name> <image>
docker run -u <username> <image>

docker run <image> <command> ==> docker run ubuntu sleep 100
docker exec <container> <command>

docker run -it ubuntu bash ==> "i" for interactive, "t" for terminal
docker run -e <env_var>=<value> <image>
```

```
docker inspect <container>/<image> ==> IP address and environment variables can be found here

docker logs <container> ==> ?
```

```
[Sample Dockerfile]

git clone https://github.com/docker/getting-started-app.git

cd ~/getting-started-app
touch Dockerfile

FROM node:18-alpine
WORKDIR /app
COPY . .
RUN yarn install --production
CMD ["node", "src/index.js"]
EXPOSE 3000

docker build -t getting-started .

docker run -dp 127.0.0.1:3000:3000 getting-started

http://localhost:3000
```

```
docker build . -t <account_name>/<application_name>:<tag>
==> "." is the directory where Dockerfile resides
==> <tag> is optional, default is "latest"

docker history <image>

docker login
docker push <image>
```

```
docker run ubuntu

docker run ubuntu sleep 5

FROM ubuntu
CMD sleep 5 or CMD ["sleep", "5"]

docker run ubuntu-sleeper
docker run ubuntu-sleeper sleep 10

FROM ubuntu
ENTRYPOINT ["sleep"]

docker run ubuntu-sleeper 5
docker run ubuntu-sleeper 10
docker run ubuntu-sleeper ==> Crash!

FROM ubuntu
ENTRYPOINT ["sleep"]
CMD ["5"]

docker run ubuntu-sleeper
docker run ubuntu-sleeper 10

docker run --entrypoint echo ubuntu-sleeper 20
```

## Docker Compose
- Compose is a tool for defining and running multi-container Docker applications.
