# Docker

- All commands require `sudo`.
- `<image>` ==> `<account_name>/<application_name>:<tag>`.
  - `<tag>` optional, default `latest`.
  - Non Docker official images are prefixed by `<account_name>` e.g. `docker/whalesay`.
- `<container>` ==> `<container_name>` or `<container_id>`.

- Check Docker version.
```
docker version
```

- Test Docker after installation.
```
docker run docker/whalesay cowsay Hello-World!
```

## Unsorted

```
docker -H=<remote_docker_engine>:2375 run <image>
docker run --cpus=.5 <image>
docker run --memory=100m <image>
```

```
docker ps
docker ps -a
docker ps -a -q ==> only show <container_id>

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
==> Example: docker run -d -e MYSQL_ROOT_PASSWORD=db_pass123 --name mysql-db mysql
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

- Docker Compose is a tool for defining and running multi-container Docker applications.
```
docker run -d --name=redis redis
docker run -d --name=db postgres:9.4
docker run -d --name=vote -p 5000:80 --link redis:redis voting-app
docker run -d --name=result -p 5001:80 --link db:db result-app
docker run -d --name=worker --link db:db --link redis:redis worker
```

```
[docker-compose.yml]
==> Avoid using tabs?

version: 2
services:
    redis:
      image: redis
      networks:
        - back-end
    db:
      image: postgres:9.4
      networks:
        - back-end
    vote:
      image: voting-app
      ports:
        - 5000:80
      networks:
        - front-end
        - back-end
    result:
      image: result-app
      ports:
        - 5001:80
      networks:
        - front-end
        - back-end
    worker:
      image: worker
      networks:
        - back-end

networks:
  front-end:
  back-end:

docker-compose up
```

```
/var/lib/docker
/var/lib/docker/volumes/

docker run -v mysql:/var/lib/mysql mysql ==> volume mounting
docker run -v /data/mysql:/var/lib/mysql mysql ==> bind mounting
docker run --mount type=bind,source=/data/mysql,target=/var/lib/mysql mysql
```

## Useful Links
- https://docs.docker.com/engine/install/ubuntu/
- https://hub.docker.com/
- https://github.com/dockersamples/example-voting-app
