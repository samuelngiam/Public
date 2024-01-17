# Docker
## Install Docker Engine
- https://docs.docker.com/engine/install/ubuntu/
- Check OS.
```
cat /etc/*release*
```

- Remove previous installations, if any.
```
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
```

- Install using the convenience script.
```
https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

- Check Docker version.
```
sudo docker version
```

- Test Docker.
```
https://hub.docker.com/

docker run docker/whalesay cowsay Hello-World!
```

## Docker Commands
- Need elevated privileges.

```
docker run <image>
docker run --name <container_name> <image>
docker run -u <username> <image>

docker run <image> <command> e.g. docker run ubuntu sleep 100
docker exec <container> command
```

```
docker run -d <image>
docker attach <container>
```

```
docker run -it ubuntu bash ==> "i" for interactive, "t" for terminal
```

```
docker run <image>:<tag> e.g. docker run redis:4.0

Default tag is "latest" e.g. docker run redis ==> docker run redis:latest

https://hub.docker.com/_/redis/tags
```

```
docker ps
docker ps -a
```

```
docker inspect <container> ==> IP address can be found here
```
  
```
docker logs <container> ==> stuff written to STDOUT
```

```
docker stop <container1> <container2> ...
docker start <container1> <container2> ...
docker rm <container1> <container2> ...
```

```
docker pull <image>
docker images
docker rmi <image> ==> delete all dependent containers first
docker rmi <image>:<tag> ==> if not latest
```

```
docker run -p <host_port>:<container_port> <image>
```

```
docker run -v <host_directory>:<container_directory> <image>
```

- Non-official images must be prefixed by the "account" e.g. `docker/whalesay` vs `ubuntu`.

## Docker Image
- Dockerfile consists of instructions and arguments.
```
FROM Ubuntu
==> Base OS or another image;
==> Dockerfiles must always start with a "FROM".

RUN apt-get update
RUN apt-get install -y python python-pip
RUN pip install flask

COPY app.py /opt/app.py

ENTRYPOINT FLASK_APP=/opt/app.py flask run --host=0.0.0.0
==> Command to execute when image is run as a container.
```

- Build Image
```
docker build . -t <name>:<tag>
==> "." is the directory where Dockerfile resides.
==> <name> can be <account_name>/<application_name>.
==> <tag> is optional, default is "latest".

docker history <name>:<tag>

docker login
docker push <name>:<tag>
```

- Environment variables
```
docker run -e xx=yy <image>
docker inspect <container> ==> Environment variables can be found here
```
