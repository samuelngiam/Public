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
docker run <image>:<tag> i.e. docker run redis:4.0

Default tag is "latest" i.e. docker run redis ==> docker run redis:latest

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

- Non-official images must be prefixed by the "account" i.e. `docker/whalesay` vs `ubuntu`.
