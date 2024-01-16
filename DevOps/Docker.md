# Docker
- Install Docker Engine
```
https://docs.docker.com/engine/install/ubuntu/

=> Make sure OS requirements are met.
cat /etc/*release*

=> Remove previous installations, if any.
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

=> Install using the convenience script.
https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo docker version
```

- Test Docker after installation
```
https://hub.docker.com/

docker run docker/whalesay cowsay Hello-World!
```

- Note: `docker` commands mostly require privileges to run.

```
docker run <image>
docker run <image> <command> e.g. docker run ubuntu sleep 100
docker run -d <image>
docker attach <image>
docker run -it ubuntu bash
docker exec <container> command
```

```
docker ps
docker ps -a
```

```
docker stop <container>
docker start <container>
docker rm <container>
```

```
docker pull <image>
docker images
docker rmi <image> ==> must delete all dependent containers first.
```

- Non-official images must be prefixed by the "account" i.e. `docker/whalesay` vs `ubuntu`.
