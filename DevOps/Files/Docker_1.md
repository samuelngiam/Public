# Docker Training Course for the Absolute Beginner

## Introduction

- https://docs.docker.com/engine/install/ubuntu/
- https://hub.docker.com/

```
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

docker run docker/whalesay cowsay "Hello, World!"
```

```
sudo apt-get purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras

sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
```

## Docker Commands

```
docker run nginx

docker ps
docker ps -a

docker stop silly_sammet
docker rm silly_sammet

docker images
docker rmi nginx
docker pull ubuntu

docker run ubuntu
docker run ubuntu sleep 5
docker exec distracted_mcclintock cat /etc/hosts

docker run kodekloud/simple-webapp
docker run -d kodekloud/simple-webapp
docker run attach a043d
```

```
docker run centos
docker run -it centos bash

docker ps

docker run -d centos sleep 20
docker ps

docker ps -a

docker run -d centos sleep 2000
docker ps
docker stop serene_pasteur
docker ps
docker ps -a

docker rm 1619625d7f5a
docker rm nervous_tesla
docker rm 345 e0a 773
docker rm 62 5b

docker images
docker rmi busybox
docker rmi ubuntu
docker images

docker run centos
docker rmi centos
docker ps -a
docker rm 8e
docker rmi centos
docker rmi hello-world
docker images

docker pull ubuntu
docker images

docker run -d ubuntu sleep 1000
docker ps
docker exec c1a19d3a7ca7 cat /etc/*release*
```
