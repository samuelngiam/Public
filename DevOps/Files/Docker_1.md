# KodeKloud - Docker Training Course for the Absolute Beginner

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
