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

sudo docker run docker/whalesay cowsay Hello-World!
```

- `sudo docker run`

- `sudo docker ps`, `sudo docker ps -a`

- `sudo docker stop <container_name>/<container_id>`

- `sudo docker rm <container_name>/<container_id>`

- `sudo docker images`

- `sudo docker rmi <repository_name>/<image_id>`
  - Must delete all dependent containers first.
