# Docker
## Useful Links
- https://docs.docker.com/engine/install/ubuntu/
- https://hub.docker.com/
- https://docs.docker.com/trusted-content/official-images/

## Docker Commands
- Use `sudo`.
- `<image>` can be `<account_name>/<application_name>:<tag>`.
- `<tag>` is optional, default is `latest`.
- Non Docker official images must be prefixed by the account e.g. `docker/whalesay` vs `ubuntu`.
- `<container>` can be `<container_name>` or `<container_id>`.

  ```
  docker version
  
  docker run docker/whalesay cowsay Hello-World!
  
  docker run <image>
  docker run --name <container_name> <image>
  docker run -u <username> <image>
  
  docker run <image> <command> ==> docker run ubuntu sleep 100
  docker exec <container> command
  
  docker run -d <image>
  docker attach <container>
  
  docker run -it ubuntu bash ==> "i" for interactive, "t" for terminal
  
  docker ps
  docker ps -a
  docker ps -a -q ==> only list <container_id>
  
  docker inspect <container>/<image> ==> IP address and environment variables can be found here
  
  docker logs <container> ==> stuff written to STDOUT
  
  docker stop <container>
  docker start <container>
  docker rm <container>
  docker rm $(docker ps -a -q)
  
  docker pull <image>
  docker images
  docker rmi <image> ==> delete all dependent containers first
  
  docker run -p <host_port>:<container_port> <image>
  docker run -v <host_directory>:<container_directory> <image>
  ```
  ```
  [Sample Dockerfile]
  FROM ubuntu
  ==> Base OS or another image
  ==> Dockerfiles must always start with a "FROM"
  
  RUN apt-get update
  RUN apt-get install -y python python-pip
  RUN pip install flask
  
  COPY app.py /opt/app.py
  
  ENTRYPOINT FLASK_APP=/opt/app.py flask run --host=0.0.0.0
  ==> Command to execute when image is run as a container
  ```
  ```
  docker build . -t <account_name>/<application_name>:<tag>
  ==> "." is the directory where Dockerfile resides
  ==> <tag> is optional, default is "latest"
  
  docker history <image>
  
  docker login
  docker push <image>
  
  docker run -e <env_var>=<value> <image>
  ```
  ```
  docker run ubuntu
  ==> CMD ["bash"]

  docker run ubuntu sleep 5
  
  FROM ubuntu
  CMD sleep 5 or CMD ["sleep", "5"]

  FROM ubuntu
  ENTRYPOINT ["sleep"]

  FROM ubuntu
  ENTRYPOINT ["sleep"]
  CMD ["5"]
  ```
