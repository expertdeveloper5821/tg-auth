FROM node:16

WORKDIR /app

COPY ./package*.json ./

RUN npm install

COPY . .

ENV DBUSERNAME=technogetic-backend

ENV DBPASSWD=technogetic5821

EXPOSE 5001

CMD ["npm", "start"]


# 1st command to build docker cmd :- docker build -t auth-docker-app .
# 2nd docker images to check image is build or not :- docker images or docker image ls
# REPOSITORY    TAG       IMAGE ID       CREATED         SIZE
# my-node-app   latest    8aa99aedfc00   6 minutes ago   978MB
# node          16        de468b37223b   3 days ago      910MB
# 3rd run the docker image:- docker run --rm -d -p 5001:5001 --name auth-app auth-docker-app
# 4th check which container is runnign:- deocker ps
# 5th to stop docker- copy container id and then:- docker stop 27cf06a54869
# 6th for binding root folder to docker folder:- docker run --rm -d -p 5001:5001 -v $(pwd):/app --name auth-app auth-docker-app
# 7th for delete the docker image the not been used :- docker rmi -f 8aa99aedfc00
