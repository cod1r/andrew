FROM ubuntu
RUN apt-get update && apt-get install libsodium-dev libssl-dev libsodium23 openssl python3
WORKDIR /app
COPY . .
RUN python3 setup.py
