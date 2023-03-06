FROM ubuntu
RUN apt-get update && yes | apt-get install libsodium-dev libssl-dev libsodium23 openssl python3 tar ca-certificates xz-utils
WORKDIR /app
COPY . .
RUN python3 setup.py
RUN tar -xf zig_master_tarball
RUN `find . -type f -name "zig"` build -Doptimize=ReleaseSafe
ENV PORT=$PORT access_token=$access_token andrew_bot_public_key=$andrew_bot_public_key
CMD ["./zig-out/bin/andrew"]
EXPOSE 80
