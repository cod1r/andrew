FROM ubuntu
RUN apt-get update && yes | apt-get install libsodium-dev libssl-dev libsodium23 openssl python3 tar ca-certificates xz-utils
WORKDIR /app
COPY . .
RUN python3 setup.py
RUN tar -xf zig_master_tarball
RUN `find . -type f -name "zig"` build -Drelease-safe=true
RUN ./zig-out/bin/andrew
EXPOSE 80
