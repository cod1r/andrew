import urllib.request
import json
import ssl
req = urllib.request.Request(url="https://ziglang.org/download/index.json", method="GET")
with urllib.request.urlopen(req) as f:
    index = f.read()
    index_obj = json.loads(index)
    zig_master = index_obj['master']['x86_64-linux']['tarball']
    with urllib.request.urlopen(zig_master) as zig_master_response:
        tarball_contents = zig_master_response.read()
        with open("zig_master_tarball", "wb") as zmt:
            zmt.write(tarball_contents)
