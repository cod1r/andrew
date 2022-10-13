import urllib.request
import json
with urllib.request.urlopen("https://ziglang.org/download/index.json") as f:
    index = f.read()
    index_obj = json.loads(index)
    zig_master = index_obj['master']['src']['tarball']
    with urllib.request.urlopen(zig_master) as zig_master_response:
        tarball_contents = zig_master_response.read()
        with open("zig_master_tarball", "wb") as zmt:
            zmt.write(tarball_contents)
