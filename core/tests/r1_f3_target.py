"""Read-only admission for the independently created disposable F3 SQL fixture."""

import json
import os
import re
import subprocess


def _inspect(kind, identity):
    command = (["docker", "inspect", "--type", "container", identity] if kind == "container"
               else ["docker", kind, "inspect", identity])
    try:
        result = subprocess.run(command,capture_output=True,text=True,timeout=15,check=False,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        values = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError,subprocess.TimeoutExpired,ValueError):
        values = []
    # Never print inspect JSON: Docker Config.Env contains the synthetic password.
    if len(values) != 1 or not isinstance(values[0],dict):
        raise ValueError("F3 external resource inspector unavailable")
    return values[0]


def verify_test_target(params):
    cid = os.environ.get("R1_F3_TEST_CONTAINER_ID","")
    system_id = os.environ.get("R1_F3_TEST_CLUSTER_SYSTEM_IDENTIFIER","")
    run_id = os.environ.get("R1_F3_TEST_RUN_ID","")
    if (not re.fullmatch(r"[0-9a-f]{64}",cid) or not re.fullmatch(r"[0-9]{10,32}",system_id)
            or not re.fullmatch(r"[0-9a-f]{32}",run_id)
            or params.get("dbname") != "r1_f3_test_" + run_id):
        raise ValueError("F3 harness container/run/cluster identity is required")
    expected_labels = {"io.qingyu.purpose":"R1_F3_TEST_ONLY","io.qingyu.run":run_id}
    def labels_ok(value):
        return isinstance(value,dict) and all(value.get(k)==v for k,v in expected_labels.items())
    container = _inspect("container",cid)
    name = container.get("Name","").lstrip("/")
    expected_name = os.environ.get("R1_F3_TEST_CONTAINER_NAME","")
    prefix = "r1_f3_test_only_" + run_id
    if (container.get("Id") != cid or not name.startswith(prefix)
            or (expected_name and name != expected_name)
            or not labels_ok(container.get("Config",{}).get("Labels"))
            or container.get("State",{}).get("Running") is not True):
        raise ValueError("F3 container identity/labels/state mismatch")
    ports = container.get("NetworkSettings",{}).get("Ports",{}).get("5432/tcp",[])
    if (not isinstance(ports,list) or len(ports)!=1 or ports[0].get("HostIp") != "127.0.0.1"
            or params.get("host") != "127.0.0.1" or ports[0].get("HostPort") != params.get("port")):
        raise ValueError("F3 database endpoint differs from inspected loopback binding")
    mounts = container.get("Mounts",[])
    if (len(mounts)!=1 or mounts[0].get("Type")!="volume" or mounts[0].get("Destination")!="/var/lib/postgresql/data"
            or mounts[0].get("Name") != prefix + "_data"):
        raise ValueError("F3 container does not have exactly one uniquely scoped new volume")
    volume = _inspect("volume",mounts[0]["Name"])
    if volume.get("Name")!=mounts[0]["Name"] or not labels_ok(volume.get("Labels")):
        raise ValueError("F3 volume provenance mismatch")
    networks = container.get("NetworkSettings",{}).get("Networks",{})
    expected_networks = {prefix+"_net":True,prefix+"_host_net":False}
    if set(networks) != set(expected_networks):
        raise ValueError("F3 requires exact new internal and loopback host networks")
    for network_name,attachment in networks.items():
        network = _inspect("network",attachment.get("NetworkID",""))
        if (network.get("Id")!=attachment.get("NetworkID") or network.get("Name")!=network_name
                or not labels_ok(network.get("Labels")) or network.get("Driver")!="bridge"
                or network.get("Internal") is not expected_networks[network_name]
                or set(network.get("Containers",{})) - {cid}):
            raise ValueError("F3 network provenance mismatch")
        if not expected_networks[network_name]:
            options = network.get("Options",{})
            expected = {"com.docker.network.bridge.enable_icc":"false",
                        "com.docker.network.bridge.enable_ip_masquerade":"false",
                        "com.docker.network.bridge.host_binding_ipv4":"127.0.0.1"}
            if any(options.get(key)!=value for key,value in expected.items()):
                raise ValueError("F3 host bridge lacks exact loopback isolation options")
    return system_id
