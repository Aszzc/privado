import requests
import json
from typing import Any, Dict, Callable
from concurrent.futures import ThreadPoolExecutor
import yaml

# Configuration setup (can be loaded from a config file or environment variables)
CONFIG = {
    "base_url": "https://172.234.123.98:59142",
    "login_endpoint": "/v1/login",
    "server_endpoint": "/v2/servers",
    "headers": {
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/json',
        'User-Agent': 'PrivadoVPN,3.8.11,OSVersion-Microsoft Windows NT 10.0.22631.0, 64 bit',
    },
    "credentials": {
        "api_key": "9f994c466340e8f2ed60a99396fecb6a",
        "username": "pvyvlcwe749103",
        "password": "4lnpu7?SCj#A",
        "language": "zh-cn"
    }
}

def send_request(method: str, url: str, headers: Dict[str, str], **kwargs) -> Any:
    """
    General function to send HTTP requests.
    """
    try:
        response = requests.request(method, url, headers=headers, **kwargs, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Response parsing failed: {e}")
        return None

def login() -> str:
    """
    Logs in to the API and retrieves the access token.
    """
    url = CONFIG["base_url"] + CONFIG["login_endpoint"]
    headers = CONFIG["headers"]
    data = json.dumps(CONFIG["credentials"])

    response = send_request("POST", url, headers=headers, data=data)
    if response and "access_token" in response:
        return response["access_token"]
    else:
        print("Login failed.")
        return ""

def get_servers(token: str) -> Any:
    """
    Retrieves the list of servers.
    """
    url = CONFIG["base_url"] + CONFIG["server_endpoint"]
    headers = {**CONFIG["headers"], "Authorization": f"Bearer {token}"}
    params = {"nodes": "all", "language": "zh-cn"}

    return send_request("GET", url, headers=headers, params=params)

def server_config(server: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fetches configuration for a given server.
    """
    domain = server.get("name")
    city = server.get("city")
    groups = server.get("groups", [])
    
    # Check if the server is a "Freemium" server
    if "Freemium" not in groups:
        return {}
    
    print(f"Freemium server found: {domain} in {city}")
    data = json.dumps({
        "Username": CONFIG["credentials"]["username"],
        "Password": CONFIG["credentials"]["password"]
    })

    headers = CONFIG['headers']
    response = requests.post(f'https://{domain}:44121/api/1.0/login', headers=headers, data=data)
    server_data = response.json()

    # Constructing the server configuration
    config = {
        "publickey": server_data['ServerPublicKey'],
        "privatekey": server_data['WGPrivateKey'],
        "endpoint": domain,
        "port": server_data['ServerListeningPort'],
        "localip": server_data['WGIPAddress'],
        "localdns": "8.8.8.8",
        "remark": city
    }

    return config

def process_server_data(servers: list, custom_parser: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(custom_parser, servers))
    return results

def format_to_clash(configs: list) -> str:
    """
    Format server data into a Clash-compatible configuration (YAML).
    """
    proxies = []
    for config in configs:
        if not config:
            continue
        domain = config.get('endpoint', '')
        proxy = {
            "name": domain,
            "type": "wireguard",
            "server": domain,
            "port": config.get("port", 51820),
            "udp": True,
            "ip": config.get("localip", "172.16.0.2"),
            "private-key": config.get("privatekey", ''),
            "public-key": config.get("publickey", ''),
            "remote-dns-resolve": True,
            "dns": ['1.1.1.1', '8.8.8.8'],
        }
        proxies.append(proxy)

    clash_config = {
        "proxies": proxies,
        "proxy-groups": [],
        "rules": []
    }

    return yaml.dump(clash_config, default_flow_style=False)

def format_to_v2ray(config: Dict[str, Any]) -> str:
    """
    Format server data into a V2Ray-compatible configuration (URL).
    """
    domain = config.get("endpoint", "")
    port = config.get("port", 51820)
    public_key = config.get("publickey", "")
    private_key = config.get("privatekey", "")
    ip = config.get("localip", "172.16.0.2")

    v2ray_config = f'wg://{domain}:{port}?publicKey={public_key}&privateKey={private_key}&ip={ip}&dns=8.8.8.8&udp=1#{domain}'
    return v2ray_config

def save(filename: str, data: str) -> None:
    """
    Save the data to a file.
    """
    with open(filename, "w") as file:
        file.write(data)
    print(f"Saved to {filename}")

def main():
    # Step 1: Login and get token
    token = login()
    if not token:
        return

    # Step 2: Fetch servers
    servers_response = get_servers(token)
    if not servers_response or "data" not in servers_response:
        print("Failed to retrieve servers.")
        return

    servers = servers_response.get('data', {}).get('servers', [])

    # Step 3: Process servers with a custom parser in parallel
    server_configs = process_server_data(servers, server_config)

    # Step 4: Format the servers into Clash and V2Ray configuration formats
    clash_config = format_to_clash(server_configs)
    v2ray_config = [format_to_v2ray(config) for config in server_configs if config]


    save("clash.yaml", clash_config)
    save("v2ray.txt", "\n".join(v2ray_config))

if __name__ == "__main__":
    main()
