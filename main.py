import asyncio
import hashlib
import hmac
import json
import os
import subprocess

import aiohttp
import aiohttp.web_request
import requests
from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

app = web.Application()
routes = web.RouteTableDef()

# Get auth information
try:
    with open('auth.json', 'r', encoding='utf-8') as f:
        auth_data = json.load(f)
except FileNotFoundError:
    print("Failed to load auth.json. Please run github_auth.py to authenticate.")
    exit(1)

# Load config.json and verify that it is valid and fields aren't empty
try:
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)
except FileNotFoundError:
    print("Failed to load config.json. Please create a config.json file.")
    exit(1)

if config["repo_author"] == "" or config["repo_name"] == "" or config["check_name"] == "" or config["board_mount_point"] == "":
    print("One or more fields in config.json are empty. Please fill out all fields.")
    exit(1)

# Add initialization variables
queue = []

async def refresh_github_token():
    """Refresh the GitHub access token every hour."""
    while True:
        try:
            # Get new access token using refresh token
            async with aiohttp.ClientSession() as session:
                data = {
                    "client_id": os.getenv("GITHUB_CLIENT_ID"),
                    "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
                    "refresh_token": auth_data["refresh_token"],
                    "grant_type": "refresh_token"
                }
                headers = {"Accept": "application/json"}
                
                async with session.post("https://github.com/login/oauth/access_token", data=data, headers=headers) as response:
                    token_data = await response.json()
                    
                    if "access_token" in token_data:
                        # Update auth.json with new tokens
                        auth_data["access_token"] = token_data["access_token"]
                        if "refresh_token" in token_data:
                            auth_data["refresh_token"] = token_data["refresh_token"]
                        
                        with open('auth.json', 'w', encoding='utf-8') as f:
                            json.dump(auth_data, f, indent=2)
                        
                        print("Successfully refreshed GitHub access token")
                    else:
                        print("Failed to refresh GitHub access token")
        except Exception as e:
            print(f"Error refreshing GitHub token: {e}")
        
        # Wait for 1 hour before next refresh
        await asyncio.sleep(3600)  # 3600 seconds = 1 hour

async def queue_runner():
    while True:
        if len(queue) > 0:
            repo_path = queue.pop(0)
            # Run install_repo in a background thread and wait for it to complete
            await asyncio.to_thread(install_repo, repo_path)
        else:
            await asyncio.sleep(1)

def verify_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        raise web.HTTPForbidden(reason="x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body.encode('utf-8'), digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise web.HTTPForbidden(reason="Request signatures didn't match!")

# Webhook endpoint
@routes.post("/webhook")
async def webhook(request: aiohttp.web_request.Request):
    verify_signature(await request.text(), os.getenv("WEBHOOK_SECRET"), request.headers.get("x-hub-signature-256"))
    print(await request.json())

    data = await request.json()

    try:
        if data["action"] == "created" or data["action"] == "synchronize":
            queue.append(data["pull_request"]["url"])
    except Exception as e:
        print(f"Error processing webhook: {e}")

    return web.json_response({"message": "Webhook received"})

def install_repo(url):
    # Get pull request data
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()
    
    try:
        check_run_id = start_pr_check(data["head"]["sha"])
    except Exception as e:
        print(f"Failed to start PR check: {e}")

    # Pull the repository
    repo_url = f"https://github.com/{data["head"]["repo"]["full_name"]}"
    repo_branch = data["head"]["ref"]

    repo_path = f"repos/{repo_branch}-{data['head']['sha']}"
    if os.path.exists(repo_path):
        os.system(f"rm -rf {repo_path}")
    os.makedirs(repo_path)

    try:
        subprocess.run(["git", "clone", repo_url, repo_path], check=True)
        subprocess.run(["git", "checkout", data["head"]["sha"]], cwd=repo_path, check=True)
        subprocess.run(["make", "install", f"BOARD_MOUNT_POINT={config['board_mount_point']}"], cwd=repo_path, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install repository to board: {e}")
        fail_pr_check(check_run_id)
        return

    # Install repository to board
    print(f"Installed {data["title"]} to PROVES Kit")

    finish_pr_check(check_run_id)

def start_pr_check(head_sha):
    response = requests.post(f"https://api.github.com/repos/{config['repo_author']}/{config['repo_name']}/check-runs", headers={
        "Authorization": f"Bearer {os.getenv('GITHUB_ACCESS_TOKEN')}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }, json={
        "head_sha": head_sha,
        "name": config["check_name"],
        "status": "in_progress"
    }, timeout=30)
    response.raise_for_status()
    return response.json()["id"]

def fail_pr_check(check_run_id):
    response = requests.patch(f"https://api.github.com/repos/{config['repo_author']}/{config['repo_name']}/check-runs/{check_run_id}", headers={
        "Authorization": f"Bearer {os.getenv('GITHUB_ACCESS_TOKEN')}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }, json={"status": "completed", "conclusion": "failure"}, timeout=30)
    response.raise_for_status()

def finish_pr_check(check_run_id):
    response = requests.patch(f"https://api.github.com/repos/{config['repo_author']}/{config['repo_name']}/check-runs/{check_run_id}", headers={
        "Authorization": f"Bearer {os.getenv('GITHUB_ACCESS_TOKEN')}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }, json={"status": "completed", "conclusion": "success"}, timeout=30)
    response.raise_for_status()

app.add_routes(routes)

if __name__ == '__main__':
    # Create and run the queue runner task
    loop = asyncio.get_event_loop()
    loop.create_task(queue_runner())
    loop.create_task(refresh_github_token())

    web.run_app(app, loop=loop, host='0.0.0.0', port=int(os.getenv("PORT", 8000)))
