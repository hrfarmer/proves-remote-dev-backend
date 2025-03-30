import json
import os
import webbrowser

import aiohttp
from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

# GitHub OAuth configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth"

# GitHub OAuth endpoints
AUTH_URL = "https://github.com/apps/proveskit-board-tester"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"

async def get_github_access_token(code: str) -> dict:
    """Exchange a GitHub OAuth code for an access token."""
    async with aiohttp.ClientSession() as session:
        data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI
        }
        headers = {"Accept": "application/json"}
        
        async with session.post(GITHUB_TOKEN_URL, data=data, headers=headers) as response:
            return await response.json()

async def auth_handler(request):
    """Handle the OAuth callback from GitHub."""
    code = request.query.get("code")
    if not code:
        return web.Response(text="Error: No code received", status=400)
    
    try:
        token_data = await get_github_access_token(code)
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        
        # Write tokens to auth.json
        auth_data = {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
        
        with open('auth.json', 'w', encoding='utf-8') as f:
            json.dump(auth_data, f, indent=2)
        
        return web.Response(
            text="Success! Your GitHub access token has been saved to auth.json\n"
                 "You can now close this window.",
            content_type="text/html"
        )
    except Exception as e:
        return web.Response(text=f"Error: {str(e)}", status=500)

def main():
    # Print instructions
    print("\nGitHub OAuth Authentication")
    print("==========================")
    print(f"1. Visit this URL to authorize the application:\n{AUTH_URL}")
    print("\n2. After authorizing, you'll be redirected back to this application.")
    print("3. Your access token will be saved to auth.json")
    print("\nStarting local server...")
    
    # Open the browser automatically
    webbrowser.open(AUTH_URL)
    
    # Create and run the web server
    app = web.Application()
    app.router.add_get("/auth", auth_handler)
    
    # Run the server
    web.run_app(app, host="localhost", port=8000)

if __name__ == "__main__":
    main() 
