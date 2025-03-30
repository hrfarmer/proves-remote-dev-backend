# PROVES Kit Remote Testing

Software to be able to remotely test code for either v4 or v5 boards.

Right now it just tests installing code to the board whenever there's a PR, but in the future it will be able to run integration tests on the boards.

## Setup

```sh
git clone https://github.com/proveskit/proves_remote_testing
cd proves_remote_testing
pip install -r requirements.txt
```

Then, copy `config_template.json`, name it `config.json`, and then fill out the following fields:

```jsonc
{
  "repo_author": "", // The author of the repository (ex. proveskit)
  "repo_name": "", // The name of the repository (ex. CircuitPython_RP2040_v4)
  "check_name": "", // The name of the check that will show up on pull requests
  "board_mount_point": "" // Where the board is mounted on your file system, so files can be installed to it
}
```

Next, navigate to https://github.com/settings/apps, create a new GitHub App named however you want, and then:

- Copy `.env.template`, rename it to `.env`, and then fill out the Client ID with the one from your GitHub App, and fill out the org that owns the GitHub App.
- Scroll down to `Private Keys`, generate & download your private key, rename it to `auth.pem`, and put it in the root directory of the project
- Save your changes

If you are going to host this on a local machine, download and setup [Ngrok](https://ngrok.com/), so that you can forward the port online for the GitHub webhook.

On the repository you want to setup the test for, go to `Settings -> Webhooks -> Add Webhook`. Then follow these steps:

1. Set the payload url to `(Your Ngrok url)/webhook`
2. Set content type to `application/json`
3. Create a secret to make sure you only accept webhooks from GitHub (`openssl rand -base64 32`), & put that secret inside of your `.env`
4. Select `Let me select individual events` and check the `Pull requests` checkbox.
5. Create the webhook

Finally, run `python main.py` and the program will be ready to go!
