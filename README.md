# poetrist

a tiny, single-file blog engine.

## Getting start

```bash
git clone https://github.com/huangziwei/poetrist.git
cd poetrist

# Initialise the database (creates the first admin user + token)
FLASK_APP=poetrist/blog.py flask init          # follow the prompts

# (Optional) regenerate a one-time login token later
# FLASK_APP=poetrist/blog.py flask token

# Create a **trusted** HTTPS certificate for localhost
# Passkeys need a cert the OS/browser actually trusts → use mkcert
# brew install mkcert
mkcert localhost
mkdir secrets
mv *.pem secrets
mkcert -install

# Run it
FLASK_APP=poetrist/blog.py flask run --cert=secrets/localhost.pem --key=secrets/localhost-key.pem --port 2046 --debug
```