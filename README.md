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

# Create a self-signed cert so you can test HTTPS locally
openssl req -x509 -newkey rsa:4096 \
            -keyout poetrist/key.pem \
            -out    poetrist/cert.pem \
            -sha256 -days 365 -nodes \
            -subj "/CN=localhost"

# Run it
FLASK_APP=poetrist/blog.py \
flask run --cert=poetrist/cert.pem --key=poetrist/key.pem --debug
```