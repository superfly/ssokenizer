# ssokenizer

Ssokenizer provides a layer of abstraction for applications wanting to authenticate users and access 3rd party APIs via OAuth, but not wanting to directly handle users' API tokens. Ssokenizer is responsible for performing the OAuth dance, obtaining the user's OAuth access token. The token is then encrypted for use with the [tokenizer](https://github.com/superfly/tokenizer) HTTP proxy. By delegating OAuth authentication to ssokenizer and access token usage to tokenizer, applications limit the risk of tokens being lost, stolen, or misused.

![](/docs/sequence_diagram.svg)

## Configuration

Ssokenizer searches for a configuration file at `/etc/ssokenizer.yml`, but a path can be specified with the `-config` flag. See [`/etc/ssokenizer.yml`](/etc/ssokenizer.yml) in this repo for an annotated example configuration. Environment variables in the configuration file are expanded when the application is booting.

## Deploying to fly.io

- Fork this repository on GitHub
- Clone the forked repository
- In a terminal, enter the repository directory and run `fly launch`
- Follow the prompts, declining to deploy the new application.
- Set secrets (`TOKENIZER_SEAL_KEY`, `PROXY_AUTH`, `<PROVIDER>_CLIENT_SECRET`) by running `fly secrets set --stage SECRET_NAME="SECRET_VALUE"`
- Edit the configuration file in [`/etc/ssokenizer.yml`](/etc/ssokenizer.yml) to reflect the OAuth providers you would like to support. The secrets you set in the previous step will be available as environment variables in this configuration file.
- Run `make deploy` or `fly deploy`

## Usage

To start the authentication flow, navigate users to `https://<ssokenizer-url>/<provider-name>/start?state=<state>`. The `<ssokenizer-url>` and `<provider-name>` will depend on your configuration and how you've deployed the app. The `state` parameter is used to prevent login-CSRF attacks. Your application should generate a random string and associate it with the user's session by either putting it in the session-store provided by your web framework or by putting it directly in a cookie.

The user will now perform the OAuth dance with ssokenizer and the identity provider. Upon successful completion, the user will be redirected back to your configured `return_url` with several parameters:

- `sealed` - The sealed OAuth access token and refresh token (if applicable), ready for use with your tokenizer deployment.
- `expires` - The unix epoch time when the access token will expire, if applicable.
- `state` - The state parameter that you passed to the `/start` URL. It is important for your application to verify that this matches the state value you stored in the user's session or cookie.

If the OAuth dance doesn't finish successfully, an `error` parameter will be added to the configured `return_url` instead of the `sealed` and `expired` parameter. 

### Using the sealed token

You are now ready to communicate with the provider API using the sealed token via the tokenizer HTTP proxy. You'll need to send the sealed token in the `Proxy-Tokenizer` header. You'll need to send the configured `proxy_authorization` secret in the `Proxy-Authorization` with the `Bearer` authorization scheme. Remember that requests made via tokenizer must use HTTP instead of HTTPS.

The following demonstrates how you might call the Google "userinfo" endpoint using cURL:

```shell
curl \
    -x $TOKENIZER_URL \
    -H "Proxy-Authorization: Bearer $PROXY_AUTH" \
    -H "Proxy-Tokenizer: $SEALED_TOKEN" \
    http://openidconnect.googleapis.com/v1/userinfo
```

### Refreshing access tokens

Some identity providers issue access tokens that expire quickly along with refresh tokens that can be used to fetch new access tokens. To fetch a new access token, send a request to `https://<ssokenizer-url>/<provider-name>/refresh` via tokenizer. Include the sealed token in the `Proxy-Tokenizer` header, including a `st=refresh` parameter in the header. The response body will contain the new token, sealed for use with tokenizer and the Cache-Control header will contain the seconds until the token expires.

The following demonstrates how you might refresh a token using cURL:

```shell
curl \
    -x $TOKENIZER_URL \
    -H "Proxy-Authorization: Bearer $PROXY_AUTH" \
    -H "Proxy-Tokenizer: $SEALED_TOKEN; st=refresh" \
    http://$SSOKENIZER_HOSTNAME/$PROVIDER_NAME/refresh
```