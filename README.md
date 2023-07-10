# ssokenizer

Ssokenizer provides a layer of abstraction for applications wanting to authenticate users and access 3rd party APIs via OAuth, but not wanting to directly handle users' API tokens. Ssokenizer is responsible for performing the OAuth dance, obtaining the user's OAuth access token. The token is then encrypted for use with the [tokenizer](https://github.com/superfly/tokenizer) HTTP proxy. By delegating OAuth authentication to ssokenizer and access token usage to tokenizer, applications limit the risk of tokens being lost, stolen, or misused.

![](/docs/sequence_diagram.svg)

## Configuration

Ssokenizer searches for a configuration file at `/etc/ssokenizer.yml`, but a path can be specified with the `-config` flag. See [`/etc/ssokenizer.yml`](/etc/ssokenizer.yml) in this repo for an annotated example configuration.

## Deploying to fly.io

TKTK
