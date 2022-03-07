# newreleases.io dispatch action

simple endpoint to listen for a newreleases.io webhook event, verify its signature, verify a known value, and forward it to a github action webhook dispatch endpoint

the service listens on `/{owner}/{repo}/{event_type}`, and will forward the dispatch to a workflow with the `event_type` defined

```
on:
  repository_dispatch:
    types: [event_type]
```

Check out a [working example](https://github.com/kryptn/infra/blob/main/.github/workflows/newreleases.yaml) of an action.


## Usage

Setup a webhook in [your newreleases webhook settings](https://newreleases.io/settings/webhooks). Set the url to `https://domain.tld/{owner}/{repo}/{event_type}` and the `X-Known-Value` header to some known secret value. Use that same value for the `NEWRELEASES_KNOWN_VALUE` environment variable

Set the `NEWRELEASES_WEBHOOK_SECRET_KEY` environment variable to the webhook secret newreleases gives you.

Create a github personal access token with the `Workflow` scope, and use that for the `GITHUB_TOKEN` environment variable.

```
docker pull ghcr.io/kryptn/newreleases-dispatch-action:v0.2.6
docker run \
  -e NEWRELEASES_WEBHOOK_SECRET_KEY=$NEWRELEASES_WEBHOOK_SECRET_KEY \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e NEWRELEASES_KNOWN_VALUE=$NEWRELEASES_KNOWN_VALUE \
  -e RUST_LOG=info \
  -p 3000:3000 \
  ghcr.io/kryptn/newreleases-dispatch-action:v0.2.6
```

## todo

Some nice-to-haves

- Replay update
- Provide docker compose
    - could use cloudflare tunnel with it
- kustomization or helm chart?
- other dispatch targets?