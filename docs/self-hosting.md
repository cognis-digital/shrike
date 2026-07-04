# Self-hosting the model

shrike's reasoning layer is optional and **always local**. This page shows how to wire it to a
model on your own machine or network. If you skip all of this, shrike still runs its full
deterministic pipeline — you just won't get the natural-language executive summary.

## The contract

shrike talks to one endpoint, an Ollama-style `/api/chat`:

| Variable | Default | Meaning |
|---|---|---|
| `SHRIKE_LLM_ENDPOINT` | `http://127.0.0.1:11434/api/chat` | Chat endpoint |
| `SHRIKE_LLM_MODEL` | `llama3.1` | Model name |

It sends the finding summaries and asks for a short executive summary. It never sends secrets it
finds (those are redacted in transit), never retries against a remote host, and never phones home.

## Ollama (simplest)

```bash
# install ollama from https://ollama.com, then:
ollama pull llama3.1
shrike audit --llm                 # uses the local ollama automatically
```

## LM Studio / vLLM / any OpenAI-compatible server

Point the endpoint at your server's chat route:

```bash
export SHRIKE_LLM_ENDPOINT="http://127.0.0.1:1234/api/chat"
export SHRIKE_LLM_MODEL="your-local-model"
shrike audit --llm
```

## A model on another box on your LAN

```bash
export SHRIKE_LLM_ENDPOINT="http://10.0.0.20:11434/api/chat"
shrike audit --llm --model mistral-small
```

The traffic stays inside your network. This is the whole point: you can run shrike against
production MCP configuration and nothing goes to a third party.

## Air-gapped

Everything except `--llm` works with no network at all. On a fully air-gapped host, run a local
model on the same machine (Ollama binds to localhost) and you have autonomous AI-stack auditing
with zero external dependencies.

## Verifying isolation

```bash
# shrike makes no outbound calls without --llm. Confirm it yourself:
strace -f -e trace=network shrike audit ./configs   # linux
```
You will see no sockets opened except, with `--llm`, the one to your configured endpoint.
