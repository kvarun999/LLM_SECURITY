# LLM Security Middleware 🛡️

A robust, multi-layered security pipeline designed to protect Large Language Model applications.

## Features

- **Fail-Fast Regex Detection:** Instantly blocks known attack signatures.
- **Semantic Intent Analysis:** Uses `sentence-transformers` to block attacks based on meaning.
- **Output Sanitization:** Redacts PII from LLM responses.
- **FastAPI Integration:** Ready-to-use middleware wrapper.

## Installation

1. `git clone <repo>`
2. `pip install -r requirements.txt`

## Usage

Start the API:

```bash
uvicorn app.main:app --reload
```
