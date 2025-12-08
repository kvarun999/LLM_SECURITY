from fastapi import FastAPI
from pydantic import BaseModel

from app.security.middleware import LLMSecurityMiddleware
from app.security.policy import SecurityPolicy
from app.llm.client import LLMClient

app = FastAPI(title="LLM Security Demo")

# ---------- Schemas ----------
class PromptRequest(BaseModel):
    prompt: str

class PromptResponse(BaseModel):
    response: str

# ---------- Init security + LLM (placeholders for now) ----------
policy = SecurityPolicy(level="balanced")  # we'll define properly soon
security = LLMSecurityMiddleware(policy=policy)
llm_client = LLMClient()  # stub for now


@app.post("/chat", response_model=PromptResponse)
async def chat(req: PromptRequest):
    # Step 1: secure input
    secured_prompt, events_in = await security.process_input(req.prompt)

    # Step 2: call underlying LLM
    raw_output = await llm_client.generate(secured_prompt)

    # Step 3: secure output
    secured_output, events_out = await security.process_output(raw_output)

    return PromptResponse(response=secured_output)
