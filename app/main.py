# app/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

# Import your security middleware
from app.security.middleware import LLMSecurityMiddleware

app = FastAPI(title="Secure LLM API")

# Initialize Middleware (Balanced Policy by default)
security_middleware = LLMSecurityMiddleware(policy_level="balanced")

# --- 1. Data Models (The Protocol) ---
class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    response: str
    metadata: Dict[str, Any]

# --- 2. The Mock LLM (The Simulation) ---
def mock_llm_generate(prompt: str) -> str:
    """
    Simulates an LLM. 
    It includes a specific trigger to test Output Sanitization.
    """
    # Trigger for testing PII redaction
    if "secret" in prompt.lower():
        return "Sure, here is the admin email: admin@company.com and the API key is AKIA1234567890123456."
    
    # Normal echo response
    return f"I received your prompt: '{prompt}'. As an AI, I am happy to help."

# --- 3. The Endpoint (The Controller) ---
@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    
    # A. INPUT SECURITY LAYER
    # -----------------------
    input_security = security_middleware.process_input(request.prompt)
    
    if not input_security["allow"]:
        # We return 403 Forbidden as requested
        raise HTTPException(
            status_code=403, 
            detail=f"Security Alert: {input_security.get('message')}"
        )

    # Get the sanitized prompt (if any changes were made)
    safe_prompt = input_security["prompt"]

    # B. LLM EXECUTION LAYER
    # ----------------------
    # In a real app, you would call OpenAI/Anthropic here
    raw_response = mock_llm_generate(safe_prompt)

    # C. OUTPUT SECURITY LAYER
    # ------------------------
    output_security = security_middleware.process_output(raw_response)

    if not output_security["allow"]:
        raise HTTPException(
            status_code=403, 
            detail="Response blocked due to security policy violation."
        )

    # Return the sanitized response
    return ChatResponse(
        response=output_security["response"],
        metadata=output_security["metadata"]
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)