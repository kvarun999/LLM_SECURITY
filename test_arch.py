# test_arch.py
from app.security.middleware import LLMSecurityMiddleware

def test_full_flow():
    print("--- Starting Security Test ---")
    security = LLMSecurityMiddleware(policy_level="strict")

    # ... keep your existing input tests ...

    # TEST: Output Sanitization
    # Simulate an LLM that accidentally leaks data
    llm_response = "Sure! Contact me at bob@example.com or call 555-012-3456."
    
    print(f"\n[Original LLM Output]: {llm_response}")
    
    clean_res = security.process_output(llm_response)
    
    print(f"[Sanitized Output]:   {clean_res.get('response')}")
    print(f"[Metadata]:           {clean_res.get('metadata')}")
    
    # Validation Logic
    if "@" not in clean_res.get('response') and "<EMAIL_REDACTED>" in clean_res.get('response'):
        print("✅ SUCCESS: Email was redacted.")
    else:
        print("❌ FAILED: PII leaked!")

if __name__ == "__main__":
    test_full_flow()