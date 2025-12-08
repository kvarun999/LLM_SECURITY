# test_arch.py
from app.security.middleware import LLMSecurityMiddleware

def test_basic_flow():
    security = LLMSecurityMiddleware(policy_level="strict")
    
    # Test Input
    in_result = security.process_input("Hello, this is a test.")
    print(f"Input Check: {in_result}")
    
    # Test Output
    out_result = security.process_output("Here is the secret data.")
    print(f"Output Check: {out_result}")

if __name__ == "__main__":
    test_basic_flow()