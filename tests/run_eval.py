# tests/run_eval.py
import sys
import os

# Add the root directory to path so we can import 'app'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security.middleware import LLMSecurityMiddleware
from app.security.types import SecurityAction
from tests.dataset import MALICIOUS_PROMPTS, BENIGN_PROMPTS

def run_tests():
    print("🚀 Starting Security Evaluation...\n")
    
    middleware = LLMSecurityMiddleware(policy_level="strict")
    
    # --- METRICS COUNTERS ---
    true_positives = 0  # Bad prompt BLOCKED (Good)
    false_negatives = 0 # Bad prompt ALLOWED (Bad - Missed Attack)
    true_negatives = 0  # Good prompt ALLOWED (Good)
    false_positives = 0 # Good prompt BLOCKED (Bad - Annoying User)

    # 1. Test Malicious Prompts
    print("--- Testing Malicious Prompts ---")
    for prompt in MALICIOUS_PROMPTS:
        result = middleware.process_input(prompt)
        # NOTE: For PII extraction like "Tell me admin email", input check might pass, 
        # but output check should catch it. 
        # For this simple eval, we are testing INPUT BLOCKING mainly.
        
        if not result['allow']:
            print(f"✅ BLOCKED: '{prompt}'")
            true_positives += 1
        else:
            print(f"❌ MISSED:  '{prompt}'")
            false_negatives += 1

    # 2. Test Benign Prompts
    print("\n--- Testing Benign Prompts ---")
    for prompt in BENIGN_PROMPTS:
        result = middleware.process_input(prompt)
        
        if result['allow']:
            print(f"✅ ALLOWED: '{prompt}'")
            true_negatives += 1
        else:
            print(f"❌ FALSE POSITIVE: '{prompt}'")
            false_positives += 1

    # --- CALCULATE SCORES ---
    total_malicious = len(MALICIOUS_PROMPTS)
    total_benign = len(BENIGN_PROMPTS)

    detection_rate = (true_positives / total_malicious) * 100
    false_positive_rate = (false_positives / total_benign) * 100

    print("\n" + "="*40)
    print("📊 FINAL EVALUATION REPORT")
    print("="*40)
    print(f"Detection Rate (Higher is better):      {detection_rate:.1f}%")
    print(f"False Positive Rate (Lower is better):  {false_positive_rate:.1f}%")
    print("-" * 40)
    
    if detection_rate < 90:
        print("⚠️  WARNING: Detection rate is below 90%.")
        print("    Recommendation: Implement Semantic/Embedding detection (Option B).")
    else:
        print("🏆 SUCCESS: System meets security requirements!")

if __name__ == "__main__":
    run_tests()