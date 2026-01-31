"""
Simple test for degree filter fix
"""
import sys
sys.path.insert(0, ".")

from db import SessionLocal
from recommendation.logic.contracts import StudentProfile
from recommendation.logic.runner import run_recommendations
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)

print("Starting simple test...")

profile = StudentProfile(
    student_id="test_simple",
    target_degree_level="masters",
    preferred_countries=["Ireland"],
    academic_score_band="good",
    language_score_band="good",
)

db = SessionLocal()
try:
    print("Running recommendations...")
    output = run_recommendations(db, profile, limit=50)
    
    print(f"\nRESULTS:")
    print(f"  Evaluated: {output.total_candidates_evaluated}")
    print(f"  Eligible: {output.total_eligible}")
    print(f"  Recommended: {output.total_recommended}")
    
    if output.all_recommendations:
        print(f"\nTop 3:")
        for rec in output.all_recommendations[:3]:
            print(f"  {rec.rank}. {rec.program_name} ({rec.degree_type})")
    
    if output.warnings:
        print(f"\nWarnings: {output.warnings}")
        
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
