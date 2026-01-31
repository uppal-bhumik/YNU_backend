"""
Debug test to check database content
"""
import sys
sys.path.insert(0, ".")

from db import SessionLocal
from models.models import Program
from recommendation.logic.adapter import normalize_degree_level

print("Checking database content...")

db = SessionLocal()
try:
    # Get first 10 programs
    programs = db.query(Program).limit(20).all()
    print(f"\nFound {len(programs)} programs in database")
    
    if programs:
        print("\nFirst 10 programs:")
        for i, prog in enumerate(programs[:10], 1):
            attrs = prog.attributes or {}
            name = attrs.get("name", "Unknown")
            raw_level = attrs.get("level") or attrs.get("degreeLevel", "")
            normalized_level = normalize_degree_level(raw_level)
            school = attrs.get("school", {}) or {}
            country = school.get("country", "Unknown")
            
            print(f"{i}. {name}")
            print(f"   Raw Level: {raw_level}")
            print(f"   Normalized: {normalized_level}")
            print(f"   Country: {country}")
    else:
        print("No programs in database!")
        
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
