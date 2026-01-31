"""Verify recommendation tables structure in the database."""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect

load_dotenv()

engine = create_engine(os.getenv('DATABASE_URL'))
inspector = inspect(engine)

# Get all recommendation tables
tables = [t for t in inspector.get_table_names() if t.startswith('rec_')]

print("=" * 60)
print("RECOMMENDATION TABLES VERIFICATION")
print("=" * 60)
print(f"\nFound {len(tables)} recommendation tables:\n")

for table in sorted(tables):
    print(f"  ✓ {table}")

print("\n" + "=" * 60)
print("TABLE SCHEMAS")
print("=" * 60)

for table in sorted(tables):
    columns = inspector.get_columns(table)
    print(f"\n{table} ({len(columns)} columns):")
    print("-" * 40)
    for col in columns:
        nullable = "NULL" if col['nullable'] else "NOT NULL"
        print(f"  {col['name']:<40} {str(col['type']):<20} {nullable}")

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE")
print("=" * 60)
