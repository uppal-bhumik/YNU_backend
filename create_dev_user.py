"""
Create dev@localhost.test user for development mode.
This user is needed for the dev-bypass-token authentication to work.
"""
import os
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.models_user import User
from werkzeug.security import generate_password_hash

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL not set")

# Create engine and session
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

try:
    # Check if dev user already exists
    existing = db.query(User).filter(User.email == "dev@localhost.test").first()
    
    if existing:
        print(f"✅ Dev user already exists:")
        print(f"   Email: {existing.email}")
        print(f"   ID: {existing.id}")
        print(f"   Role: {existing.role}")
    else:
        # Create dev user
        dev_user = User(
            id=uuid.uuid4(),
            email="dev@localhost.test",
            password_hash=generate_password_hash("dev123"),  # Correct column name
            role="student",
            full_name="Dev User",
            is_verified=True
        )
        db.add(dev_user)
        db.commit()
        db.refresh(dev_user)
        
        print(f"✅ Created dev user:")
        print(f"   Email: {dev_user.email}")
        print(f"   ID: {dev_user.id}")
        print(f"   Password: dev123")
        print(f"   Role: {dev_user.role}")
        print()
        print("You can now use dev-bypass-token in the frontend!")

finally:
    db.close()
