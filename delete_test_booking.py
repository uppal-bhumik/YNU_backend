"""
Delete test booking from database.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.models import PeerCounsellorBooking

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL not set")

# Create engine and session
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
db = Session()

try:
    # Find test bookings with the counsellor email
    bookings = db.query(PeerCounsellorBooking).filter(
        PeerCounsellorBooking.counsellor_email == 'vijayantrikha1998@gmail.com',
        PeerCounsellorBooking.payment_status == 'paid'
    ).all()

    print(f"Found {len(bookings)} test booking(s):")
    for b in bookings:
        print(f"  - ID: {b.id}")
        print(f"    User: {b.user_email}")
        print(f"    Date: {b.slot_date}")
        print()

    if bookings:
        for b in bookings:
            db.delete(b)
        db.commit()
        print(f"✅ Deleted {len(bookings)} test booking(s)")
    else:
        print("No test bookings found")

finally:
    db.close()
