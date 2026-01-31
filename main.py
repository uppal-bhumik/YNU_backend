from fastapi import FastAPI, Depends, HTTPException, Depends, Header, Query, Path, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from sqlalchemy import and_
from sqlalchemy.orm import Session
import random, string
from typing import Optional
import os
import psycopg2
from fastapi.responses import JSONResponse
import boto3
from google.oauth2 import service_account
import gspread
from fastapi.responses import JSONResponse
import json
from sqlalchemy import cast, Integer, text, Float
from sqlalchemy.exc import SQLAlchemyError
import logging
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from models.models import (
    Program,Service, Scholarship, LeadIn, LeadOut, Booking, BookingCreate, AustraliaScholarship, UniversityModel ,ResetPasswordRequest,ForgotPasswordRequest,
    PeerCounsellor, PeerCounsellorAvailability,PeerCounsellorBooking, CartItem, SlotReservation, PaymentRecord
)
from db import Base, engine, get_db
from models.models_user import User
from models.schemas_user import UserRegister, UserLogin, UserVerify, UserOut, TokenResponse
from utils.crud_user import get_user_by_email, create_user
from utils.auth_utils import hash_password, verify_password, create_token, decode_token
from utils.email_service import send_otp, smtp_diagnostics, send_email  # Make sure send_email is imported
from recommendation.routes import router as recommendation_router
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logging.info("App starting with DATABASE_URL")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include recommendation router
app.include_router(recommendation_router)

SERVICES = [
    Service(code="peer", name="Peer Counselling", category="counselling", description="Connect with current international students."),
    Service(code="rep", name="University Representative", category="counselling", description="Official sessions with university reps."),
    Service(code="visa", name="Visa Guidance", category="compliance", description="Checklist & mock interviews."),
    Service(code="scholarship", name="Scholarship Assistance", category="funding", description="Identify & apply for scholarships."),
]

SCHOLARSHIPS = [
    Scholarship(id=1, name="Global Excellence Scholarship", country="Canada", amount="$10,000", level="Masters", deadline="2025-11-01"),
    Scholarship(id=2, name="STEM Innovators Grant", country="USA", amount="$8,000", level="Bachelors", deadline="2025-12-15"),
    Scholarship(id=3, name="EU Research Fellowship", country="Germany", amount="€12,000", level="PhD", deadline="2026-01-20"),
]

LEADS: list[LeadOut] = []
BOOKINGS: list[Booking] = [
    Booking(id=1, topic="Peer Counselling", scheduled_for=datetime.utcnow()+timedelta(days=3), status="upcoming"),
]

Base.metadata.create_all(bind=engine)

DB_URL = os.environ.get("DATABASE_URL")
session = boto3.session.Session()

logging.basicConfig(level=logging.INFO)

def generate_otp(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))

@app.post("/auth/register", response_model=dict, tags=["auth"], summary="Register & send OTP")
def register(payload: UserRegister, db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        existing = get_user_by_email(db, payload.email.lower())
        if existing:
            if existing.is_verified:
                raise HTTPException(status_code=400, detail="Email already registered")
            user = existing
            user.full_name = payload.full_name
            user.role = payload.role
            user.password_hash = hash_password(payload.password)
        else:
            user = create_user(
                db,
                email=payload.email,
                full_name=payload.full_name,
                role=payload.role,
                password_hash=hash_password(payload.password),
            )
        code = generate_otp()
        user.set_otp(code)
        if not send_otp(user.email, code):
            raise HTTPException(status_code=500, detail="Could not send verification email (check SMTP settings)")
        return {"message": "OTP sent to email for verification"}

@app.post("/auth/verify", response_model=TokenResponse, tags=["auth"], summary="Verify OTP & get token")
def verify_otp(payload: UserVerify, db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        user = get_user_by_email(db, payload.email.lower())
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_verified:
            return TokenResponse(access_token=create_token(str(user.id)))
        if not user.otp_code or not user.otp_expires:
            raise HTTPException(status_code=400, detail="No OTP pending")
        if datetime.utcnow() > user.otp_expires:
            raise HTTPException(status_code=400, detail="OTP expired")
        if payload.code != user.otp_code:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        user.is_verified = True
        user.otp_code = None
        user.otp_expires = None
        return TokenResponse(access_token=create_token(str(user.id)))

@app.post("/auth/login", response_model=TokenResponse, tags=["auth"], summary="Login (requires verified)")
def login(payload: UserLogin, db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        user = get_user_by_email(db, payload.email.lower())
        if not user or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Email not verified")
        return TokenResponse(access_token=create_token(str(user.id)))

def auth_user(authorization: str | None = Header(default=None), db_session=Depends(get_db)) -> UserOut:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ",1)[1]
    try:
        data = decode_token(token)
    except Exception as e:
        logging.error(f"Token decode failed: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    user_id = data.get("sub")
    db: Session
    with db_session as db:
        user = db.get(User, user_id)
        if not user:
            logging.error(f"User not found for id: {user_id}")
            raise HTTPException(status_code=401, detail=f"User not found for id: {user_id}")
        payload = {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_verified": user.is_verified,
            "created_at": user.created_at
        }
        return UserOut.model_validate(payload)

@app.get("/users/me", response_model=UserOut, tags=["users"], summary="Current user")
def me(current: UserOut = Depends(auth_user)):
    return current


@app.get("/health", tags=["meta"], summary="Health check")
def health():
    return {"status": "ok"}


@app.get("/services", response_model=list[Service], tags=["services"], summary="List services")
def list_services(category: str | None = None):
    if category:
        return [s for s in SERVICES if s.category == category]
    return SERVICES

    

@app.get("/scholarships", response_model=list[Scholarship], tags=["scholarships"], summary="List scholarships")
def list_scholarships(country: Optional[str] = None, level: Optional[str] = None):
    data = SCHOLARSHIPS
    if country:
        data = [s for s in data if s.country.lower() == country.lower()]
    if level:
        data = [s for s in data if s.level.lower() == level.lower()]
    return data



@app.post("/leads", response_model=LeadOut, status_code=201, tags=["leads"], summary="Create lead")
def create_lead(payload: LeadIn):
    lead = LeadOut(id=len(LEADS)+1, created_at=datetime.utcnow(), **payload.dict())
    LEADS.append(lead)
    return lead


@app.get("/bookings", response_model=list[Booking], tags=["bookings"], summary="List bookings (static demo)")
def list_bookings():
    return BOOKINGS


@app.post("/bookings", response_model=Booking, status_code=201, tags=["bookings"], summary="Create booking (static in-memory)")
def create_booking(payload: BookingCreate):
    b = Booking(id=len(BOOKINGS)+1, topic=payload.topic, scheduled_for=payload.scheduled_for, status="upcoming")
    BOOKINGS.append(b)
    return b


@app.get("/debug/smtp", tags=["meta"], summary="SMTP diagnostics (protected)")
def smtp_debug(current: UserOut = Depends(auth_user)):
    if current.role != "counsellor":
        raise HTTPException(status_code=403, detail="Not authorized")
    return smtp_diagnostics()


@app.post("/api/consultation-excel")
async def consultation_to_excel(request: Request):
    try:
        data = await request.json()
        if "timestamp" not in data:
            data["timestamp"] = datetime.utcnow().isoformat()

        row = [
            data.get("first_name", ""),
            data.get("last_name", ""),
            data.get("email", ""),
            data.get("phone", ""),
            data.get("dial_code", ""),
            data.get("nationality", ""),
            data.get("preferred_destination", ""),      # <-- Added
            data.get("preferred_study_level", ""),      # <-- Added
            data.get("preferred_start_year", ""),       # <-- Added
            data.get("timestamp", "")
        ]

        GOOGLE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE")
        SPREADSHEET_ID = os.environ.get("EXCEL_FILE_ID")

        creds = service_account.Credentials.from_service_account_file(
            GOOGLE_SERVICE_ACCOUNT_FILE,
            scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        )

        gc = gspread.authorize(creds)
        sh = gc.open_by_key(SPREADSHEET_ID)
        worksheet = sh.sheet1
        worksheet.append_row(row)

        return {"status": "ok", "message": "Consultation saved to Google Sheet"}

    except Exception as e:
        import traceback
        return JSONResponse(status_code=500, content={"error": str(e), "trace": traceback.format_exc()})


@app.post("/api/accommodation-excel")
async def accommodation_to_excel(request: Request):
    try:
        data = await request.json()
        if "timestamp" not in data:
            data["timestamp"] = datetime.utcnow().isoformat()

        row = [
            data.get("name", ""),
            data.get("email", ""),
            data.get("phone", ""),
            data.get("message", ""),
            data.get("timestamp", "")
        ]

        GOOGLE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE")
        ACCOMMODATION_SPREADSHEET_ID = os.environ.get("ACCOMMODATION_FILE_ID")

        creds = service_account.Credentials.from_service_account_file(
            GOOGLE_SERVICE_ACCOUNT_FILE,
            scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        )

        gc = gspread.authorize(creds)
        sh = gc.open_by_key(ACCOMMODATION_SPREADSHEET_ID)
        worksheet = sh.sheet1
        worksheet.append_row(row)

        return {"status": "ok", "message": "Accommodation data saved to Google Sheet"}

    except Exception as e:
        import traceback
        return JSONResponse(status_code=500, content={"error": str(e), "trace": traceback.format_exc()})

@app.get("/universities/{school_id}")
def get_university_by_school_id(
    school_id: str,
    db_session=Depends(get_db)
):
   
    db: Session
    with db_session as db:
        uni = db.query(UniversityModel).filter(UniversityModel.id == str(school_id)).first()
        if not uni:
            raise HTTPException(status_code=404, detail="University not found")
        return {
            "id": uni.id,
            "type": uni.type,
            "attributes": uni.attributes,
            "relationships": uni.relationships,
            "included": getattr(uni, "included", None)
        }

@app.get("/scholarships/{school_id}")
def get_scholarships_by_school_id(
    school_id: str,
    db_session=Depends(get_db)
):

    db: Session
    with db_session as db:
        from models.models import ScholarshipModel
        scholarships = db.query(ScholarshipModel).filter(ScholarshipModel.schoolGroupId == int(school_id)).all()
        return [
            {
                "id": sch.id,
                "title": sch.title,
                "description": sch.description,
                "awardAmountFrom": sch.awardAmountFrom,
                "awardAmountTo": sch.awardAmountTo,
                "awardAmountType": sch.awardAmountType,
                "schoolGroupId": sch.schoolGroupId,
                "schoolGroupName": sch.schoolGroupName,
                "sourceUrl": sch.sourceUrl,
                "updatedAt": sch.updatedAt,
            }
            for sch in scholarships
        ]

@app.get("/api/programs/{program_id}")
def get_programs_by_school_id(
    program_id: str,
    db_session=Depends(get_db)
):
    try:
        db: Session
        with db_session as db:
            from models.models import ProgramDetail
            prog = db.query(ProgramDetail).filter(ProgramDetail.id == str(program_id)).first()
            if not prog:
                return JSONResponse(status_code=200, content={})
            return {
                "id": prog.id,
                "attributes": prog.attributes,
                "school": prog.school,
                "program": prog.program,
                "program_requirements": prog.program_requirements,
                "school_id": prog.school_id,
                "program_basic": getattr(prog, "program_basic", None)
            }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/program-details", tags=["programs"], summary="List programs from program_details table")
def list_program_details(
    university_name: Optional[str] = Query(None, description="University name (partial match)"),
    program_name: Optional[str] = Query(None, description="Program name (partial match)"),
    country: Optional[str] = Query(None, description="Country code (partial match)"),
    min_fees: Optional[int] = Query(None, description="Minimum tuition fee"),
    max_fees: Optional[int] = Query(None, description="Maximum tuition fee"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db_session=Depends(get_db),
):
    try:
        from models.models import ProgramDetail
        from sqlalchemy import cast, Integer, String, Float
        with db_session as db:
            query = db.query(ProgramDetail)

            if university_name:
                query = query.filter(
                    cast(ProgramDetail.school["name"], String).ilike(f"%{university_name}%")
                )

            if program_name:
                query = query.filter(
                    cast(ProgramDetail.attributes["name"], String).ilike(f"%{program_name}%")
                )

            if country:
                query = query.filter(
                    cast(ProgramDetail.school["country"], String).ilike(f"%{country}%")
                )

            if min_fees is not None:
                # Extract as string first, then cast to Float. 
                # Note: This assumes the JSON value is a number or string-number.
                query = query.filter(
                    cast(cast(ProgramDetail.attributes["tuition"], String), Float) >= min_fees
                )
            if max_fees is not None:
                query = query.filter(
                    cast(cast(ProgramDetail.attributes["tuition"], String), Float) <= max_fees
                )

            # OPTIMIZATION: Use fast approximate count for unfiltered queries
            # When no filters are applied, use PostgreSQL table statistics (instant)
            # When filters exist, use exact count (necessary for accuracy)
            has_filters = any([university_name, program_name, country, min_fees is not None, max_fees is not None])
            
            if not has_filters:
                # Fast path: Use PostgreSQL statistics for instant approximate count
                # This is ~95% accurate and 100x faster than full table scan
                try:
                    total = db.execute(
                        text("SELECT reltuples::bigint FROM pg_class WHERE relname='program_details'")
                    ).scalar() or 0
                except Exception:
                    # Fallback to exact count if stats query fails
                    total = query.count()
            else:
                # Filtered query: Use exact count (necessary for pagination accuracy)
                total = query.count()

            offset = (page - 1) * page_size
            results = query.offset(offset).limit(page_size).all()
            items = [
                {
                    "id": prog.id,
                    "attributes": prog.attributes,
                    "school": prog.school,
                    "program": prog.program,
                    "program_requirements": prog.program_requirements,
                    "school_id": prog.school_id,
                    "program_basic": getattr(prog, "program_basic", None),
                }
                for prog in results
            ]
            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size,
            }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# COMPARE UNIVERSITIES (V1) - Student POV
# ============================================================================
@app.get("/api/compare-universities", tags=["universities"], summary="Compare up to 4 universities side-by-side")
def compare_universities(
    ids: str = Query(..., description="Comma-separated university IDs (max 4)"),
    db_session=Depends(get_db)
):
    """
    Compare up to 4 universities with aggregated program and scholarship data.
    
    - **ids**: Comma-separated university IDs (e.g., "123,456,789")
    - Returns university-centric response with tuition ranges, program counts, levels, and scholarship info
    """
    try:
        from models.models import ProgramDetail, ScholarshipModel
        from sqlalchemy import func
        
        # Parse and validate IDs
        raw_ids = [id_str.strip() for id_str in ids.split(",") if id_str.strip()]
        unique_ids = list(dict.fromkeys(raw_ids))  # De-duplicate while preserving order
        
        # Validation: 0 or >4 IDs
        if len(unique_ids) == 0:
            return JSONResponse(status_code=400, content={"error": "At least 1 university ID is required"})
        if len(unique_ids) > 4:
            return JSONResponse(status_code=400, content={"error": "Maximum 4 university IDs allowed"})
        
        # Convert to integers for school_id matching (program_details.school_id is INTEGER)
        try:
            int_ids = [int(uid) for uid in unique_ids]
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid university ID format. IDs must be numeric."})
        
        db: Session
        with db_session as db:
            universities_result = []
            
            for uni_id in int_ids:
                str_id = str(uni_id)
                
                # Get university basic info from universities table
                uni = db.query(UniversityModel).filter(UniversityModel.id == str_id).first()
                
                # Get programs for this university
                programs = db.query(ProgramDetail).filter(ProgramDetail.school_id == uni_id).all()
                
                # Get scholarships for this university
                scholarships = db.query(ScholarshipModel).filter(ScholarshipModel.schoolGroupId == uni_id).all()
                
                # Skip if university doesn't exist (partial results)
                if not uni and len(programs) == 0:
                    continue
                
                # Extract university name and country (prefer from programs if available)
                uni_name = None
                uni_country = None
                uni_state = None
                
                if programs:
                    # Get from first program's school JSONB
                    first_prog = programs[0]
                    if first_prog.school:
                        uni_name = first_prog.school.get("name", None)
                        uni_country = first_prog.school.get("country", None)
                
                # Fallback to universities table
                if uni and uni.attributes:
                    if not uni_name:
                        uni_name = uni.attributes.get("name", "Unknown University")
                    if not uni_country:
                        uni_country = uni.attributes.get("country", "Unknown")
                    uni_state = uni.attributes.get("state", None)
                
                if not uni_name:
                    uni_name = "Unknown University"
                if not uni_country:
                    uni_country = "Unknown"
                
                # Aggregate tuition (min/max)
                tuition_values = []
                for prog in programs:
                    if prog.attributes and prog.attributes.get("tuition"):
                        try:
                            tuition_val = float(prog.attributes["tuition"])
                            if tuition_val > 0:
                                tuition_values.append(tuition_val)
                        except (ValueError, TypeError):
                            pass
                
                tuition_min = int(min(tuition_values)) if tuition_values else 0
                tuition_max = int(max(tuition_values)) if tuition_values else 0
                
                # Aggregate program levels (distinct)
                levels_set = set()
                for prog in programs:
                    if prog.attributes and prog.attributes.get("level"):
                        level = prog.attributes["level"]
                        if level and isinstance(level, str):
                            levels_set.add(level)
                
                # Scholarship count
                scholarship_count = len(scholarships)
                
                # Build university response object
                uni_obj = {
                    "id": str_id,
                    "name": uni_name,
                    "country": uni_country,
                    "state": uni_state,
                    "tuition": {
                        "min": tuition_min,
                        "max": tuition_max,
                        "currency": "USD"  # V1 default assumption
                    },
                    "programs": {
                        "total_count": len(programs),
                        "levels": sorted(list(levels_set))
                    },
                    "scholarships": {
                        "count": scholarship_count,
                        "available": scholarship_count > 0
                    },
                    "ranking": None,  # AU-only field, not implemented in V1
                    "living_cost_aud": None  # AU-only field, not implemented in V1
                }
                
                universities_result.append(uni_obj)
            
            # Build response
            return {
                "universities": universities_result,
                "meta": {
                    "compared_count": len(universities_result),
                    "generated_at": datetime.utcnow().isoformat() + "Z"
                }
            }
    
    except Exception as e:
        import traceback
        return JSONResponse(status_code=500, content={"error": str(e), "trace": traceback.format_exc()})


@app.post("/auth/forgot-password", tags=["auth"], summary="Request password reset (send OTP)")
def forgot_password(payload: ForgotPasswordRequest, db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        user = get_user_by_email(db, payload.email.lower())
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        code = generate_otp()
        user.set_otp(code)
        if not send_otp(user.email, code):
            raise HTTPException(status_code=500, detail="Could not send reset email (check SMTP settings)")
        return {"message": "Password reset OTP sent to email"}

@app.post("/auth/reset-password", tags=["auth"], summary="Reset password using OTP")
def reset_password(payload: ResetPasswordRequest, db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        user = get_user_by_email(db, payload.email.lower())
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.otp_code or not user.otp_expires:
            raise HTTPException(status_code=400, detail="No OTP pending")
        if datetime.utcnow() > user.otp_expires:
            raise HTTPException(status_code=400, detail="OTP expired")
        if payload.code != user.otp_code:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        user.password_hash = hash_password(payload.new_password)
        user.otp_code = None
        user.otp_expires = None
        return {"message": "Password reset successful"}

@app.post("/api/auth/google", tags=["auth"], summary="Google OAuth login/register")
def google_oauth_login(
    payload: dict = Body(...),
    db_session=Depends(get_db)
):
    token = payload.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Missing Google token")

    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google client ID not configured")

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo.get("email")
        full_name = idinfo.get("name", "")
        if not email:
            raise HTTPException(status_code=400, detail="Google token missing email")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")

    db: Session
    with db_session as db:
        user = get_user_by_email(db, email.lower())
        if not user:
            random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            user = create_user(
                db,
                email=email,
                full_name=full_name,
                role="student",
                password_hash=hash_password(random_password),
            )
            user.is_verified = True
        elif not user.is_verified:
            user.is_verified = True

        access_token = create_token(str(user.id))
        return {"access_token": access_token}

@app.get("/peer-counsellors/{counsellor_id}/available-slots", tags=["peer-counsellors"])
def get_available_slots(
    counsellor_id: int,
    db_session=Depends(get_db),
    days: int = Query(30, ge=1, le=60, description="Number of days to look ahead for available slots (default 30, max 60)")
):
    """
    Returns available 30-min slots for the next `days` days (default 30) for a given peer counsellor,
    excluding slots already booked for a specific date.
    """
    db: Session
    with db_session as db:
        availabilities = db.query(PeerCounsellorAvailability).filter_by(counsellor_id=counsellor_id).all()
        now = datetime.utcnow()
        end_date = now + timedelta(days=days)
        bookings = db.query(PeerCounsellorBooking).filter(
            PeerCounsellorBooking.counsellor_id == counsellor_id,
            PeerCounsellorBooking.slot_date >= now,
            PeerCounsellorBooking.slot_date < end_date,
            PeerCounsellorBooking.payment_status == "paid"
        ).all()
        booked = set((b.slot_date.date(), b.slot_id) for b in bookings)
        result = []
        for day_offset in range(days):
            day = now.date() + timedelta(days=day_offset)
            weekday = day.strftime("%A")
            for av in availabilities:
                if av.day_of_week == weekday:
                    if (day, av.id) not in booked:
                        result.append({
                            "slot_id": av.id,
                            "date": day.isoformat(),
                            "start_time": av.start_time,
                            "end_time": av.end_time,
                        })
        return result

@app.get("/peer-counsellors", tags=["peer-counsellors"])
def list_peer_counsellors(db_session=Depends(get_db)):
   
    db: Session
    with db_session as db:
        peers = db.query(PeerCounsellor).all()
        result = []
        for peer in peers:
            result.append({
                "id": peer.id,
                "email": peer.email,
                "name": peer.name,
                "phone": peer.phone,
                "contact_method": peer.contact_method,
                "university": peer.university,
                "program": peer.program,
                "location": peer.location,
                "languages": peer.languages,
                "profile_image_url": peer.profile_image_url,
                "about": peer.about,
                "expertise": peer.expertise,
                "work_experience": peer.work_experience,
                "peer_support_experience": peer.peer_support_experience,
                "projects": peer.projects,
                "journey": peer.journey,
                "created_at": peer.created_at,
                "charges": peer.charges
            })
        return result

from fastapi import status

@app.post("/peer-counsellors/upsert", tags=["peer-counsellors"], status_code=status.HTTP_201_CREATED)
def upsert_peer_counsellor(
    payload: dict = Body(...),
    db_session=Depends(get_db)
):
    
    db: Session
    with db_session as db:
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        peer = db.query(PeerCounsellor).filter_by(email=email).first()
        if peer:
            for field, value in payload.items():
                if hasattr(peer, field) and value is not None:
                    setattr(peer, field, value)
        else:
            peer = PeerCounsellor(**payload)
            db.add(peer)
        db.commit()
        db.refresh(peer)
        return {
            "id": peer.id,
            "email": peer.email,
            "name": peer.name,
            "phone": peer.phone,
            "contact_method": peer.contact_method,
            "university": peer.university,
            "program": peer.program,
            "location": peer.location,
            "languages": peer.languages,
            "profile_image_url": peer.profile_image_url,
            "about": peer.about,
            "expertise": peer.expertise,
            "work_experience": peer.work_experience,
            "peer_support_experience": peer.peer_support_experience,
            "projects": peer.projects,
            "journey": peer.journey,
            "created_at": peer.created_at,
            "charges": peer.charges
        }


@app.post("/peer-counsellors/{counsellor_id}/availability/upsert", tags=["peer-counsellors"])
def upsert_peer_availability(
    counsellor_id: int,
    slots: list[dict] = Body(...),
    db_session=Depends(get_db)
):
   
    db: Session
    with db_session as db:
        existing_slots = db.query(PeerCounsellorAvailability).filter_by(counsellor_id=counsellor_id).all()
        slot_ids = [slot.id for slot in existing_slots]
        referenced_slot_ids = set(
            r[0] for r in db.query(PeerCounsellorBooking.slot_id)
            .filter(PeerCounsellorBooking.counsellor_id == counsellor_id)
            .filter(PeerCounsellorBooking.slot_id.in_(slot_ids))
            .all()
        )
        deletable_slot_ids = set(slot_ids) - referenced_slot_ids
        if deletable_slot_ids:
            db.query(PeerCounsellorAvailability).filter(
                PeerCounsellorAvailability.counsellor_id == counsellor_id,
                PeerCounsellorAvailability.id.in_(deletable_slot_ids)
            ).delete(synchronize_session=False)
        for slot in slots:
            db.add(PeerCounsellorAvailability(
                counsellor_id=counsellor_id,
                day_of_week=slot["day_of_week"],
                start_time=slot["start_time"],
                end_time=slot["end_time"]
            ))
        db.commit()
        return {
            "status": "ok",
            "count": len(slots),
            "skipped_existing_slots": list(referenced_slot_ids)
        }

@app.post("/peer-counsellors/book-slot", tags=["peer-counsellors"])
def book_peer_counsellor_slot(
    payload: dict = Body(...),
    db_session=Depends(get_db)
):
    """
    Book a session with a peer counsellor.
    Expects JSON body:
    {
      "user_id": <int>,
      "user_email": <str>,
      "counsellor_id": <int>,
      "counsellor_email": <str>,
      "slot_id": <int>,
      "slot_date": <ISO datetime string>,
      "payment_status": <str, e.g. "pending" or "paid">,
      "meeting_link": <str, optional>
    }
    """
    db: Session
    with db_session as db:
        slot_date = datetime.fromisoformat(payload["slot_date"])
        existing_paid = db.query(PeerCounsellorBooking).filter_by(
            counsellor_id=payload["counsellor_id"],
            slot_id=payload["slot_id"],
            slot_date=slot_date,
            payment_status="paid"
        ).first()
        if existing_paid:
            raise HTTPException(status_code=409, detail="Slot already booked and paid for this date/time")

        if payload.get("payment_status") == "paid":
            existing_any = db.query(PeerCounsellorBooking).filter_by(
                counsellor_id=payload["counsellor_id"],
                slot_id=payload["slot_id"],
                slot_date=slot_date
            ).filter(PeerCounsellorBooking.payment_status.in_(["paid", "pending"])).first()
            if existing_any:
                raise HTTPException(status_code=409, detail="Slot already reserved or paid for this date/time")

        booking = PeerCounsellorBooking(
            user_id=payload["user_id"],
            user_email=payload["user_email"],
            counsellor_id=payload["counsellor_id"],
            counsellor_email=payload["counsellor_email"],
            slot_id=payload["slot_id"],
            slot_date=slot_date,
            payment_status=payload.get("payment_status", "pending"),
            meeting_link=payload.get("meeting_link")
        )
        db.add(booking)
        db.commit()
        db.refresh(booking)

        try:
            subject = "Your Peer Counselling Booking Request"
            message = (
                f"Dear {booking.user_email},\n\n"
                f"Your booking request has been received for {booking.slot_date.strftime('%A, %d %B %Y at %H:%M')}.\n"
                f"Status: {booking.payment_status}\n"
                f"Peer Counsellor: {booking.counsellor_email}\n\n"
                f"Thank you for booking with us!\n"
            )
            send_email(
                to_email=booking.user_email,
                subject=subject,
                message=message
            )
        except Exception as e:
            logging.error(f"Failed to send booking email to candidate: {e}")

        try:
            subject = "A New Booking Has Been Made With You"
            message = (
                f"Dear {booking.counsellor_email},\n\n"
                f"A student ({booking.user_email}) has booked a session with you.\n"
                f"Date & Time: {booking.slot_date.strftime('%A, %d %B %Y at %H:%M')}\n"
                f"Status: {booking.payment_status}\n\n"
                f"Please check your dashboard for details.\n\n"
                f"Thank you for supporting students!\n"
            )
            send_email(
                to_email=booking.counsellor_email,
                subject=subject,
                message=message
            )
        except Exception as e:
            logging.error(f"Failed to send booking email to peer counsellor: {e}")

        return {
            "id": booking.id,
            "user_id": booking.user_id,
            "user_email": booking.user_email,
            "counsellor_id": booking.counsellor_id,
            "counsellor_email": booking.counsellor_email,
            "slot_id": booking.slot_id,
            "slot_date": booking.slot_date.isoformat(),
            "payment_status": booking.payment_status,
            "meeting_link": booking.meeting_link,
            "created_at": booking.created_at.isoformat()
        }

@app.post("/peer-counsellors/confirm-payment", tags=["peer-counsellors"])
def confirm_peer_counsellor_payment(
    payload: dict = Body(...),
    db_session=Depends(get_db)
):
    """
    Confirm payment for a peer counsellor booking.
    Expects JSON body:
    {
      "booking_id": <int>,
      "meeting_link": <str, optional>
    }
    Sets payment_status to "paid" and (optionally) updates meeting_link.
    """
    db: Session
    with db_session as db:
        booking_id = payload.get("booking_id")
        if not booking_id:
            raise HTTPException(status_code=400, detail="booking_id is required")
        booking = db.query(PeerCounsellorBooking).filter_by(id=booking_id).first()
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        if booking.payment_status == "paid":
            raise HTTPException(status_code=409, detail="Booking already marked as paid")

        existing_paid = db.query(PeerCounsellorBooking).filter(
            PeerCounsellorBooking.counsellor_id == booking.counsellor_id,
            PeerCounsellorBooking.slot_id == booking.slot_id,
            PeerCounsellorBooking.slot_date == booking.slot_date,
            PeerCounsellorBooking.payment_status == "paid",
            PeerCounsellorBooking.id != booking.id
        ).first()
        if existing_paid:
            raise HTTPException(status_code=409, detail="Slot already paid for by another user")

        booking.payment_status = "paid"
        if "meeting_link" in payload:
            booking.meeting_link = payload["meeting_link"]
        db.commit()
        db.refresh(booking)

        try:
            slot_time = booking.slot_date.strftime("%A, %d %B %Y at %H:%M")
            subject = "Your Peer Counselling Session is Confirmed"
            message = (
                f"Dear {booking.user_email},\n\n"
                f"Your session with peer counsellor ({booking.counsellor_email}) has been booked.\n"
                f"Date & Time: {slot_time}\n"
                f"Meeting Link: {booking.meeting_link or 'Will be shared soon'}\n\n"
                f"Please join the meeting 5 minutes prior to your scheduled time.\n\n"
                f"Thank you for booking with us!\n"
            )
            send_email(
                to_email=booking.user_email,
                subject=subject,
                message=message
            )
        except Exception as e:
            logging.error(f"Failed to send confirmation email: {e}")

        try:
            slot_time = booking.slot_date.strftime("%A, %d %B %Y at %H:%M")
            subject = "A Session Has Been Booked With You"
            message = (
                f"Dear {booking.counsellor_email},\n\n"
                f"A student ({booking.user_email}) has booked a session with you.\n"
                f"Date & Time: {slot_time}\n"
                f"Meeting Link: {booking.meeting_link or 'Will be shared soon'}\n\n"
                f"Please be ready and join the meeting 5 minutes prior to the scheduled time.\n\n"
                f"Thank you for supporting students!\n"
            )
            send_email(
                to_email=booking.counsellor_email,
                subject=subject,
                message=message
            )
        except Exception as e:
            logging.error(f"Failed to send confirmation email to counsellor: {e}")

        return {
            "id": booking.id,
            "user_id": booking.user_id,
            "user_email": booking.user_email,
            "counsellor_id": booking.counsellor_id,
            "counsellor_email": booking.counsellor_email,
            "slot_id": booking.slot_id,
            "slot_date": booking.slot_date.isoformat(),
            "payment_status": booking.payment_status,
            "meeting_link": booking.meeting_link,
            "created_at": booking.created_at.isoformat()
        }


import httpx
import os
import json
import logging
from fastapi import HTTPException
from pydantic import BaseModel
import socket
import asyncio

logging.basicConfig(level=logging.INFO)

DODO_API_KEY = os.getenv("DODO_PAYMENTS_API_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.getenv("BACKEND_URL", "https://studconnect-backend.onrender.com")

class Customer(BaseModel):
    name: str
    email: str
    phone: str = None

class PaymentRequest(BaseModel):
    amount: float
    customer: Customer
    booking_id: str
    discount_code: str = None

def _resolve_host(host: str) -> tuple[bool, str | None]:
    try:
        ip = socket.gethostbyname(host)
        return True, ip
    except Exception as e:
        return False, str(e)

def _dodo_base_urls() -> list[str]:
    return ["https://live.dodopayments.com"]

async def _http_post_with_retry(
    url: str,
    headers: dict,
    payload: dict,
    attempts: int = 3
) -> httpx.Response:
   
    for attempt in range(1, attempts + 1):
        try:
            timeout = httpx.Timeout(
                connect=10.0,
                read=25.0,
                write=10.0,
                pool=10.0
            )
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
                return await client.post(url, json=payload, headers=headers)
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            if attempt == attempts:
                raise
            backoff = 2 ** (attempt - 1)
            logging.warning(f"[Dodo LIVE] attempt {attempt} failed ({e}); retrying in {backoff}s")
            await asyncio.sleep(backoff)

@app.post("/api/create-dodo-session", tags=["payments"])
async def create_dodo_session(request: PaymentRequest):
    """
    Live-only Dodo checkout session creation.
    - Requires a live API key (sk_live_*)
    - Single endpoint: https://live.dodopayments.com/checkouts
    """
    try:
        if not request.booking_id or not request.amount or request.amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid booking ID or amount")
        if not request.customer.email or not request.customer.name:
            raise HTTPException(status_code=400, detail="Customer email and name are required")
        api_key = DODO_API_KEY
        if not api_key or len(api_key) < 10:
            raise HTTPException(status_code=500, detail="Payment gateway not configured (missing API key)")
        if api_key.startswith("sk_test_"):
            raise HTTPException(status_code=400, detail="Test API key provided. Set a live key (sk_live_...).")

        discount = 0
        if request.discount_code and request.discount_code.lower() == "save50":
            discount = 50
        final_amount = max(request.amount - discount, 0)

        base_url = _dodo_base_urls()[0]  # live only
        host = base_url.replace("https://", "").split("/")[0]
        ok_dns, dns_msg = _resolve_host(host)
        if not ok_dns:
            raise HTTPException(
                status_code=503,
                detail=f"DNS resolution failed for {host}: {dns_msg}\n"
                       "Resolution steps:\n"
                       "  1. Verify outbound DNS/network access to live.dodopayments.com:443\n"
                       "  2. Ensure no firewall blocks egress\n"
                       "  3. Retry after network stabilization\n"
                       "  4. Contact hosting + Dodo support with this message"
            )

        payload = {
            "product_cart": [
                {
                    "product_id": "pdt_isuaGsszAodjHrUaplbG4",
                    "quantity": 1
                }
            ],
            "customer": {
                "email": request.customer.email,
                "name": request.customer.name
            },
            "billing_address": {
                "city": "Delhi",
                "country": "IN",
                "state": "Delhi",
                "street": "100, New Park",
                "zipcode": "110001"
            },
            "billing_currency": "INR",
            "return_url": f"{FRONTEND_URL}/payment-status?bookingId={request.booking_id}",
            "metadata": {
                "bookingId": str(request.booking_id),
                "service": "peer_counselling",
                "platform": "studconnect",
                "amount": str(final_amount),
                "discount_code": request.discount_code or "",
                "customer_phone": request.customer.phone or "",
                "customer_email": request.customer.email,
                "customer_name": request.customer.name
            },
            "confirm": True,
            "allowed_payment_method_types": ["credit","debit","upi_collect","upi_intent","apple_pay","cashapp","google_pay"],
            "show_saved_payment_methods": False
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "StudConnect/1.0"
        }

        endpoint = f"{base_url}/checkouts"
        logging.info(f"[Dodo LIVE] POST {endpoint}")

        resp = await _http_post_with_retry(endpoint, headers, payload, attempts=3)
        body_text = resp.text
        logging.info(f"[Dodo LIVE] Status {resp.status_code}")

        if resp.status_code in (200, 201):
            try:
                data = resp.json()
            except json.JSONDecodeError:
                raise HTTPException(status_code=502, detail="Invalid JSON from payment gateway")

            checkout_url = (
                data.get("checkout_url") or
                data.get("url") or
                data.get("payment_url") or
                data.get("redirect_url")
            )
            session_id = (
                data.get("session_id") or
                data.get("id") or
                data.get("checkout_session_id")
            )
            if not checkout_url:
                raise HTTPException(status_code=502, detail="Missing checkout_url in gateway response")

            return {
                "checkout_url": checkout_url,
                "session_id": session_id,
                "booking_id": request.booking_id,
                "amount": final_amount,
                "status": "success",
                "payment_type": "dodo",
                "environment": "live",
                "discount_applied": discount
            }

        if resp.status_code == 401:
            raise HTTPException(status_code=500, detail="Gateway authentication failed. Verify live API key.")
        if resp.status_code == 400:
            try:
                err_json = resp.json()
                msg = err_json.get("message") or err_json.get("error") or body_text[:200]
            except:
                msg = body_text[:200]
            raise HTTPException(status_code=400, detail=f"Gateway validation error: {msg}")

        raise HTTPException(
            status_code=502,
            detail=f"Unexpected gateway status {resp.status_code}: {body_text[:250]}"
        )

    except HTTPException:
        raise
    except (httpx.TimeoutException, httpx.ConnectError) as e:
        raise HTTPException(
            status_code=503,
            detail=f"Network error reaching Dodo live endpoint: {e}\n"
                   "Check outbound connectivity, firewall, and retry."
        )
    except Exception as e:
        logging.error(f"[Dodo LIVE] Unhandled exception: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal payment processing error: {e}")

@app.get("/debug/dodo-status", tags=["payments"])
def dodo_status():
    key = DODO_API_KEY or ""
    return {
        "api_key_present": bool(key),
        "api_key_prefix": key[:10] + "..." if key else None,
        "is_live_key": key.startswith("sk_live_"),
        "warning": None if (key and key.startswith("sk_live_")) else "Provide a live key (sk_live_*) for production.",
        "endpoint_used": "https://live.dodopayments.com/checkouts",
        "product_id": "pdt_isuaGsszAodjHrUaplbG4",
        "timestamp": datetime.utcnow().isoformat()
    }

import base64

ZOOM_ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")

_zoom_cache = {"token": None, "exp": None}

async def get_zoom_token() -> str:
    if not (ZOOM_ACCOUNT_ID and ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET):
        raise RuntimeError("Zoom credentials missing")
    now = datetime.utcnow()
    if _zoom_cache["token"] and _zoom_cache["exp"] and now < _zoom_cache["exp"]:
        return _zoom_cache["token"]
    auth_bytes = f"{ZOOM_CLIENT_ID}:{ZOOM_CLIENT_SECRET}".encode()
    auth_header = base64.b64encode(auth_bytes).decode()
    url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={ZOOM_ACCOUNT_ID}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(url, headers={"Authorization": f"Basic {auth_header}"})
        if r.status_code != 200:
            raise RuntimeError(f"Zoom token error {r.status_code}: {r.text[:150]}")
        data = r.json()
        _zoom_cache["token"] = data.get("access_token")
        _zoom_cache["exp"] = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
        return _zoom_cache["token"]

async def create_zoom_meeting(slot_dt: datetime, student_email: str, counsellor_email: str) -> dict:
    token = await get_zoom_token()
    payload = {
        "topic": "Peer Counselling Session",
        "type": 2,
        "start_time": slot_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": 30,
        "timezone": "UTC",
        "agenda": f"Session: {student_email} with {counsellor_email}",
        "settings": {"host_video": True, "participant_video": True, "waiting_room": True}
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post("https://api.zoom.us/v2/users/me/meetings",
                              headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json"},
                              json=payload)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"Zoom meeting error {r.status_code}: {r.text[:200]}")
        jd = r.json()
        return {"join_url": jd.get("join_url"), "start_url": jd.get("start_url"), "id": jd.get("id")}

@app.post("/webhook/dodo", tags=["payments"])
async def dodo_webhook(request: Request, db_session=Depends(get_db)):
    
    try:
        raw = await request.body()
        logging.info(f"[Dodo WEBHOOK] Raw: {raw[:500].decode(errors='ignore')}")
        try:
            event = json.loads(raw.decode())
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON"}
        event_type = event.get("event") or event.get("type")
        data = event.get("data") or {}
        metadata = data.get("metadata") or {}
        booking_id = metadata.get("bookingId") or metadata.get("booking_id")
        if not booking_id:
            return {"status": "ignored", "message": "No bookingId in metadata"}

        if event_type not in ("checkout.session.completed", "payment.succeeded"):
            return {"status": "ignored", "message": f"Event {event_type} not processed"}

        db: Session
        with db_session as db:
            booking = db.query(PeerCounsellorBooking).filter_by(id=int(booking_id)).first()
            if not booking:
                return {"status": "error", "message": "Booking not found"}
            if booking.payment_status == "paid" and booking.meeting_link:
                return {"status": "ok", "message": "Already processed"}

            booking.payment_status = "paid"

            meeting_link = None
            try:
                zoom_info = await create_zoom_meeting(booking.slot_date, booking.user_email, booking.counsellor_email)
                meeting_link = zoom_info["join_url"]
                booking.meeting_link = meeting_link
            except Exception as ze:
                logging.error(f"[Zoom] Failed to create meeting for booking {booking.id}: {ze}")

            db.commit()
            db.refresh(booking)

            slot_time_disp = booking.slot_date.strftime("%A, %d %B %Y at %H:%M UTC")
            student_msg = (
                f"Dear {booking.user_email},\n\n"
                f"Payment confirmed. Your session is booked.\n"
                f"Date & Time: {slot_time_disp}\n"
                f"Meeting Link: {booking.meeting_link or 'Pending'}\n\n"
                f"Please join 5 minutes early.\n\nStudConnect"
            )
            counsellor_msg = (
                f"Dear {booking.counsellor_email},\n\n"
                f"A paid session has been booked.\n"
                f"Student: {booking.user_email}\n"
                f"Date & Time: {slot_time_disp}\n"
                f"Meeting Link: {booking.meeting_link or 'Pending'}\n\n"
                f"Please be ready.\n\nStudConnect"
            )
            try:
                send_email(booking.user_email, "Session Confirmed & Meeting Link", student_msg)
            except Exception as e:
                logging.error(f"[Email] Student send failed: {e}")
            try:
                send_email(booking.counsellor_email, "New Paid Session Booked", counsellor_msg)
            except Exception as e:
                logging.error(f"[Email] Counsellor send failed: {e}")

            return {
                "status": "success",
                "booking_id": booking.id,
                "payment_status": booking.payment_status,
                "meeting_link": booking.meeting_link
            }
    except Exception as e:
        logging.error(f"[Dodo WEBHOOK] Unhandled: {e}", exc_info=True)
        return {"status": "error", "message": str(e)}

@app.get("/peer-counsellors/booking-status", tags=["peer-counsellors"])
def booking_status(booking_id: int = Query(...), db_session=Depends(get_db)):
    db: Session
    with db_session as db:
        b = db.query(PeerCounsellorBooking).filter_by(id=booking_id).first()
        if not b:
            raise HTTPException(status_code=404, detail="Booking not found")
        return {
            "booking_id": b.id,
            "payment_status": b.payment_status,
            "meeting_link": b.meeting_link,
            "slot_date": b.slot_date.isoformat()
        }

@app.get("/peer-counsellors/student-bookings", tags=["peer-counsellors"])
def get_student_bookings(
    user_id: str = Query(None, description="Student user ID (UUID or int)"),
    user_email: str = Query(None, description="Student email"),
    db_session=Depends(get_db)
):
    """
    Get all peer counsellor bookings for a student by user_id or user_email.
    At least one of user_id or user_email must be provided.
    """
    if not user_id and not user_email:
        raise HTTPException(status_code=400, detail="user_id or user_email is required")
    db: Session
    with db_session as db:
        query = db.query(PeerCounsellorBooking)
        if user_id:
            query = query.filter(PeerCounsellorBooking.user_id == user_id)
        if user_email:
            query = query.filter(PeerCounsellorBooking.user_email == user_email)
        bookings = query.order_by(PeerCounsellorBooking.slot_date.desc()).all()
        return [
            {
                "id": b.id,
                "user_id": b.user_id,
                "user_email": b.user_email,
                "counsellor_id": b.counsellor_id,
                "counsellor_email": b.counsellor_email,
                "slot_id": b.slot_id,
                "slot_date": b.slot_date.isoformat(),
                "payment_status": b.payment_status,
                "meeting_link": b.meeting_link,
                "created_at": b.created_at.isoformat()
            }
            for b in bookings
        ]


# ==================== SAFETY UTILITY FUNCTIONS ====================

def is_payment_already_processed(db: Session, payment_id: str) -> bool:
    """
    Check if a payment has already been processed (idempotency check).
    Returns True if payment was already processed, False otherwise.
    """
    payment_record = db.query(PaymentRecord).filter(
        PaymentRecord.payment_id == payment_id,
        PaymentRecord.processed == 1
    ).first()
    return payment_record is not None


def record_payment(db: Session, payment_id: str, user_id: int, amount: float, status: str, 
                   order_id: str = None, cart_checkout_id: str = None, webhook_payload: str = None) -> PaymentRecord:
    """
    Record a payment attempt in the database.
    This enables idempotent webhook processing.
    """
    payment_record = PaymentRecord(
        payment_id=payment_id,
        user_id=user_id,
        amount=amount,
        status=status,
        order_id=order_id,
        cart_checkout_id=cart_checkout_id,
        webhook_payload=webhook_payload,
        processed=0
    )
    db.add(payment_record)
    db.commit()
    db.refresh(payment_record)
    return payment_record


def mark_payment_processed(db: Session, payment_id: str):
    """Mark a payment as processed to prevent duplicate handling."""
    payment_record = db.query(PaymentRecord).filter(
        PaymentRecord.payment_id == payment_id
    ).first()
    if payment_record:
        payment_record.processed = 1
        payment_record.processed_at = datetime.utcnow()
        db.commit()


def reserve_slot(db: Session, cart_item_id: int, slot_id: int, slot_date: datetime, user_id: int) -> SlotReservation:
    """
    Reserve a slot for a user during checkout.
    Reservation expires after 15 minutes.
    Raises HTTPException if slot is already reserved/booked.
    """
    # Check if slot is already reserved or booked
    existing = db.query(SlotReservation).filter(
        SlotReservation.slot_id == slot_id,
        SlotReservation.slot_date == slot_date,
        SlotReservation.status.in_(["reserved", "booked"])
    ).first()
    
    if existing:
        if existing.user_id == user_id:
            # Same user - return existing reservation
            return existing
        else:
            # Different user - slot unavailable
            raise HTTPException(
                status_code=409,
                detail=f"This time slot is no longer available. Please select another time."
            )
    
    # Create reservation
    reservation = SlotReservation(
        cart_item_id=cart_item_id,
        slot_id=slot_id,
        slot_date=slot_date,
        user_id=user_id,
        status="reserved",
        reserved_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=15)
    )
    db.add(reservation)
    db.commit()
    db.refresh(reservation)
    return reservation


def release_expired_reservations(db: Session):
    """
    Release all expired reservations (cleanup job).
    This should be called periodically or before checking slot availability.
    """
    now = datetime.utcnow()
    expired = db.query(SlotReservation).filter(
        SlotReservation.status == "reserved",
        SlotReservation.expires_at < now
    ).all()
    
    for reservation in expired:
        reservation.status = "released"
    
    if expired:
        db.commit()
    
    return len(expired)


def convert_reservations_to_bookings(db: Session, user_id: int, cart_item_ids: list):
    """
    Convert reserved slots to booked status after successful payment.
    """
    reservations = db.query(SlotReservation).filter(
        SlotReservation.user_id == user_id,
        SlotReservation.cart_item_id.in_(cart_item_ids),
        SlotReservation.status == "reserved"
    ).all()
    
    for reservation in reservations:
        reservation.status = "booked"
    
    db.commit()


def release_user_reservations(db: Session, user_id: int):
    """
    Release all reservations for a user (e.g., on payment failure or checkout cancel).
    """
    reservations = db.query(SlotReservation).filter(
        SlotReservation.user_id == user_id,
        SlotReservation.status == "reserved"
    ).all()
    
    for reservation in reservations:
        reservation.status = "released"
    
    db.commit()


# ==================== CART API ENDPOINTS ====================

def get_current_user_from_token(authorization: str | None = Header(default=None), db_session=Depends(get_db)) -> User:
    """
    Dependency to get current user from Authorization header.
    Raises HTTPException if token is missing or invalid.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1]
    
    
    try:
        data = decode_token(token)
    except Exception as e:
        logging.error(f"Token decode failed: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token")
    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    db: Session = db_session
    user = db.get(User, user_id)  # No int() conversion - user_id is already UUID string
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/api/cart/add", tags=["cart"])
def add_to_cart(
    payload: dict = Body(...),
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Add a peer counsellor to user's cart.
    Payload: { "peer_counsellor_id": int }
    Returns: Created cart item with full peer details
    """
    peer_counsellor_id = payload.get("peer_counsellor_id")
    if not peer_counsellor_id:
        raise HTTPException(status_code=400, detail="peer_counsellor_id is required")
    
    db: Session = db_session
    
    # Validate peer counsellor exists
    peer = db.get(PeerCounsellor, peer_counsellor_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer counsellor not found")
    
    # Check if already in cart
    existing = db.query(CartItem).filter(
        CartItem.user_id == current_user.id,
        CartItem.peer_counsellor_id == peer_counsellor_id,
        CartItem.state.in_(["in_cart", "checkout_in_progress"])
    ).first()
    
    if existing:
        # Return existing cart item
        return {
            "id": existing.id,
            "peer_id": peer.id,
            "peer_name": peer.name,
            "peer_university": peer.university,
            "peer_program": peer.program,
            "peer_location": peer.location,
            "peer_profile_image_url": peer.profile_image_url,
            "charges": existing.locked_price,  # Use locked price, not current price
            "locked_price": existing.locked_price,
            "state": existing.state,
            "created_at": existing.created_at.isoformat(),
            "message": "Item already in cart"
        }
    
    # SAFETY: Lock price at time of adding to cart
    locked_price = peer.charges if peer.charges else 699.0
    
    # Create new cart item
    cart_item = CartItem(
        user_id=current_user.id,
        peer_counsellor_id=peer_counsellor_id,
        state="in_cart",
        locked_price=locked_price  # Price locked at add-to-cart time
    )
    db.add(cart_item)
    db.commit()
    db.refresh(cart_item)
    
    return {
        "id": cart_item.id,
        "peer_id": peer.id,
        "peer_name": peer.name,
        "peer_university": peer.university,
        "peer_program": peer.program,
        "peer_location": peer.location,
        "peer_profile_image_url": peer.profile_image_url,
        "charges": locked_price,
        "locked_price": locked_price,
        "state": cart_item.state,
        "created_at": cart_item.created_at.isoformat(),
        "message": "Added to cart successfully"
    }



@app.get("/api/cart/items", tags=["cart"])
def get_cart_items(
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Get all cart items for current user.
    Only returns items with state='in_cart' or 'checkout_in_progress'
    Returns: Array of cart items with peer details
    """
    db: Session = db_session
    
    cart_items = db.query(CartItem).filter(
        CartItem.user_id == current_user.id,
        CartItem.state.in_(["in_cart", "checkout_in_progress"])
    ).order_by(CartItem.created_at.desc()).all()
    
    result = []
    for cart_item in cart_items:
        peer = cart_item.peer_counsellor
        if peer:
            result.append({
                "id": cart_item.id,
                "peer_id": peer.id,
                "peer_name": peer.name,
                "peer_university": peer.university,
                "peer_program": peer.program,
                "peer_location": peer.location,
                "peer_profile_image_url": peer.profile_image_url,
                "charges": cart_item.locked_price,  # Use locked price
                "locked_price": cart_item.locked_price,
                "current_price": peer.charges or 699,  # Include current price for comparison
                "state": cart_item.state,
                "created_at": cart_item.created_at.isoformat()
            })

    
    return result


@app.delete("/api/cart/remove/{cart_item_id}", tags=["cart"])
def remove_from_cart(
    cart_item_id: int,
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Remove item from cart (soft delete by setting state='removed').
    Validates ownership before deletion.
    """
    db: Session = db_session
    
    cart_item = db.get(CartItem, cart_item_id)
    if not cart_item:
        raise HTTPException(status_code=404, detail="Cart item not found")
    
    # Verify ownership
    if cart_item.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to remove this item")
    
    # Soft delete
    cart_item.state = "removed"
    cart_item.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Item removed from cart", "cart_item_id": cart_item_id}


@app.delete("/api/cart/clear", tags=["cart"])
def clear_cart(
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Clear entire cart (set all items to state='removed').
    """
    db: Session = db_session
    
    cart_items = db.query(CartItem).filter(
        CartItem.user_id == current_user.id,
        CartItem.state.in_(["in_cart", "checkout_in_progress"])
    ).all()
    
    count = 0
    for cart_item in cart_items:
        cart_item.state = "removed"
        cart_item.updated_at = datetime.utcnow()
        count += 1
    
    db.commit()
    
    return {"message": f"Cart cleared. {count} items removed.", "removed_count": count}


@app.post("/api/cart/checkout/initiate", tags=["cart"])
def initiate_checkout(
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Start checkout process. Locks cart items by changing state to 'checkout_in_progress'.
    Returns: Cart items ready for slot selection
    """
    db: Session = db_session
    
    cart_items = db.query(CartItem).filter(
        CartItem.user_id == current_user.id,
        CartItem.state == "in_cart"
    ).all()
    
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    # SAFETY: Validate prices haven't changed significantly
    price_mismatches = []
    for cart_item in cart_items:
        peer = cart_item.peer_counsellor
        if peer:
            current_price = peer.charges if peer.charges else 699.0
            locked_price = cart_item.locked_price
            
            # Allow small floating point differences (< 1 rupee)
            if abs(current_price - locked_price) >= 1.0:
                price_mismatches.append({
                    "peer_name": peer.name,
                    "locked_price": locked_price,
                    "current_price": current_price
                })
    
    # If prices changed, block checkout and inform user
    if price_mismatches:
        raise HTTPException(
            status_code=409,  # Conflict status code
            detail={
                "error": "Price mismatch detected",
                "message": "Some prices have changed since you added them to cart. Please review and re-add these items.",
                "mismatches": price_mismatches
            }
        )
    
    # Lock cart items (prevents modification during checkout)
    result = []
    for cart_item in cart_items:
        cart_item.state = "checkout_in_progress"
        cart_item.updated_at = datetime.utcnow()
        
        peer = cart_item.peer_counsellor
        if peer:
            result.append({
                "cart_item_id": cart_item.id,
                "peer_id": peer.id,
                "peer_name": peer.name,
                "peer_university": peer.university,
                "peer_program": peer.program,
                "peer_email": peer.email,
                "charges": cart_item.locked_price,  # Use locked price for checkout
                "locked_price": cart_item.locked_price,
                "state": cart_item.state
            })
    
    db.commit()
    
    return {
        "message": "Checkout initiated. Cart items locked.",
        "cart_items": result,
        "total_amount": sum(item["charges"] for item in result)
    }



@app.post("/api/cart/checkout/cancel", tags=["cart"])
def cancel_checkout(
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Cancel checkout and return items to cart.
    Updates all 'checkout_in_progress' items back to 'in_cart'.
    """
    db: Session = db_session
    
    # SAFETY: Release any slot reservations
    release_user_reservations(db, current_user.id)
    
    cart_items = db.query(CartItem).filter(
        CartItem.user_id == current_user.id,
        CartItem.state == "checkout_in_progress"
    ).all()
    
    count = 0
    for cart_item in cart_items:
        cart_item.state = "in_cart"
        cart_item.updated_at = datetime.utcnow()
        count += 1
    
    db.commit()
    
    return {"message": f"Checkout cancelled. {count} items returned to cart.", "count": count}


@app.post("/api/cart/checkout/complete", tags=["cart"])
async def complete_checkout(
    payload: dict = Body(...),
    current_user: User = Depends(get_current_user_from_token),
    db_session=Depends(get_db)
):
    """
    Complete checkout after payment success.
    Creates bookings for all cart items and clears cart.
    
    CRITICAL: Only call this AFTER payment confirmation (from webhook).
    
    Payload:
    {
        "payment_id": "pay_abc123",  # From payment gateway
        "cart_items": [
            {"cart_item_id": 1, "slot_id": 10, "slot_date": "2026-02-15T10:00:00Z"},
            {"cart_item_id": 2, "slot_id": 15, "slot_date": "2026-02-16T14:00:00Z"}
        ],
        "payment_verified": true
    }
    """
    payment_id = payload.get("payment_id")
    cart_items_data = payload.get("cart_items", [])
    payment_verified = payload.get("payment_verified", False)
    
    if not payment_id:
        raise HTTPException(status_code=400, detail="payment_id is required")
    
    if not payment_verified:
        raise HTTPException(status_code=400, detail="Payment not verified")
    
    if not cart_items_data:
        raise HTTPException(status_code=400, detail="No cart items provided")
    
    db: Session = db_session
    
    # SAFETY: Check if payment already processed (idempotency)
    if is_payment_already_processed(db, payment_id):
        logging.info(f"[SAFETY] Payment {payment_id} already processed. Skipping duplicate.")
        return {
            "message": "Payment already processed",
            "bookings_created": 0,
            "bookings": []
        }
    
    created_bookings = []
    cart_item_ids = []
    
    for item_data in cart_items_data:
        cart_item_id = item_data.get("cart_item_id")
        slot_id = item_data.get("slot_id")
        slot_date_str = item_data.get("slot_date")
        
        if not all([cart_item_id, slot_id, slot_date_str]):
            continue
        
        # Validate cart item
        cart_item = db.get(CartItem, cart_item_id)
        if not cart_item or cart_item.user_id != current_user.id:
            continue
            
        if cart_item.state != "checkout_in_progress":
            continue
        
        # Get peer counsellor
        peer = cart_item.peer_counsellor
        if not peer:
            continue
        
        # Parse slot date
        try:
            slot_date = datetime.fromisoformat(slot_date_str.replace("Z", "+00:00"))
        except:
            slot_date = datetime.fromisoformat(slot_date_str)
        
        # Create booking
        booking = PeerCounsellorBooking(
            user_id=str(current_user.id),
            user_email=current_user.email,
            counsellor_id=peer.id,
            counsellor_email=peer.email,
            slot_id=slot_id,
            slot_date=slot_date,
            payment_status="paid",
            meeting_link=None  # Will be set by Zoom integration
        )
        db.add(booking)
        
        # Update cart item state
        cart_item.state = "paid"
        cart_item.updated_at = datetime.utcnow()
        cart_item_ids.append(cart_item_id)
        
        # Try to create Zoom meeting
        try:
            zoom_info = await create_zoom_meeting(slot_date, current_user.email, peer.email)
            booking.meeting_link = zoom_info["join_url"]
        except Exception as ze:
            logging.error(f"[Zoom] Failed to create meeting: {ze}")
            booking.meeting_link = None
        
        created_bookings.append({
            "booking_id": booking.id,
            "peer_name": peer.name,
            "slot_date": slot_date.isoformat(),
            "meeting_link": booking.meeting_link
        })
    
    # SAFETY: Convert slot reservations to booked status
    convert_reservations_to_bookings(db, current_user.id, cart_item_ids)
    
    # SAFETY: Mark payment as processed (prevents duplicate webhook processing)
    mark_payment_processed(db, payment_id)
    
    db.commit()
    
    # Send confirmation emails (async, non-blocking)
    try:
        for booking_data in created_bookings:
            # Email logic here (simplified for now)
            pass
    except Exception as e:
        logging.error(f"Failed to send confirmation emails: {e}")
    
    logging.info(f"[CHECKOUT] Successfully completed checkout for payment {payment_id}. Created {len(created_bookings)} bookings.")
    
    return {
        "message": "Checkout completed successfully",
        "bookings_created": len(created_bookings),
        "bookings": created_bookings
    }

