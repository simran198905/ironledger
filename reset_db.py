#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from backend.database import SupabaseDatabase

print("================================================================")
print(" ⚠️  WARNING: Supabase Database Purge")
print(" This action will permanently truncate all records from:")
print("   - ics_events")
print("   - blockchain_blocks")
print("   - forensic_cases")
print("================================================================")

confirm = input("Type YES to confirm database reset: ").strip()
if confirm != "YES":
    print("Action cancelled. Database was not modified.")
    sys.exit(0)

db = SupabaseDatabase()
if db.enabled:
    db.clear_all_tables()
    print("✅ All events, blocks, and forensic cases successfully purged.")
else:
    print("ℹ️  Supabase is not configured or offline. No database to reset.")
