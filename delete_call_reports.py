from app import db, CallReport

# Delete all call reports
db.session.query(CallReport).delete()
db.session.commit()

print("All call report data deleted.")
