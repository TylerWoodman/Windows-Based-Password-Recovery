import sqlite3
from datetime import datetime

def initalize_database(database_name="forensic_audit.db"):
    con = sqlite3.connect(database_name)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS Audit_Logs(
                id integer primary key,
                case_reference TEXT,
                investigator TEXT,
                timestamp TEXT,
                event TEXT
                )''')
    con.commit()
    con.close()

def log_event(case_id, investigator, event, database_name="forensic_audit.db"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(database_name)
    cur = con.cursor()
    cur.execute("INSERT INTO Audit_Logs(case_reference , investigator , timestamp , event) " \
        "VALUES (?, ?, ?, ?)",
        (case_id , investigator , timestamp , event))
    con.commit()
    con.close()
    return timestamp