import database
import sqlite3

def test_initalize_database_and_log_event(tmp_path):
    test_database = tmp_path / "test_audit.db"
    test_database_path = str(test_database)
    database.initalize_database(database_name=test_database_path)

    database.log_event(
        case_id="TEST-CASE-001",
        investigator="Test Investigator",
        event="Extracted test hash",
        database_name=test_database_path
    )

    con = sqlite3.connect(test_database_path)
    cur = con.cursor()
    cur.execute("SELECT case_reference, investigator, event FROM Audit_Logs")
    rows = cur.fetchall()
    con.close()

    assert len(rows) == 1
    assert rows[0][0] == "TEST-CASE-001"
    assert rows [0][1] == "Test Investigator"
    assert rows [0][2] == "Extracted test hash"