import pyodbc
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from contextlib import asynccontextmanager
import logging
from typing import Literal, Dict

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)

# --- FastAPI App ---
app = FastAPI(
    title="SQL MCP Tool",
    description="MCP-compliant tool to query SQL Server metadata.",
    version="1.0.0"
)

# --- Database Config ---
DB_CONFIG = {
    'server': os.getenv("MSSQL_SERVER", ""),
    'database': os.getenv("MSSQL_DATABASE", ""),
    'username': os.getenv("MSSQL_USER", ""),
    'password': os.getenv("MSSQL_PASSWORD", ""),
    'driver': os.getenv("MSSQL_DRIVER", '{ODBC Driver 17 for SQL Server}'),
}

# --- Schema Cache ---
db_schema_cache = {
    "tables": {},
    "columns": {},
    "objects": {},
    "jobs": {},
}

def get_db_connection():
    conn_str = (
        f"DRIVER={DB_CONFIG['driver']};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']}"
    )
    try:
        return pyodbc.connect(conn_str)
    except Exception as e:
        logging.error(f"DB connection failed: {e}")
        return None

def load_schema_cache():
    conn = get_db_connection()
    if not conn:
        logging.error("Cannot connect to DB to build schema cache.")
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
        tables = [row.TABLE_NAME for row in cursor.fetchall()]
        db_schema_cache["tables"] = {t.lower(): t for t in tables}

        for table in tables:
            cursor.execute("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?", table)
            columns = [row.COLUMN_NAME for row in cursor.fetchall()]
            db_schema_cache["columns"][table.lower()] = {c.lower(): c for c in columns}

        cursor.execute("SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS")
        db_schema_cache["objects"] = {row.ROUTINE_NAME.lower(): row.ROUTINE_NAME for row in cursor.fetchall()}

        cursor.execute("SELECT name FROM msdb.dbo.sysjobs")
        db_schema_cache["jobs"] = {row.name.lower(): row.name for row in cursor.fetchall()}

        logging.info("Schema cache loaded.")
    finally:
        conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_schema_cache()
    yield

app.router.lifespan_context = lifespan

# --- Tool Input Schema ---
class ToolInput(BaseModel):
    tool: Literal[
        "get_column_data",
        "get_column_population_logic",
        "get_table_schema",
        "get_object_definition",
        "get_job_status"
    ]
    parameters: Dict

# --- Tool Handlers ---
def handle_get_column_data(params: dict):
    table = params.get("table")
    select_col = params.get("select_col")
    where_col = params.get("where_col")
    value = params.get("value")

    if not all([table, select_col, where_col, value]):
        raise HTTPException(status_code=400, detail="Missing required parameters.")

    table_name = db_schema_cache["tables"].get(table.lower())
    if not table_name:
        raise HTTPException(status_code=404, detail=f"Table '{table}' not found.")

    select_col_real = db_schema_cache["columns"].get(table.lower(), {}).get(select_col.lower())
    where_col_real = db_schema_cache["columns"].get(table.lower(), {}).get(where_col.lower())
    if not all([select_col_real, where_col_real]):
        raise HTTPException(status_code=404, detail="Column(s) not found.")

    query = f"SELECT TOP 20 {select_col_real} FROM {table_name} WHERE {where_col_real} = ?"
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed.")

    try:
        cursor = conn.cursor()
        try:
            cursor.execute(query, int(value))
        except ValueError:
            cursor.execute(query, value)
        rows = cursor.fetchall()
        return {"results": [row[0] for row in rows]}
    finally:
        conn.close()

def handle_get_table_schema(params: dict):
    table = params.get("table")
    table_name = db_schema_cache["tables"].get(table.lower())
    if not table_name:
        raise HTTPException(status_code=404, detail="Table not found.")

    query = "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?"
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute(query, table_name)
        rows = cursor.fetchall()
        return [dict(zip([c[0] for c in cursor.description], row)) for row in rows]
    finally:
        conn.close()

def handle_get_column_population_logic(params: dict):
    column = params.get("column")
    if not column:
        raise HTTPException(status_code=400, detail="Missing column name.")

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed.")

    try:
        cursor = conn.cursor()
        query = "SELECT ROUTINE_NAME, ROUTINE_DEFINITION FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE'"
        cursor.execute(query)
        procedures = cursor.fetchall()
        matches = []

        for proc in procedures:
            if proc.ROUTINE_DEFINITION and column.lower() in proc.ROUTINE_DEFINITION.lower():
                if "insert into" in proc.ROUTINE_DEFINITION.lower() or "update" in proc.ROUTINE_DEFINITION.lower():
                    matches.append(proc.ROUTINE_NAME)

        return {"column": column, "procedures": matches}
    finally:
        conn.close()

def handle_get_object_definition(params: dict):
    object_name = params.get("object")
    real_object = db_schema_cache["objects"].get(object_name.lower())
    if not real_object:
        raise HTTPException(status_code=404, detail="Object not found.")

    query = "SELECT OBJECT_DEFINITION(OBJECT_ID(?)) AS definition"
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute(query, real_object)
        row = cursor.fetchone()
        if row and row.definition:
            return {"object": real_object, "definition": row.definition}
        else:
            raise HTTPException(status_code=404, detail="No definition found.")
    finally:
        conn.close()

def handle_get_job_status(params: dict):
    job_name = params.get("job")
    real_job = db_schema_cache["jobs"].get(job_name.lower())
    if not real_job:
        raise HTTPException(status_code=404, detail="Job not found.")

    query = """
    SELECT TOP 1 j.name, h.run_date, h.run_time,
        CASE h.run_status
            WHEN 0 THEN 'Failed' WHEN 1 THEN 'Succeeded'
            WHEN 2 THEN 'Retry' WHEN 3 THEN 'Canceled'
            ELSE 'Running'
        END AS status
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    WHERE j.name = ? AND h.step_id = 0
    ORDER BY h.run_date DESC, h.run_time DESC
    """

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed.")

    try:
        cursor = conn.cursor()
        cursor.execute(query, real_job)
        row = cursor.fetchone()
        if row:
            return {
                "job": row.name,
                "status": row.status,
                "last_run_date": row.run_date,
                "last_run_time": row.run_time
            }
        else:
            raise HTTPException(status_code=404, detail="No run history found.")
    finally:
        conn.close()

# --- MCP Tool Execution Endpoint ---
@app.post("/v1/tool-use")
def tool_use(input: ToolInput):
    tool = input.tool
    params = input.parameters

    if tool == "get_column_data":
        return handle_get_column_data(params)
    elif tool == "get_column_population_logic":
        return handle_get_column_population_logic(params)
    elif tool == "get_table_schema":
        return handle_get_table_schema(params)
    elif tool == "get_object_definition":
        return handle_get_object_definition(params)
    elif tool == "get_job_status":
        return handle_get_job_status(params)
    else:
        raise HTTPException(status_code=400, detail="Unknown tool.")

# --- MCP Metadata Endpoint ---
@app.get("/v1/metadata")
def metadata():
    return {
        "name": "sql_mcp_tool",
        "description": "Tool for querying SQL Server metadata using structured parameters.",
        "tools": [
            {
                "tool": "get_column_data",
                "description": "Fetch data from a specific column with a WHERE condition.",
                "parameters": {
                    "table": "Name of the table",
                    "select_col": "Column to select",
                    "where_col": "Column to filter on",
                    "value": "Value for the filter"
                }
            },
            {
                "tool": "get_column_population_logic",
                "description": "Retrieve procedures that populate a specific column.",
                "parameters": {
                    "column": "Name of the column"
                }
            },
            {
                "tool": "get_table_schema",
                "description": "Get schema of a specified table.",
                "parameters": {
                    "table": "Name of the table"
                }
            },
            {
                "tool": "get_object_definition",
                "description": "Get definition of a database object (procedure/view).",
                "parameters": {
                    "object": "Name of the object"
                }
            },
            {
                "tool": "get_job_status",
                "description": "Get the last run status of a SQL Agent job.",
                "parameters": {
                    "job": "Name of the job"
                }
            }
        ]
    }
