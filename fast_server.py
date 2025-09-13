import os
import re
import logging
import pymssql
from typing import List, Any
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mssql_fastmcp_server")


def validate_table_name(table_name: str) -> str:
    """Validate and escape table name to prevent SQL injection."""
    if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$', table_name):
        raise ValueError(f"Invalid table name: {table_name}")
    parts = table_name.split('.')
    if len(parts) == 2:
        return f"[{parts[0]}].[{parts[1]}]"
    else:
        return f"[{table_name}]"


class DBConfig(BaseModel):
    server: str
    user: str | None
    password: str | None
    database: str
    port: int = 1433
    tds_version: str | None = None
    # additional settings if required


def get_db_config() -> DBConfig:
    server = os.getenv("MSSQL_SERVER", "localhost")
    logger.info(f"MSSQL_SERVER: {server}")

    if server.startswith("(localdb)\\"):
        instance_name = server.replace("(localdb)\\", "")
        server = f".\\{instance_name}"
        logger.info(f"Detected LocalDB, converted server to: {server}")

    db_conf = {
        "server": server,
        "user": os.getenv("MSSQL_USER"),
        "password": os.getenv("MSSQL_PASSWORD"),
        "database": os.getenv("MSSQL_DATABASE"),
        "port": int(os.getenv("MSSQL_PORT", "1433")),
    }

    # Azure / encryption settings
    if ".database.windows.net" in server or os.getenv("MSSQL_ENCRYPT", "false").lower() == "true":
        db_conf["tds_version"] = "7.4"

    use_windows_auth = os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"
    if use_windows_auth:
        # drop user / password
        db_conf["user"] = None
        db_conf["password"] = None
        logger.info("Using Windows Authentication")
    else:
        if not (db_conf["user"] and db_conf["password"] and db_conf["database"]):
            logger.error("Missing MSSQL_USER, MSSQL_PASSWORD or MSSQL_DATABASE")
            raise ValueError("Database configuration incomplete")

    return DBConfig(**db_conf)


def make_connection(config: DBConfig):
    # Build kwargs for pymssql
    conn_kwargs: dict[str, Any] = {
        "server": config.server,
        "database": config.database,
        "port": config.port
    }
    if config.user:
        conn_kwargs["user"] = config.user
    if config.password:
        conn_kwargs["password"] = config.password
    if config.tds_version:
        conn_kwargs["tds_version"] = config.tds_version
    conn = pymssql.connect(**conn_kwargs)
    return conn


mcp = FastMCP("mssql_fastmcp_server")


@mcp.resource("tables://")
def list_tables_resource() -> List[str]:
    """Resource exposing list of table names."""
    cfg = get_db_config()
    conn = make_connection(cfg)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_TYPE = 'BASE TABLE'
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [r[0] for r in rows]


@mcp.resource("table://{table}/data")
def read_table(table: str) -> List[List[Any]]:
    """Resource exposing data from a given table, top 100 rows."""
    cfg = get_db_config()
    try:
        safe_table = validate_table_name(table)
    except ValueError as ve:
        raise ToolError(str(ve))
    conn = make_connection(cfg)
    cursor = conn.cursor()
    sql = f"SELECT TOP 100 * FROM {safe_table}"
    cursor.execute(sql)
    cols = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    # Return as list: first row columns, then data rows
    result: List[List[Any]] = []
    result.append(cols)
    for row in rows:
        # converting each field to str or as needed
        result.append([str(item) for item in row])
    return result


class QueryInput(BaseModel):
    query: str


@mcp.tool()
def execute_sql_tool(ctx: Context, input: QueryInput) -> Any:
    """Tool to execute an SQL query."""
    cfg = get_db_config()
    query = input.query.strip()
    # Basic protections: e.g. disallow dangerous statements
    # Could expand this logic
    if not query:
        raise ToolError("Query is required")
    # Example restriction: only allow SELECT or DML (INSERT/UPDATE/DELETE)
    # You might also check no DROP, etc.
    upper = query.upper()
    # Disallow multiple statements?
    # Could parse better, but simple check:
    if ";" in query and query.count(";") > 1:
        raise ToolError("Multiple statements not allowed")

    try:
        conn = make_connection(cfg)
        cursor = conn.cursor()
        cursor.execute(query)
        if upper.startswith("SELECT"):
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            # Format results: list of dicts or list of rows
            # Here return list of dicts
            result = [dict(zip(cols, row)) for row in rows]
            return result
        else:
            conn.commit()
            affected = cursor.rowcount
            cursor.close()
            conn.close()
            return {"status": "success", "rows_affected": affected}
    except Exception as e:
        logger.error(f"Error executing SQL: {e}", exc_info=True)
        # If it’s an expected error, wrap in ToolError
        raise ToolError(f"Error executing query: {e}")


if __name__ == "__main__":
    mcp.run()  # uses default transport (stdio) etc.
