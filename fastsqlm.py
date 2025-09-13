import os
import re
import logging
from contextlib import contextmanager
from typing import List, Any, Dict, Optional
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator
import pymssql

# --- SCRIPT VERSION 5.0: FINAL VERSION WITH ALL FIXES ---
print("--- SCRIPT VERSION 5.0: FINAL VERSION WITH ALL FIXES ---")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mssql_fastmcp_server")


def validate_table_name(table_name: str) -> str:
    """Validate and escape table name to prevent SQL injection."""
    if not table_name:
        raise ValueError("Table name cannot be empty")
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$', table_name):
        raise ValueError(f"Invalid table name format: {table_name}")
    parts = table_name.split('.')
    return f"[{parts[0]}].[{parts[1]}]" if len(parts) == 2 else f"[{table_name}]"


def sanitize_sql_query(query: str) -> str:
    """Basic SQL query sanitization for full queries."""
    query = query.strip()
    if not query:
        raise ValueError("Query cannot be empty")
    dangerous_patterns = [
        r';\s*(drop|delete|truncate|alter|create)\s+', r'--', r'/\*.*?\*/',
        r'xp_cmdshell', r'sp_executesql'
    ]
    query_lower = query.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, query_lower, re.IGNORECASE | re.DOTALL):
            raise ValueError(f"Query contains potentially dangerous pattern: {pattern}")
    return query


class DBConfig(BaseModel):
    server: str
    user: Optional[str] = None
    password: Optional[str] = None
    database: str
    port: int = Field(default=1433, ge=1, le=65535)
    tds_version: Optional[str] = None
    timeout: int = Field(default=30, ge=1)
    charset: str = Field(default="utf8")


def get_db_config() -> DBConfig:
    """Get database configuration from environment variables."""
    server = os.getenv("MSSQL_SERVER")
    if not server: raise ValueError("MSSQL_SERVER environment variable is required")
    database = os.getenv("MSSQL_DATABASE")
    if not database: raise ValueError("MSSQL_DATABASE environment variable is required")
    db_conf = {
        "server": server, "database": database,
        "port": int(os.getenv("MSSQL_PORT", "1433")),
        "timeout": int(os.getenv("MSSQL_TIMEOUT", "30")),
        "charset": os.getenv("MSSQL_CHARSET", "utf8")
    }
    if not (os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"):
        user = os.getenv("MSSQL_USER")
        password = os.getenv("MSSQL_PASSWORD")
        if not user or not password:
            raise ValueError("MSSQL_USER and MSSQL_PASSWORD are required when not using Windows Authentication")
        db_conf["user"] = user
        db_conf["password"] = password
    if ".database.windows.net" in server or os.getenv("MSSQL_ENCRYPT", "false").lower() == "true":
        db_conf["tds_version"] = "7.4"
    return DBConfig(**db_conf)


@contextmanager
def get_db_connection(config: DBConfig = None):
    """Context manager for database connections with proper cleanup."""
    if config is None: config = get_db_config()
    conn = None
    try:
        conn_kwargs = config.model_dump(exclude_none=True)
        conn = pymssql.connect(**conn_kwargs)
        yield conn
    except pymssql.Error as e:
        logger.error(f"Database connection error: {e}")
        raise ToolError(f"Database connection failed: {e}")
    finally:
        if conn: conn.close()


# Initialize FastMCP server
mcp = FastMCP("mssql_fastmcp_server")


class QueryInput(BaseModel):
    query: str = Field(..., description="SQL query to execute")
    limit: Optional[int] = Field(default=100, ge=1, le=10000)
    passcode: str


    @model_validator(mode='before')
    @classmethod
    def normalize_input(cls, data: Any) -> Any:
        """A robust validator that accepts multiple input formats."""
        if isinstance(data, str):
            return {'query': data}
        if isinstance(data, dict) and 'input' in data and 'query' not in data:
            data['query'] = data.pop('input')
        return data


@mcp.tool()
def execute_query(ctx: Context, input: Any) -> Dict[str, Any]:
    """Tool to execute a read-only SELECT query safely, only with passcode."""
    try:
        # Validate input via Pydantic
        validated_input = QueryInput.model_validate(input)

        # Check the passcode
        if validated_input.passcode != "devi22":
            raise ToolError("Invalid passcode.")

        query = sanitize_sql_query(validated_input.query)

        if not query.upper().strip().startswith('SELECT'):
            raise ToolError("Only SELECT queries are allowed")

        with get_db_connection() as conn:
            cursor = conn.cursor(as_dict=True)
            # Add TOP or LIMIT if not present
            if 'TOP' not in query.upper() and 'LIMIT' not in query.upper():
                query = re.sub(r'^\s*SELECT\s+', f'SELECT TOP {validated_input.limit} ', query, flags=re.IGNORECASE)

            logger.info(f"Executing query: {query}")
            cursor.execute(query)
            data = [
                {k: str(v) if v is not None else None for k, v in row.items()}
                for row in cursor.fetchall()
            ]
            columns = list(data[0].keys()) if data else []
            return {
                "status": "success",
                "columns": columns,
                "row_count": len(data),
                "data": data,
                "query_executed": query
            }

    except ValueError as ve:
        raise ToolError(str(ve))
    except ToolError:
        raise  # re-raise passcode or SELECT restrictions
    except Exception as e:
        logger.error(f"Error executing query: {e}", exc_info=True)
        raise ToolError(f"Query execution failed: {e}")


@mcp.tool()
def test_connection(ctx: Context) -> Dict[str, Any]:
    """Tool to test database connectivity and configuration."""
    try:
        config = get_db_config()
        with get_db_connection(config) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 [test_value], GETDATE() [current_time]")
            result = cursor.fetchone()
            return {
                "status": "success", "message": "Database connection successful",
                "test_value": result[0], "server_time": str(result[1]),
                "config": {"server": config.server, "database": config.database, "port": config.port}
            }
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        return {"status": "failed", "message": f"Database connection failed: {e}"}


if __name__ == "__main__":
    try:
        logger.info("Starting MSSQL FastMCP Server...")
        config = get_db_config()
        logger.info(f"Configuration loaded for {config.server}/{config.database}")
        mcp.run(transport="http",host="0.0.0.0",port=8000)
    except Exception as e:
        logger.error(f"FATAL: Failed to start server: {e}")
        exit(1)
