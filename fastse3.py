import os
import re
import logging
from contextlib import contextmanager
from typing import List, Any, Dict, Optional
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator
import pymssql

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
    
    # Allow schema.table format
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$', table_name):
        raise ValueError(f"Invalid table name format: {table_name}")
    
    parts = table_name.split('.')
    if len(parts) == 2:
        return f"[{parts[0]}].[{parts[1]}]"
    else:
        return f"[{table_name}]"


def sanitize_sql_query(query: str) -> str:
    """Basic SQL query sanitization."""
    query = query.strip()
    if not query:
        raise ValueError("Query cannot be empty")
    
    # Remove potential SQL injection patterns
    dangerous_patterns = [
        r';\s*(drop|delete|truncate|alter|create)\s+',
        r'--',
        r'/\*.*?\*/',
        r'xp_cmdshell',
        r'sp_executesql'
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
    if not server:
        raise ValueError("MSSQL_SERVER environment variable is required")
    
    logger.info(f"MSSQL_SERVER: {server}")

    # Handle LocalDB instances
    if server.startswith("(localdb)\\"):
        instance_name = server.replace("(localdb)\\", "")
        server = f".\\{instance_name}"
        logger.info(f"Detected LocalDB, converted server to: {server}")

    database = os.getenv("MSSQL_DATABASE")
    if not database:
        raise ValueError("MSSQL_DATABASE environment variable is required")

    db_conf = {
        "server": server,
        "database": database,
        "port": int(os.getenv("MSSQL_PORT", "1433")),
        "timeout": int(os.getenv("MSSQL_TIMEOUT", "30")),
        "charset": os.getenv("MSSQL_CHARSET", "utf8")
    }

    # Handle authentication
    use_windows_auth = os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"
    
    if not use_windows_auth:
        user = os.getenv("MSSQL_USER")
        password = os.getenv("MSSQL_PASSWORD")
        if not user or not password:
            raise ValueError("MSSQL_USER and MSSQL_PASSWORD are required when not using Windows Authentication")
        db_conf["user"] = user
        db_conf["password"] = password
        logger.info("Using SQL Server Authentication")
    else:
        logger.info("Using Windows Authentication")

    # Azure / encryption settings
    if ".database.windows.net" in server or os.getenv("MSSQL_ENCRYPT", "false").lower() == "true":
        db_conf["tds_version"] = "7.4"
        logger.info("Using TDS version 7.4 for encrypted connection")

    return DBConfig(**db_conf)


@contextmanager
def get_db_connection(config: DBConfig = None):
    """Context manager for database connections with proper cleanup."""
    if config is None:
        config = get_db_config()
    
    conn = None
    try:
        # Build connection kwargs
        conn_kwargs = {
            "server": config.server,
            "database": config.database,
            "port": config.port,
            "timeout": config.timeout,
            "charset": config.charset
        }
        
        if config.user:
            conn_kwargs["user"] = config.user
        if config.password:
            conn_kwargs["password"] = config.password
        if config.tds_version:
            conn_kwargs["tds_version"] = config.tds_version
        
        logger.info(f"Connecting to database: {config.server}:{config.port}/{config.database}")
        conn = pymssql.connect(**conn_kwargs)
        yield conn
        
    except pymssql.Error as e:
        logger.error(f"Database connection error: {e}")
        raise ToolError(f"Database connection failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected connection error: {e}")
        raise ToolError(f"Connection error: {e}")
    finally:
        if conn:
            try:
                conn.close()
                logger.debug("Database connection closed")
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")


# Initialize FastMCP server
mcp = FastMCP("mssql_fastmcp_server")


@mcp.resource("connection://status")
def connection_status() -> Dict[str, Any]:
    """Resource to check database connection status."""
    try:
        config = get_db_config()
        with get_db_connection(config) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION, DB_NAME(), USER_NAME(), @@SERVERNAME")
            result = cursor.fetchone()
            return {
                "status": "connected",
                "server_version": result[0] if result else "Unknown",
                "database": result[1] if result else "Unknown",
                "user": result[2] if result else "Unknown",
                "server_name": result[3] if result else "Unknown"
            }
    except Exception as e:
        logger.error(f"Connection status check failed: {e}")
        return {
            "status": "disconnected",
            "error": str(e)
        }


@mcp.resource("tables://list")
def list_tables_resource() -> List[Dict[str, Any]]:
    """Resource exposing detailed list of tables with schema information."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    TABLE_SCHEMA,
                    TABLE_NAME,
                    TABLE_TYPE
                FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_TYPE IN ('BASE TABLE', 'VIEW')
                ORDER BY TABLE_SCHEMA, TABLE_NAME
            """)
            rows = cursor.fetchall()
            
            return [
                {
                    "schema": row[0],
                    "name": row[1],
                    "type": row[2],
                    "full_name": f"{row[0]}.{row[1]}" if row[0] else row[1]
                }
                for row in rows
            ]
    except Exception as e:
        logger.error(f"Error listing tables: {e}")
        raise ToolError(f"Failed to list tables: {e}")


@mcp.resource("table://{table}/schema")
def get_table_schema(table: str) -> Dict[str, Any]:
    """Resource exposing schema information for a specific table."""
    try:
        safe_table = validate_table_name(table)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get column information
            cursor.execute("""
                SELECT 
                    COLUMN_NAME,
                    DATA_TYPE,
                    IS_NULLABLE,
                    COLUMN_DEFAULT,
                    CHARACTER_MAXIMUM_LENGTH,
                    NUMERIC_PRECISION,
                    NUMERIC_SCALE,
                    ORDINAL_POSITION
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            """, (table.split('.')[-1],))
            
            columns = []
            for row in cursor.fetchall():
                columns.append({
                    "name": row[0],
                    "data_type": row[1],
                    "nullable": row[2] == "YES",
                    "default": row[3],
                    "max_length": row[4],
                    "precision": row[5],
                    "scale": row[6],
                    "position": row[7]
                })
            
            return {
                "table": table,
                "columns": columns,
                "column_count": len(columns)
            }
            
    except ValueError as ve:
        raise ToolError(str(ve))
    except Exception as e:
        logger.error(f"Error getting table schema for {table}: {e}")
        raise ToolError(f"Failed to get table schema: {e}")


@mcp.resource("table://{table}/sample")
def get_table_sample(table: str) -> Dict[str, Any]:
    """Resource exposing sample data from a table (top 10 rows)."""
    try:
        safe_table = validate_table_name(table)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get row count first
            cursor.execute(f"SELECT COUNT(*) FROM {safe_table}")
            total_rows = cursor.fetchone()[0]
            
            # Get sample data
            cursor.execute(f"SELECT TOP 10 * FROM {safe_table}")
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
            # Convert rows to list of dictionaries
            data = []
            for row in rows:
                data.append(dict(zip(columns, [str(item) if item is not None else None for item in row])))
            
            return {
                "table": table,
                "total_rows": total_rows,
                "sample_rows": len(data),
                "columns": columns,
                "data": data
            }
            
    except ValueError as ve:
        raise ToolError(str(ve))
    except Exception as e:
        logger.error(f"Error getting table sample for {table}: {e}")
        raise ToolError(f"Failed to get table sample: {e}")


class QueryInput(BaseModel):
    query: str = Field(..., description="SQL query to execute")
    limit: Optional[int] = Field(default=100, ge=1, le=10000, description="Maximum number of rows to return")

    @model_validator(mode='before')
    @classmethod
    def convert_str_to_dict(cls, data: Any) -> Any:
        """Allow the tool to accept a raw string as input."""
        if isinstance(data, str):
            # If the input is a string, wrap it in a dict
            return {'query': data}
        # Otherwise, return the data as is (assuming it's already a dict)
        return data


@mcp.tool()
def execute_query(ctx: Context, input: QueryInput) -> Dict[str, Any]:
    """Tool to execute a SELECT query safely."""
    try:
        query = sanitize_sql_query(input.query)
        
        # Only allow SELECT statements
        if not query.upper().strip().startswith('SELECT'):
            raise ToolError("Only SELECT queries are allowed")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Apply limit if not already present
            if 'TOP' not in query.upper() and 'LIMIT' not in query.upper():
                # Insert TOP clause after SELECT
                query = re.sub(r'^SELECT\s+', f'SELECT TOP {input.limit} ', query, flags=re.IGNORECASE)
            
            logger.info(f"Executing query: {query}")
            cursor.execute(query)
            
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            data = []
            for row in rows:
                data.append(dict(zip(columns, [str(item) if item is not None else None for item in row])))
            
            return {
                "status": "success",
                "columns": columns,
                "row_count": len(data),
                "data": data,
                "query": query
            }
            
    except ValueError as ve:
        raise ToolError(str(ve))
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        raise ToolError(f"Query execution failed: {e}")


class TableInput(BaseModel):
    table_name: str = Field(..., description="Name of the table to query")
    columns: Optional[List[str]] = Field(default=None, description="Specific columns to select")
    where_clause: Optional[str] = Field(default=None, description="WHERE clause conditions")
    limit: Optional[int] = Field(default=100, ge=1, le=10000, description="Maximum number of rows to return")


@mcp.tool()
def query_table(ctx: Context, input: TableInput) -> Dict[str, Any]:
    """Tool to query a specific table with optional filtering."""
    try:
        safe_table = validate_table_name(input.table_name)
        
        # Build SELECT clause
        if input.columns:
            # Validate column names
            safe_columns = []
            for col in input.columns:
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', col):
                    raise ValueError(f"Invalid column name: {col}")
                safe_columns.append(f"[{col}]")
            columns_str = ", ".join(safe_columns)
        else:
            columns_str = "*"
        
        # Build query
        query = f"SELECT TOP {input.limit} {columns_str} FROM {safe_table}"
        
        if input.where_clause:
            # Basic validation of WHERE clause
            where_clause = input.where_clause.strip()
            if where_clause.upper().startswith('WHERE'):
                where_clause = where_clause[5:].strip()
            query += f" WHERE {where_clause}"
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            logger.info(f"Executing table query: {query}")
            cursor.execute(query)
            
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            data = []
            for row in rows:
                data.append(dict(zip(columns, [str(item) if item is not None else None for item in row])))
            
            return {
                "status": "success",
                "table": input.table_name,
                "columns": columns,
                "row_count": len(data),
                "data": data,
                "query": query
            }
            
    except ValueError as ve:
        raise ToolError(str(ve))
    except Exception as e:
        logger.error(f"Error querying table {input.table_name}: {e}")
        raise ToolError(f"Table query failed: {e}")


@mcp.tool()
def test_connection(ctx: Context) -> Dict[str, Any]:
    """Tool to test database connectivity."""
    try:
        config = get_db_config()
        with get_db_connection(config) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 as test_value, GETDATE() as current_time")
            result = cursor.fetchone()
            
            return {
                "status": "success",
                "message": "Database connection successful",
                "test_value": result[0],
                "server_time": str(result[1]),
                "config": {
                    "server": config.server,
                    "database": config.database,
                    "port": config.port
                }
            }
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        return {
            "status": "failed",
            "message": f"Database connection failed: {e}"
        }


if __name__ == "__main__":
    try:
        logger.info("Starting MSSQL FastMCP Server...")
        # Test configuration on startup
        config = get_db_config()
        logger.info(f"Configuration loaded successfully for server: {config.server}/{config.database}")
        mcp.run(transport="http",host="0.0.0.0",port=8000)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise
