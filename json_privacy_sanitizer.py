import json
import argparse
import re
import os
from datetime import datetime
from uuid import UUID
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Union

"""
JSON Privacy Sanitizer

DISCLAIMER: This software is provided "AS IS" without any warranties.
Use at your own risk. The author is NOT responsible for any data loss,
security breaches, or damages. Always backup your data and test thoroughly
before using in production. Review the source code to understand what this
script does before using it.
"""

# JSON Schema-compatible type labels
TYPE_LABELS = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    type(None): "null",
    datetime: "string",
    UUID: "string",
    Decimal: "number",
    bytes: "string"
}

# Patterns for identifying potentially sensitive data
SENSITIVE_PATTERNS = {
    # Personal Information
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'phone': r'(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
    'ssn': r'\d{3}-\d{2}-\d{4}',
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    'mac_address': r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
    
    # IT Infrastructure
    'ssh_key': r'ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256',
    'private_key': r'-----BEGIN PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----',
    'certificate': r'-----BEGIN CERTIFICATE-----|-----BEGIN X509 CERTIFICATE-----',
    'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    'api_key': r'sk_live_|pk_live_|ak_|api_key_|access_key_|secret_key_',
    'aws_key': r'AKIA[A-Z0-9]{16}',
    'connection_string': r'[a-zA-Z]+://[^:]+:[^@]+@[^/]+/[^?]+',
    'encryption_key': r'[a-zA-Z0-9]{32,}|[a-zA-Z0-9]{8,}:[A-Z0-9]{8,}',
    
    # Company and Traceable Information
    'company_domain': r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Any domain
    'company_url': r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # URLs
    'internal_hostname': r'[a-zA-Z0-9-]+\.(internal|local|corp|company|org)',  # Internal domains
    'server_name': r'(prod|dev|staging|test|qa)-[a-zA-Z0-9-]+',  # Server naming patterns
    'product_name': r'[A-Z][a-zA-Z0-9\s]+(Pro|Enterprise|Cloud|Suite|Platform)',  # Product names
    'service_name': r'[a-zA-Z0-9-]+-service|[a-zA-Z0-9-]+-api',  # Service naming
    'geographic_location': r'[A-Z][a-zA-Z\s]+(City|State|Country|Region|Zone)',  # Geographic references
    'timestamp': r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO timestamps
    'version_number': r'v?\d+\.\d+\.\d+',  # Version numbers
    'environment_name': r'(production|prod|development|dev|staging|test|qa)',  # Environment names
    
    # Common sensitive field names
    'password': r'password|passwd|pwd|secret|token|key|auth',
    'personal': r'name|address|city|state|zip|country|birth|age|gender|race',
    'financial': r'account|routing|balance|amount|salary|income|price|cost',
    'medical': r'patient|diagnosis|treatment|medication|prescription|health',
    'government': r'license|passport|id|identification|tax|social'
}

def is_sensitive_value(value: Any) -> bool:
    """Check if a value contains sensitive information."""
    if not isinstance(value, str):
        return False
    
    value_lower = value.lower()
    
    # Check for sensitive patterns
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, value, re.IGNORECASE):
            return True
    
    # Check for common sensitive indicators
    sensitive_indicators = [
        'password', 'secret', 'token', 'key', 'private', 'confidential',
        'sensitive', 'personal', 'private', 'internal', 'restricted'
    ]
    
    return any(indicator in value_lower for indicator in sensitive_indicators)

def is_sensitive_key(key: str) -> bool:
    """Check if a key name indicates sensitive data."""
    key_lower = key.lower()
    
    sensitive_key_patterns = [
        # Personal identifiers
        r'id$', r'name$', r'email$', r'phone$', r'address$',
        r'birth', r'age$', r'gender$', r'race$', r'ethnicity$',
        
        # Financial data
        r'account$', r'balance$', r'credit$', r'debit$', r'card$',
        r'bank$', r'routing$', r'salary$', r'income$', r'price$',
        
        # Authentication
        r'password$', r'passwd$', r'pwd$', r'secret$', r'token$',
        r'key$', r'auth$', r'login$', r'username$',
        
        # Medical/Health
        r'patient$', r'diagnosis$', r'treatment$', r'medication$',
        r'prescription$', r'health$', r'medical$',
        
        # Government/ID
        r'license$', r'passport$', r'ssn$', r'social$', r'tax$',
        r'driver$', r'government$',
        
        # IT Infrastructure
        r'hostname$', r'ip$', r'mac$', r'ssh$', r'root$',
        r'api$', r'aws$', r'access$', r'secret$', r'private$',
        r'ssl$', r'cert$', r'session$', r'firewall$', r'connection$',
        r'admin$', r'backup$', r'encryption$', r'jwt$', r'oauth$',
        r'webhook$', r'third_party$', r'prometheus$', r'grafana$',
        r'alert$', r'log$', r'metrics$', r'vpn$', r'load_balancer$',
        r'ldap$', r'saml$', r'mfa$', r'totp$', r'deployment$',
        r'git$', r'docker$', r'kubernetes$', r'cluster$', r'service_account$',
        r's3$', r'bucket$', r'uuid$', r'hash$', r'signature$',
        
        # Company and Traceable Information
        r'company$', r'organization$', r'corp$', r'inc$', r'llc$',
        r'domain$', r'url$', r'website$', r'hostname$', r'server$',
        r'product$', r'service$', r'application$', r'app$',
        r'location$', r'region$', r'zone$', r'environment$',
        r'version$', r'build$', r'release$', r'timestamp$',
        r'created$', r'updated$', r'modified$', r'last_modified$',
        r'deployment$', r'instance$', r'cluster$', r'namespace$',
        r'project$', r'repository$', r'branch$', r'commit$',
        
        # Common sensitive words
        r'private$', r'confidential$', r'sensitive$', r'internal$',
        r'restricted$', r'secret$', r'hidden$'
    ]
    
    for pattern in sensitive_key_patterns:
        if re.search(pattern, key_lower):
            return True
    
    return False

def get_type_label(value: Any) -> str:
    """Get the JSON Schema-compatible type label for a value."""
    # Check for bool first since bool is a subclass of int
    if isinstance(value, bool):
        return "boolean"
    
    for py_type, label in TYPE_LABELS.items():
        if isinstance(value, py_type):
            return label
    return type(value).__name__

def safe_str(value: Any, max_length: int = 30) -> str:
    """Safely convert a value to string with length limit."""
    try:
        result = str(value)
        if len(result) > max_length:
            return result[:max_length-3] + "..."
        return result
    except Exception:
        return "<unserializable>"

def sanitize_json(
    data: Any,
    path: str = "$",
    seen: Optional[Set[int]] = None,
    audit_log: Optional[List[Dict[str, str]]] = None,
    include_sample: bool = False,
    max_sample_length: int = 30,
    max_depth: Optional[int] = None,
    depth: int = 0,
    remove_sensitive: bool = True,
    replace_with: str = "[REDACTED]"
) -> Any:
    """
    Sanitize JSON by removing sensitive information and replacing values with type labels.
    
    Args:
        data: The data to sanitize
        path: Current path in the JSON structure
        seen: Set of object IDs to detect circular references
        audit_log: List to store type information
        include_sample: Whether to include example values
        max_sample_length: Maximum length for sample values
        max_depth: Maximum recursion depth
        depth: Current recursion depth
        remove_sensitive: Whether to remove sensitive data
        replace_with: What to replace sensitive data with
    
    Returns:
        Sanitized data structure
    """
    seen = seen or set()
    if audit_log is None:
        audit_log = []

    # Check depth limit
    if max_depth is not None and depth > max_depth:
        return "<max depth reached>"

    # Handle circular references
    if isinstance(data, (dict, list)) and id(data) in seen:
        return "<circular>"

    # Add current object to seen set if it's a container
    if isinstance(data, (dict, list)):
        seen.add(id(data))

    if isinstance(data, dict):
        # Log the dict type
        audit_log.append({"path": path, "type": "object"})
        return {
            key: sanitize_json(
                value,
                f"{path}.{key}",
                seen,
                audit_log,
                include_sample,
                max_sample_length,
                max_depth,
                depth + 1,
                remove_sensitive,
                replace_with
            )
            for key, value in data.items()
        }

    elif isinstance(data, list):
        # Log the list type
        audit_log.append({"path": path, "type": "array"})
        return [
            sanitize_json(
                item,
                f"{path}[{i}]",
                seen,
                audit_log,
                include_sample,
                max_sample_length,
                max_depth,
                depth + 1,
                remove_sensitive,
                replace_with
            )
            for i, item in enumerate(data)
        ]

    else:
        # Handle primitive values
        label = get_type_label(data)
        
        # Check if this is sensitive data
        is_sensitive = False
        if remove_sensitive and isinstance(data, str):
            is_sensitive = is_sensitive_value(data)
        
        audit_log.append({
            "path": path, 
            "type": label,
            "sensitive": is_sensitive
        })
        
        # Replace sensitive data
        if is_sensitive:
            if include_sample:
                return {
                    "type": label,
                    "example": replace_with,
                    "sensitive": True
                }
            return replace_with
        
        # Handle non-sensitive data
        if include_sample:
            return {
                "type": label,
                "example": safe_str(data, max_sample_length)
            }
        return label

def sanitize_json_with_key_check(
    data: Any,
    path: str = "$",
    seen: Optional[Set[int]] = None,
    audit_log: Optional[List[Dict[str, str]]] = None,
    include_sample: bool = False,
    max_sample_length: int = 30,
    max_depth: Optional[int] = None,
    depth: int = 0,
    remove_sensitive: bool = True,
    replace_with: str = "[REDACTED]"
) -> Any:
    """
    Sanitize JSON with additional key-based sensitivity checking.
    """
    seen = seen or set()
    if audit_log is None:
        audit_log = []

    # Check depth limit
    if max_depth is not None and depth > max_depth:
        return "<max depth reached>"

    # Handle circular references
    if isinstance(data, (dict, list)) and id(data) in seen:
        return "<circular>"

    # Add current object to seen set if it's a container
    if isinstance(data, (dict, list)):
        seen.add(id(data))

    if isinstance(data, dict):
        # Log the dict type
        audit_log.append({"path": path, "type": "object"})
        return {
            key: sanitize_json_with_key_check(
                value,
                f"{path}.{key}",
                seen,
                audit_log,
                include_sample,
                max_sample_length,
                max_depth,
                depth + 1,
                remove_sensitive,
                replace_with
            )
            for key, value in data.items()
            if not (remove_sensitive and is_sensitive_key(key))
        }

    elif isinstance(data, list):
        # Log the list type
        audit_log.append({"path": path, "type": "array"})
        return [
            sanitize_json_with_key_check(
                item,
                f"{path}[{i}]",
                seen,
                audit_log,
                include_sample,
                max_sample_length,
                max_depth,
                depth + 1,
                remove_sensitive,
                replace_with
            )
            for i, item in enumerate(data)
        ]

    else:
        # Handle primitive values
        label = get_type_label(data)
        
        # Check if this is sensitive data
        is_sensitive = False
        if remove_sensitive and isinstance(data, str):
            is_sensitive = is_sensitive_value(data)
        
        audit_log.append({
            "path": path, 
            "type": label,
            "sensitive": is_sensitive
        })
        
        # Replace sensitive data
        if is_sensitive:
            if include_sample:
                return {
                    "type": label,
                    "example": replace_with,
                    "sensitive": True
                }
            return replace_with
        
        # Handle non-sensitive data
        if include_sample:
            return {
                "type": label,
                "example": safe_str(data, max_sample_length)
            }
        return label

def load_json_file(file_path: str) -> Any:
    """Load JSON data from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in input file: {e}")
    except Exception as e:
        raise RuntimeError(f"Error reading input file: {e}")

def save_json_file(file_path: str, data: Any) -> None:
    """Save JSON data to a file."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        raise RuntimeError(f"Error writing output file: {e}")

def save_audit_log(file_path: str, audit_log: List[Dict[str, str]]) -> None:
    """Save audit log to a file."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(audit_log, f, indent=2, ensure_ascii=False)
    except Exception as e:
        raise RuntimeError(f"Error writing audit log: {e}")

def ensure_output_directory(file_path: str) -> str:
    """Ensure the output directory exists and return the full path."""
    # If the path doesn't start with output/, prepend it
    if not file_path.startswith('output/'):
        file_path = os.path.join('output', file_path)
    
    # Create the directory if it doesn't exist
    output_dir = os.path.dirname(file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    return file_path

def main():
    """Main function to handle command line interface."""
    
    # Print disclaimer warning
    print("=" * 80)
    print("WARNING: This software is provided 'AS IS' without any warranties.")
    print("Use at your own risk. The author is NOT responsible for any data loss,")
    print("security breaches, or damages. Always backup your data before processing.")
    print("Review the source code to understand what this script does.")
    print("=" * 80)
    print()
    
    parser = argparse.ArgumentParser(
        description="Sanitize JSON by removing sensitive information and replacing values with type labels."
    )
    parser.add_argument("--input", required=True, help="Path to input JSON file")
    parser.add_argument("--output", help="Path to output sanitized JSON (default: output/sanitized_<input_name>.json)")
    parser.add_argument("--audit-log", help="Path to write audit log (optional, default: output/audit_<input_name>.json)")
    parser.add_argument("--include-sample", action="store_true", 
                       help="Include example values in output")
    parser.add_argument("--max-depth", type=int, default=None, 
                       help="Maximum recursion depth (default: unlimited)")
    parser.add_argument("--max-sample-length", type=int, default=30,
                       help="Maximum length for sample values (default: 30)")
    parser.add_argument("--remove-sensitive", action="store_true", default=True,
                       help="Remove sensitive data (default: True)")
    parser.add_argument("--replace-with", default="[REDACTED]",
                       help="Text to replace sensitive data with (default: [REDACTED])")
    parser.add_argument("--check-keys", action="store_true",
                       help="Also check key names for sensitive data")

    args = parser.parse_args()

    try:
        # Generate default output paths if not provided
        if not args.output:
            input_name = os.path.splitext(os.path.basename(args.input))[0]
            args.output = f"sanitized_{input_name}.json"
        
        if not args.audit_log:
            input_name = os.path.splitext(os.path.basename(args.input))[0]
            args.audit_log = f"audit_{input_name}.json"
        
        # Ensure output directory exists and get full paths
        output_path = ensure_output_directory(args.output)
        audit_log_path = ensure_output_directory(args.audit_log) if args.audit_log else None
        
        # Load input JSON
        print(f"Loading JSON from: {args.input}")
        raw_data = load_json_file(args.input)
        
        # Sanitize the data
        print("Sanitizing JSON and removing sensitive data...")
        audit_log: List[Dict[str, str]] = []
        
        if args.check_keys:
            sanitized = sanitize_json_with_key_check(
                raw_data,
                audit_log=audit_log,
                include_sample=args.include_sample,
                max_depth=args.max_depth,
                max_sample_length=args.max_sample_length,
                remove_sensitive=args.remove_sensitive,
                replace_with=args.replace_with
            )
        else:
            sanitized = sanitize_json(
                raw_data,
                audit_log=audit_log,
                include_sample=args.include_sample,
                max_depth=args.max_depth,
                max_sample_length=args.max_sample_length,
                remove_sensitive=args.remove_sensitive,
                replace_with=args.replace_with
            )

        # Save sanitized output
        save_json_file(output_path, sanitized)
        print(f"Sanitized JSON saved to: {output_path}")

        # Save audit log if requested
        if audit_log_path:
            save_audit_log(audit_log_path, audit_log)
            print(f"Audit log saved to: {audit_log_path}")

        # Print summary
        sensitive_count = sum(1 for item in audit_log if item.get("sensitive", False))
        print(f"Processed {len(audit_log)} values, {sensitive_count} sensitive items removed")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main()) 