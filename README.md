# JSON Privacy Sanitizer

A Python script that sanitizes JSON files by removing sensitive information and replacing values with their type labels, ensuring privacy protection while maintaining data structure.

## DISCLAIMER AND WARNING

**IMPORTANT: USE AT YOUR OWN RISK**

This software is provided "AS IS" without any warranties of any kind. By using this script, you acknowledge and agree to the following:

### **No Responsibility Assumed**
- The author is **NOT responsible** for any data loss, security breaches, or damages that may occur from using this script
- The author is **NOT responsible** for any misuse, misconfiguration, or unintended consequences
- The author is **NOT responsible** for any legal issues arising from the use of this tool

### **Use at Your Own Risk**
- This script may not work for every use case or data format
- The sensitive data detection is not 100% foolproof and may miss some sensitive information
- Always test thoroughly with your specific data before using in production
- Always backup your original data before processing

### **Security and Privacy**
- **NEVER use any script without fully understanding what it does**
- Review the source code thoroughly before using
- This tool is designed for educational and testing purposes
- For production use, consult with security professionals
- Always verify the sanitized output meets your privacy requirements

### **Limitations**
- This script may not detect all types of sensitive data
- False positives and false negatives are possible
- The tool may not work correctly with all JSON structures
- Performance may vary with large or complex files

**By using this script, you accept full responsibility for any consequences and agree to use it at your own risk.**

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/1B05H1N/json-privacy-sanitizer.git
   cd json-privacy-sanitizer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Test the installation:**
   ```bash
   python json_privacy_sanitizer.py --input sample.json
   ```

## Features

- **Privacy Protection**: Automatically detects and removes sensitive data
- **Pattern Recognition**: Identifies emails, phone numbers, SSNs, credit cards, IP addresses, etc.
- **Key-based Filtering**: Can remove entire fields based on sensitive key names
- **Type Preservation**: Replaces values with JSON Schema-compatible type labels
- **Circular Reference Detection**: Prevents infinite recursion
- **Configurable Recursion Depth**: Limits processing depth for large files
- **Audit Logging**: Detailed logging of all processed values and removed sensitive data
- **Sample Value Inclusion**: Optional inclusion of example values with length limits

## Sensitive Data Detection

The sanitizer automatically detects and removes:

### Personal Information
- Email addresses
- Phone numbers
- Social Security Numbers (SSN)
- Names and addresses
- Birth dates and ages

### Financial Data
- Credit card numbers
- Bank account numbers
- Routing numbers
- Salaries and balances

### Technical Data
- IP addresses
- MAC addresses
- API keys and tokens
- Password hashes
- Private keys

### Medical Information
- Patient IDs
- Diagnoses
- Medications
- Treatment plans

### Authentication Data
- Passwords and secrets
- Session tokens
- Authentication keys

## Quick Start

### Basic Usage (Recommended)

```bash
# Simplest usage - automatically saves to output/ folder
python json_privacy_sanitizer.py --input your_file.json
```

This will:
- Read your JSON file
- Detect and remove sensitive data
- Save sanitized output to `output/sanitized_your_file.json`
- Save audit log to `output/audit_your_file.json`

### Advanced Usage

```bash
# Custom output paths
python json_privacy_sanitizer.py --input input.json --output sanitized.json

# Include sample values in output
python json_privacy_sanitizer.py --input input.json --include-sample

# Also check field names for sensitive data
python json_privacy_sanitizer.py --input input.json --check-keys
```

### More Examples

```bash
# Include sample values in output
python json_privacy_sanitizer.py --input input.json --include-sample

# Also check field names for sensitive data
python json_privacy_sanitizer.py --input input.json --check-keys

# Limit processing depth for large files
python json_privacy_sanitizer.py --input input.json --max-depth 3

# Custom replacement text
python json_privacy_sanitizer.py --input input.json --replace-with "[SENSITIVE]"
```

### Complete Example

```bash
python json_privacy_sanitizer.py \
  --input sensitive_data.json \
  --output sanitized.json \
  --audit-log audit.json \
  --include-sample \
  --check-keys \
  --max-depth 5 \
  --max-sample-length 50
```

## Command Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--input` | Yes | - | Path to input JSON file |
| `--output` | No | `output/sanitized_<input_name>.json` | Path to output sanitized JSON |
| `--audit-log` | No | `output/audit_<input_name>.json` | Path to write audit log |
| `--include-sample` | No | False | Include example values in output |
| `--max-depth` | No | Unlimited | Maximum recursion depth |
| `--max-sample-length` | No | 30 | Maximum length for sample values |
| `--remove-sensitive` | No | True | Remove sensitive data |
| `--replace-with` | No | `[REDACTED]` | Text to replace sensitive data with |
| `--check-keys` | No | False | Also check key names for sensitive data |

## Output Folder

All output files are automatically saved to the `output/` folder by default. This folder is excluded from version control via `.gitignore` to ensure sensitive data is never accidentally committed to the repository.

### Default File Naming

- **Sanitized JSON**: `output/sanitized_<input_filename>.json`
- **Audit Log**: `output/audit_<input_filename>.json`

### Examples

```bash
# Input: data.json
# Output: output/sanitized_data.json
# Audit: output/audit_data.json
python json_privacy_sanitizer.py --input data.json

# Input: users.json  
# Output: output/sanitized_users.json
# Audit: output/audit_users.json
python json_privacy_sanitizer.py --input users.json
```

### Custom Paths

You can specify custom output paths, and they will still be placed in the `output/` folder unless you provide an absolute path:

```bash
# Saves to: output/my_output.json
python json_privacy_sanitizer.py --input data.json --output my_output.json

# Saves to: /tmp/my_output.json (absolute path)
python json_privacy_sanitizer.py --input data.json --output /tmp/my_output.json
```

## Output Examples

### Input with Sensitive Data

```json
{
  "user": {
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1-555-123-4567",
    "ssn": "123-45-6789",
    "credit_card": "4111-1111-1111-1111"
  },
  "public_info": {
    "username": "johndoe",
    "join_date": "2023-01-15"
  }
}
```

### Basic Sanitization Output

```json
{
  "user": {
    "name": "string",
    "email": "[REDACTED]",
    "phone": "[REDACTED]",
    "ssn": "[REDACTED]",
    "credit_card": "[REDACTED]"
  },
  "public_info": {
    "username": "string",
    "join_date": "string"
  }
}
```

### With Sample Values

```json
{
  "user": {
    "name": {
      "type": "string",
      "example": "John Doe"
    },
    "email": {
      "type": "string",
      "example": "[REDACTED]",
      "sensitive": true
    }
  }
}
```

### With Key-based Filtering

```json
{
  "public_info": {
    "username": "string",
    "join_date": "string"
  }
}
```

## Audit Log Format

The audit log contains detailed information about each processed value:

```json
[
  {
    "path": "$.user.email",
    "type": "string",
    "sensitive": true
  },
  {
    "path": "$.public_info.username",
    "type": "string",
    "sensitive": false
  }
]
```

## Privacy Protection Levels

### Level 1: Value-based Detection
- Detects sensitive patterns in data values
- Replaces sensitive values with `[REDACTED]`
- Preserves non-sensitive data structure

### Level 2: Key-based Filtering
- Also checks field names for sensitive indicators
- Completely removes sensitive fields
- More aggressive privacy protection

### Level 3: Custom Patterns
- Extensible pattern matching system
- Can be customized for specific data types
- Supports regular expressions for complex patterns

## Testing

You can test the sanitizer with the included sample files:

```bash
# Test with sample data (recommended first test)
python json_privacy_sanitizer.py --input sample.json

# Test with sensitive data
python json_privacy_sanitizer.py --input sensitive_sample.json --include-sample

# Test with key checking
python json_privacy_sanitizer.py --input sensitive_sample.json --check-keys

# Test with company data
python json_privacy_sanitizer.py --input company_sample.json --include-sample
```

### Expected Results

After running the tests, you should see:
- Files created in the `output/` folder
- Sensitive data replaced with `[REDACTED]`
- Audit logs showing what was processed
- Console output showing processing statistics

## Error Handling

The script includes robust error handling for:
- File not found errors
- Invalid JSON syntax
- Circular references
- Maximum depth exceeded
- Unserializable values

## Security Features

- **No Data Leakage**: Sensitive data is completely removed or redacted
- **Audit Trail**: Complete logging of all processed data
- **Configurable Replacement**: Customizable redaction text
- **Pattern-based Detection**: Comprehensive sensitive data recognition
- **Key-based Filtering**: Removes entire sensitive fields when needed

## Supported Types

- `string`: String values (with sensitive data detection)
- `integer`: Integer numbers
- `number`: Float/decimal numbers
- `boolean`: True/false values
- `null`: Null values
- `object`: JSON objects
- `array`: JSON arrays

The JSON Privacy Sanitizer ensures your data is safe for sharing, testing, or analysis while maintaining the original structure and type information. 