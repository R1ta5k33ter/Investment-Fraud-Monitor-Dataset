# Investment-Fraud-Monitor-Dataset

This repository manages a dataset of malicious domains for use in block lists and security analysis. The dataset uses SQLite for efficient storage and management with automatic domain defanging using the square bracket method.

## Features

- **SQLite Database**: Fast, reliable storage with indexing for efficient queries
- **Automatic Domain Defanging**: Domains are automatically defanged using the square bracket method (e.g., `example[.]com`)
- **Easy Data Management**: Add, update, delete, and search domains with simple commands
- **CSV Import/Export**: Full compatibility with CSV format for data exchange
- **Command-Line Interface**: Comprehensive CLI for all operations
- **Interactive Mode**: User-friendly interactive script for guided operations
- **Batch Import**: Support for adding multiple domains from text files
- **Advanced Search**: Search domains by various fields with filtering
- **Blocklist Export**: Export domains in various formats for use in security tools
- **Input Validation**: Comprehensive validation for domains and flags
- **Duplicate Detection**: Prevents adding duplicate domains
- **Migration Support**: Easy migration from CSV-based systems

## Dataset Structure

The dataset uses SQLite with the following schema:

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `id` | INTEGER | Primary key (auto-increment) | `1` |
| `domain` | TEXT | Malicious domain (defanged) | `example[.]com` |
| `source` | TEXT | Source URL (e.g., VirusTotal) | `https://virustotal.com/gui/domain/example.com` |
| `date_reported` | TEXT | Date when domain was reported | `2024-01-15` |
| `comments` | TEXT | Free text comments | `Phishing site targeting banks` |
| `flags` | TEXT | Semicolon-separated flags | `phishing;botnet` |
| `created_at` | TIMESTAMP | When record was created | `2024-01-15 10:30:00` |
| `updated_at` | TIMESTAMP | When record was last updated | `2024-01-15 10:30:00` |

The database includes indexes on `domain` and `flags` for fast searching.

## Installation

No external dependencies are required! This project uses only Python standard library modules.

```bash
# Clone the repository
git clone <repository-url>
cd Investment-Fraud-Monitor-Dataset

# Make scripts executable (optional)
chmod +x domain_manager.py add_domain.py
```

## Usage

### Interactive Mode (Recommended for beginners)

Run the interactive script for a guided experience:

```bash
python3 add_domain.py
```

This will present you with a menu to:
- Add single domains interactively
- Add multiple domains from a file
- View statistics
- Search domains
- Export blocklists

### Command-Line Interface

#### Add a Domain

```bash
# Basic usage
python3 domain_manager.py add example.com "source"
# Example:
python3 domain_manager.py add example.com "https://virustotal.com/gui/domain/example.com"

# With comments and flags
python3 domain_manager.py add example.com "https://virustotal.com/gui/domain/example.com" \
    --comments "Phishing site targeting banks" \
    --flags "phishing;botnet"

# With custom date
python3 domain_manager.py add example.com "https://virustotal.com/gui/domain/example.com" \
    --date "2024-01-15"
```

#### Update a Domain

```bash
# Update source
python3 domain_manager.py update example.com --source "https://new-source.com"

# Update comments and flags
python3 domain_manager.py update example.com \
    --comments "Updated analysis" \
    --flags "phishing;confirmed"

# Update multiple fields
python3 domain_manager.py update example.com \
    --source "https://virustotal.com/new" \
    --comments "Confirmed malicious" \
    --flags "phishing;malware"
```

#### Delete a Domain

```bash
# Delete a domain
python3 domain_manager.py delete example.com
```

#### Get Domain Information

```bash
# Get detailed information about a domain
python3 domain_manager.py get example.com
```

#### List Domains

```bash
# List all domains
python3 domain_manager.py list

# List with limit and offset
python3 domain_manager.py list --limit 10 --offset 20
```

#### Search Domains

```bash
# Search by domain
python3 domain_manager.py search "example"

# Search by flags
python3 domain_manager.py search "phishing" --field flags

# Search by comments
python3 domain_manager.py search "bank" --field comments

# Search with limit
python3 domain_manager.py search "malware" --field flags --limit 5
```

#### View Statistics

```bash
python3 domain_manager.py stats
```

#### Export to CSV

```bash
# Export entire dataset to CSV
python3 domain_manager.py export-csv --output domains_export.csv
```

#### Import from CSV

```bash
# Import domains from CSV file
python3 domain_manager.py import-csv domains.csv

# Import and skip duplicates
python3 domain_manager.py import-csv domains.csv --skip-duplicates
```

#### Export Blocklist

```bash
# Export defanged domains (default)
python3 domain_manager.py export --output blocklist.txt

# Export normal domains
python3 domain_manager.py export --output blocklist.txt --format normal
```

### Migration from CSV

If you have an existing CSV-based dataset, you can easily migrate to SQLite:

```bash
# Migrate CSV to SQLite
python3 migrate_to_sqlite.py domains.csv

# Migrate with custom database name
python3 migrate_to_sqlite.py domains.csv --db my_domains.db

# Migrate with verification
python3 migrate_to_sqlite.py domains.csv --verify
```

### Batch Import

Create a text file with domains (one per line, comma-separated):

```
example.com,https://virustotal.com/gui/domain/example.com,Phishing site,phishing;botnet
malware.com,https://virustotal.com/gui/domain/malware.com,Malware distribution,malware
```

Then use the interactive mode to import the file, or use the CLI:

```bash
python3 add_domain.py
# Select option 2 for batch import
```

## Common Flags

The system supports various flags for categorizing malicious domains:

- `phishing` - Phishing websites
- `botnet` - Botnet command and control
- `c2` - Command and control servers
- `malware` - Malware distribution sites
- `spam` - Spam-related domains
- `scam` - Scam websites
- `cryptocurrency` - Cryptocurrency scams
- `investment` - Investment fraud

## Examples

### Adding a Phishing Domain

```bash
python3 domain_manager.py add "bank-security.com" \
    "https://virustotal.com/gui/domain/bank-security.com" \
    --comments "Fake banking website targeting customers" \
    --flags "phishing;scam"
```

### Searching for Botnet Domains

```bash
python3 domain_manager.py search "botnet" --field flags
```

### Exporting for Pi-hole

```bash
python3 domain_manager.py export --output pihole-blocklist.txt --format normal
```

## File Structure

```
Investment-Fraud-Monitor-Dataset/
├── README.md                 # This file
├── domain_manager.py         # Main SQLite-based domain management class and CLI
├── add_domain.py            # Interactive domain management script
├── migrate_to_sqlite.py     # Migration script for CSV to SQLite
├── example.py               # Example usage script
├── requirements.txt         # Dependencies (none required)
└── malicious_domains.db     # SQLite database (created automatically)
```

## Advanced Usage

### Using as a Python Module

```python
from domain_manager import DomainManager

# Initialize with SQLite database
dm = DomainManager("my_domains.db")

# Add a domain
dm.add_domain("example.com", "https://virustotal.com/example", 
              "Malicious site", "phishing;botnet")

# Update a domain
dm.update_domain("example.com", comments="Updated analysis", flags="phishing;confirmed")

# Get domain information
domain_info = dm.get_domain("example.com")

# Search domains
results = dm.search_domains("phishing", "flags")

# Export to CSV
dm.export_to_csv("backup.csv")

# Get statistics
stats = dm.get_stats()
print(f"Total domains: {stats['total_domains']}")
```

### Custom Database File

```bash
# Use a different database file
python3 domain_manager.py --db custom_domains.db add example.com "source"
```

## Security Considerations

- All domains are automatically defanged using the square bracket method
- Input validation prevents malformed domains from being added
- Duplicate detection prevents accidental re-addition of domains
- Source URLs should be from trusted security vendors (VirusTotal, etc.)

## Contributing

When adding domains:
1. Ensure the domain is actually malicious
2. Provide a reliable source
3. Use appropriate flags for categorization
4. Add descriptive comments when possible

## License

This project is part of the Investment Fraud Monitor system.
