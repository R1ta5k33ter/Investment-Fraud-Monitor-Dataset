#!/usr/bin/env python3
"""
SQLite-based Domain Manager for Investment Fraud Monitor Dataset

This module provides functionality to manage malicious domains with SQLite storage,
domain defanging, and easy data modification capabilities.
"""

import sqlite3
import csv
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
import argparse
import sys


class DomainManager:
    """Manages malicious domain dataset with SQLite storage and domain defanging."""
    
    def __init__(self, db_file: str = "malicious_domains.db"):
        """Initialize the DomainManager with a SQLite database file path."""
        self.db_file = Path(db_file)
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the SQLite database with the required schema."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Create domains table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    date_reported TEXT NOT NULL,
                    comments TEXT DEFAULT '',
                    flags TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index on domain for faster searches
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)
            ''')
            
            # Create index on flags for faster flag-based searches
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_flags ON domains(flags)
            ''')
            
            conn.commit()
    
    def defang_domain(self, domain: str) -> str:
        """
        Defang a domain using square bracket method.
        
        Args:
            domain: The domain to defang (e.g., "example.com")
            
        Returns:
            Defanged domain (e.g., "example[.]com")
        """
        # Remove any existing defanging first
        domain = domain.replace('[.]', '.')
        
        # Defang the domain by replacing dots with [.]
        defanged = domain.replace('.', '[.]')
        
        return defanged
    
    def defang_domain_back(self, defanged_domain: str) -> str:
        """
        Convert defanged domain back to normal format.
        
        Args:
            defanged_domain: The defanged domain (e.g., "example[.]com")
            
        Returns:
            Normal domain (e.g., "example.com")
        """
        return defanged_domain.replace('[.]', '.')
    
    def validate_domain(self, domain: str) -> bool:
        """
        Basic domain validation.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if domain appears valid, False otherwise
        """
        # Remove defanging for validation
        clean_domain = self.defang_domain_back(domain)
        
        # Basic domain regex pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        return bool(re.match(domain_pattern, clean_domain))
    
    def validate_flags(self, flags: str) -> bool:
        """
        Validate flags format (semicolon-separated).
        
        Args:
            flags: Flags string to validate
            
        Returns:
            True if format is valid, False otherwise
        """
        if not flags:
            return True
        
        # Check for valid flag format (no empty flags, proper semicolon separation)
        flag_list = [flag.strip() for flag in flags.split(';')]
        return all(flag for flag in flag_list) and len(flag_list) == len(set(flag_list))
    
    def add_domain(self, domain: str, source: str, comments: str = "", 
                   flags: str = "", date_reported: Optional[str] = None) -> bool:
        """
        Add a new malicious domain to the dataset.
        
        Args:
            domain: The malicious domain
            source: Source URL (e.g., VirusTotal link)
            comments: Free text comments
            flags: Semicolon-separated flags (e.g., "phishing;botnet")
            date_reported: Date in YYYY-MM-DD format (defaults to today)
            
        Returns:
            True if successfully added, False otherwise
        """
        # Validate inputs
        if not self.validate_domain(domain):
            print(f"Error: Invalid domain format: {domain}")
            return False
        
        if not self.validate_flags(flags):
            print(f"Error: Invalid flags format: {flags}")
            return False
        
        # Defang the domain
        defanged_domain = self.defang_domain(domain)
        
        # Set default date if not provided
        if date_reported is None:
            date_reported = datetime.now().strftime("%Y-%m-%d")
        
        # Check for duplicates
        if self.domain_exists(defanged_domain):
            print(f"Warning: Domain {defanged_domain} already exists in dataset")
            return False
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO domains (domain, source, date_reported, comments, flags)
                    VALUES (?, ?, ?, ?, ?)
                ''', (defanged_domain, source, date_reported, comments, flags))
                conn.commit()
            
            print(f"Successfully added domain: {defanged_domain}")
            return True
            
        except sqlite3.Error as e:
            print(f"Error adding domain to database: {e}")
            return False
    
    def update_domain(self, domain: str, **kwargs) -> bool:
        """
        Update an existing domain's information.
        
        Args:
            domain: The domain to update (can be defanged or normal)
            **kwargs: Fields to update (source, comments, flags, date_reported)
            
        Returns:
            True if successfully updated, False otherwise
        """
        defanged_domain = self.defang_domain(domain)
        
        if not self.domain_exists(defanged_domain):
            print(f"Error: Domain {defanged_domain} not found in dataset")
            return False
        
        # Validate flags if provided
        if 'flags' in kwargs and not self.validate_flags(kwargs['flags']):
            print(f"Error: Invalid flags format: {kwargs['flags']}")
            return False
        
        # Build update query dynamically
        update_fields = []
        values = []
        
        for field, value in kwargs.items():
            if field in ['source', 'comments', 'flags', 'date_reported']:
                update_fields.append(f"{field} = ?")
                values.append(value)
        
        if not update_fields:
            print("Error: No valid fields to update")
            return False
        
        # Add updated_at timestamp
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        values.append(defanged_domain)
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                query = f"UPDATE domains SET {', '.join(update_fields)} WHERE domain = ?"
                cursor.execute(query, values)
                
                if cursor.rowcount == 0:
                    print(f"Error: Domain {defanged_domain} not found")
                    return False
                
                conn.commit()
            
            print(f"Successfully updated domain: {defanged_domain}")
            return True
            
        except sqlite3.Error as e:
            print(f"Error updating domain: {e}")
            return False
    
    def delete_domain(self, domain: str) -> bool:
        """
        Delete a domain from the dataset.
        
        Args:
            domain: The domain to delete (can be defanged or normal)
            
        Returns:
            True if successfully deleted, False otherwise
        """
        defanged_domain = self.defang_domain(domain)
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM domains WHERE domain = ?", (defanged_domain,))
                
                if cursor.rowcount == 0:
                    print(f"Error: Domain {defanged_domain} not found")
                    return False
                
                conn.commit()
            
            print(f"Successfully deleted domain: {defanged_domain}")
            return True
            
        except sqlite3.Error as e:
            print(f"Error deleting domain: {e}")
            return False
    
    def get_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Get a specific domain's information.
        
        Args:
            domain: The domain to retrieve (can be defanged or normal)
            
        Returns:
            Dictionary with domain information or None if not found
        """
        defanged_domain = self.defang_domain(domain)
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT domain, source, date_reported, comments, flags, 
                           created_at, updated_at
                    FROM domains WHERE domain = ?
                ''', (defanged_domain,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'domain': row[0],
                        'source': row[1],
                        'date_reported': row[2],
                        'comments': row[3],
                        'flags': row[4],
                        'created_at': row[5],
                        'updated_at': row[6]
                    }
                return None
                
        except sqlite3.Error as e:
            print(f"Error retrieving domain: {e}")
            return None
    
    def domain_exists(self, domain: str) -> bool:
        """
        Check if a domain already exists in the dataset.
        
        Args:
            domain: Domain to check (can be defanged or normal)
            
        Returns:
            True if domain exists, False otherwise
        """
        defanged_domain = self.defang_domain(domain)
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM domains WHERE domain = ?", (defanged_domain,))
                return cursor.fetchone() is not None
        except sqlite3.Error:
            return False
    
    def get_all_domains(self, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, str]]:
        """
        Get all domains from the dataset.
        
        Args:
            limit: Maximum number of domains to return
            offset: Number of domains to skip
            
        Returns:
            List of dictionaries containing domain data
        """
        domains = []
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT domain, source, date_reported, comments, flags, 
                           created_at, updated_at
                    FROM domains 
                    ORDER BY created_at DESC
                '''
                
                if limit:
                    query += f" LIMIT {limit} OFFSET {offset}"
                
                cursor.execute(query)
                
                for row in cursor.fetchall():
                    domains.append({
                        'domain': row[0],
                        'source': row[1],
                        'date_reported': row[2],
                        'comments': row[3],
                        'flags': row[4],
                        'created_at': row[5],
                        'updated_at': row[6]
                    })
                
        except sqlite3.Error as e:
            print(f"Error retrieving domains: {e}")
        
        return domains
    
    def search_domains(self, query: str, field: str = "domain", limit: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Search domains by a specific field.
        
        Args:
            query: Search query
            field: Field to search in (domain, source, comments, flags)
            limit: Maximum number of results to return
            
        Returns:
            List of matching domain records
        """
        valid_fields = ["domain", "source", "comments", "flags"]
        if field not in valid_fields:
            print(f"Error: Invalid field '{field}'. Valid fields: {', '.join(valid_fields)}")
            return []
        
        domains = []
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                sql_query = f'''
                    SELECT domain, source, date_reported, comments, flags, 
                           created_at, updated_at
                    FROM domains 
                    WHERE {field} LIKE ? 
                    ORDER BY created_at DESC
                '''
                
                if limit:
                    sql_query += f" LIMIT {limit}"
                
                cursor.execute(sql_query, (f'%{query}%',))
                
                for row in cursor.fetchall():
                    domains.append({
                        'domain': row[0],
                        'source': row[1],
                        'date_reported': row[2],
                        'comments': row[3],
                        'flags': row[4],
                        'created_at': row[5],
                        'updated_at': row[6]
                    })
                
        except sqlite3.Error as e:
            print(f"Error searching domains: {e}")
        
        return domains
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get basic statistics about the dataset.
        
        Returns:
            Dictionary with statistics
        """
        stats = {}
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Total domains
                cursor.execute("SELECT COUNT(*) FROM domains")
                stats["total_domains"] = cursor.fetchone()[0]
                
                # Unique sources
                cursor.execute("SELECT COUNT(DISTINCT source) FROM domains")
                stats["unique_sources"] = cursor.fetchone()[0]
                
                # Domains with flags
                cursor.execute("SELECT COUNT(*) FROM domains WHERE flags != '' AND flags IS NOT NULL")
                stats["domains_with_flags"] = cursor.fetchone()[0]
                
                # Domains with comments
                cursor.execute("SELECT COUNT(*) FROM domains WHERE comments != '' AND comments IS NOT NULL")
                stats["domains_with_comments"] = cursor.fetchone()[0]
                
                # Flag counts
                cursor.execute("SELECT flags FROM domains WHERE flags != '' AND flags IS NOT NULL")
                all_flags = []
                for row in cursor.fetchall():
                    if row[0]:
                        all_flags.extend([flag.strip() for flag in row[0].split(';')])
                
                flag_counts = {}
                for flag in all_flags:
                    flag_counts[flag] = flag_counts.get(flag, 0) + 1
                
                stats["flag_counts"] = flag_counts
                
        except sqlite3.Error as e:
            print(f"Error getting statistics: {e}")
            stats = {
                "total_domains": 0,
                "unique_sources": 0,
                "domains_with_flags": 0,
                "domains_with_comments": 0,
                "flag_counts": {}
            }
        
        return stats
    
    def export_to_csv(self, output_file: str = "malicious_domains_export.csv") -> bool:
        """
        Export the entire dataset to a CSV file.
        
        Args:
            output_file: Output CSV file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            domains = self.get_all_domains()
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['domain', 'source', 'date_reported', 'comments', 'flags', 
                            'created_at', 'updated_at']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for domain in domains:
                    writer.writerow(domain)
            
            print(f"Successfully exported {len(domains)} domains to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
    
    def import_from_csv(self, csv_file: str, skip_duplicates: bool = True) -> Tuple[int, int]:
        """
        Import domains from a CSV file.
        
        Args:
            csv_file: Path to CSV file to import
            skip_duplicates: Whether to skip duplicate domains
            
        Returns:
            Tuple of (imported_count, skipped_count)
        """
        imported_count = 0
        skipped_count = 0
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    domain = row.get('domain', '').strip()
                    source = row.get('source', '').strip()
                    date_reported = row.get('date_reported', '').strip()
                    comments = row.get('comments', '').strip()
                    flags = row.get('flags', '').strip()
                    
                    if not domain or not source:
                        skipped_count += 1
                        continue
                    
                    # Check for duplicates
                    if skip_duplicates and self.domain_exists(domain):
                        skipped_count += 1
                        continue
                    
                    # Add domain
                    if self.add_domain(domain, source, comments, flags, date_reported):
                        imported_count += 1
                    else:
                        skipped_count += 1
            
            print(f"Import completed: {imported_count} imported, {skipped_count} skipped")
            
        except Exception as e:
            print(f"Error importing from CSV: {e}")
        
        return imported_count, skipped_count
    
    def export_blocklist(self, output_file: str = "blocklist.txt", 
                        format_type: str = "defanged") -> bool:
        """
        Export domains as a blocklist file.
        
        Args:
            output_file: Output file path
            format_type: "defanged" or "normal"
            
        Returns:
            True if successful, False otherwise
        """
        domains = self.get_all_domains()
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for domain in domains:
                    if format_type == "normal":
                        f.write(self.defang_domain_back(domain['domain']) + '\n')
                    else:  # defanged
                        f.write(domain['domain'] + '\n')
            
            print(f"Exported {len(domains)} domains to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting blocklist: {e}")
            return False


def main():
    """Command-line interface for the DomainManager."""
    parser = argparse.ArgumentParser(description="Manage malicious domain dataset with SQLite")
    parser.add_argument("--db", default="malicious_domains.db", 
                       help="SQLite database file path (default: malicious_domains.db)")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add domain command
    add_parser = subparsers.add_parser("add", help="Add a new domain")
    add_parser.add_argument("domain", help="Domain to add")
    add_parser.add_argument("source", help="Source URL")
    add_parser.add_argument("--comments", default="", help="Comments")
    add_parser.add_argument("--flags", default="", help="Flags (semicolon-separated)")
    add_parser.add_argument("--date", help="Date reported (YYYY-MM-DD)")
    
    # Update domain command
    update_parser = subparsers.add_parser("update", help="Update an existing domain")
    update_parser.add_argument("domain", help="Domain to update")
    update_parser.add_argument("--source", help="New source URL")
    update_parser.add_argument("--comments", help="New comments")
    update_parser.add_argument("--flags", help="New flags (semicolon-separated)")
    update_parser.add_argument("--date", help="New date reported (YYYY-MM-DD)")
    
    # Delete domain command
    delete_parser = subparsers.add_parser("delete", help="Delete a domain")
    delete_parser.add_argument("domain", help="Domain to delete")
    
    # Get domain command
    get_parser = subparsers.add_parser("get", help="Get domain information")
    get_parser.add_argument("domain", help="Domain to retrieve")
    
    # List domains command
    list_parser = subparsers.add_parser("list", help="List all domains")
    list_parser.add_argument("--limit", type=int, help="Limit number of results")
    list_parser.add_argument("--offset", type=int, default=0, help="Number of results to skip")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Search domains")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--field", default="domain", 
                              choices=["domain", "source", "comments", "flags"],
                              help="Field to search in")
    search_parser.add_argument("--limit", type=int, help="Limit number of results")
    
    # Stats command
    subparsers.add_parser("stats", help="Show dataset statistics")
    
    # Export CSV command
    export_csv_parser = subparsers.add_parser("export-csv", help="Export dataset to CSV")
    export_csv_parser.add_argument("--output", default="malicious_domains_export.csv", 
                                  help="Output CSV file")
    
    # Import CSV command
    import_csv_parser = subparsers.add_parser("import-csv", help="Import domains from CSV")
    import_csv_parser.add_argument("csv_file", help="CSV file to import")
    import_csv_parser.add_argument("--skip-duplicates", action="store_true", 
                                  help="Skip duplicate domains")
    
    # Export blocklist command
    export_parser = subparsers.add_parser("export", help="Export blocklist")
    export_parser.add_argument("--output", default="blocklist.txt", 
                              help="Output file")
    export_parser.add_argument("--format", choices=["defanged", "normal"], 
                              default="defanged", help="Output format")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    dm = DomainManager(args.db)
    
    if args.command == "add":
        success = dm.add_domain(
            domain=args.domain,
            source=args.source,
            comments=args.comments,
            flags=args.flags,
            date_reported=args.date
        )
        sys.exit(0 if success else 1)
    
    elif args.command == "update":
        update_data = {}
        if args.source is not None:
            update_data['source'] = args.source
        if args.comments is not None:
            update_data['comments'] = args.comments
        if args.flags is not None:
            update_data['flags'] = args.flags
        if args.date is not None:
            update_data['date_reported'] = args.date
        
        if not update_data:
            print("Error: No fields to update")
            sys.exit(1)
        
        success = dm.update_domain(args.domain, **update_data)
        sys.exit(0 if success else 1)
    
    elif args.command == "delete":
        success = dm.delete_domain(args.domain)
        sys.exit(0 if success else 1)
    
    elif args.command == "get":
        domain_info = dm.get_domain(args.domain)
        if domain_info:
            print(f"\nDomain Information:")
            print(f"Domain: {domain_info['domain']}")
            print(f"Source: {domain_info['source']}")
            print(f"Date Reported: {domain_info['date_reported']}")
            print(f"Flags: {domain_info['flags'] or 'None'}")
            print(f"Comments: {domain_info['comments'] or 'None'}")
            print(f"Created: {domain_info['created_at']}")
            print(f"Updated: {domain_info['updated_at']}")
        else:
            print(f"Domain {args.domain} not found")
            sys.exit(1)
    
    elif args.command == "list":
        domains = dm.get_all_domains(args.limit, args.offset)
        print(f"\nFound {len(domains)} domains:")
        print("-" * 80)
        for domain in domains:
            print(f"Domain: {domain['domain']}")
            print(f"Source: {domain['source']}")
            print(f"Date: {domain['date_reported']}")
            print(f"Flags: {domain['flags'] or 'None'}")
            print(f"Comments: {domain['comments'] or 'None'}")
            print(f"Created: {domain['created_at']}")
            print("-" * 80)
    
    elif args.command == "search":
        results = dm.search_domains(args.query, args.field, args.limit)
        print(f"\nFound {len(results)} matching domains:")
        print("-" * 80)
        for domain in results:
            print(f"Domain: {domain['domain']}")
            print(f"Source: {domain['source']}")
            print(f"Date: {domain['date_reported']}")
            print(f"Flags: {domain['flags'] or 'None'}")
            print(f"Comments: {domain['comments'] or 'None'}")
            print("-" * 80)
    
    elif args.command == "stats":
        stats = dm.get_stats()
        print(f"\nDataset Statistics:")
        print(f"Total domains: {stats['total_domains']}")
        print(f"Unique sources: {stats['unique_sources']}")
        print(f"Domains with flags: {stats['domains_with_flags']}")
        print(f"Domains with comments: {stats['domains_with_comments']}")
        
        if stats['flag_counts']:
            print(f"\nFlag counts:")
            for flag, count in sorted(stats['flag_counts'].items()):
                print(f"  {flag}: {count}")
    
    elif args.command == "export-csv":
        success = dm.export_to_csv(args.output)
        sys.exit(0 if success else 1)
    
    elif args.command == "import-csv":
        imported, skipped = dm.import_from_csv(args.csv_file, args.skip_duplicates)
        print(f"Import completed: {imported} imported, {skipped} skipped")
        sys.exit(0)
    
    elif args.command == "export":
        success = dm.export_blocklist(args.output, args.format)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()