#!/usr/bin/env python3
"""
Migration script to convert CSV-based domain datasets to SQLite format.
This script helps users migrate from the old CSV-based system to the new SQLite system.
"""

import csv
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime
from domain_manager import DomainManager


def migrate_csv_to_sqlite(csv_file: str, db_file: str = "malicious_domains.db", 
                         skip_duplicates: bool = True) -> tuple[int, int]:
    """
    Migrate domains from CSV file to SQLite database.
    
    Args:
        csv_file: Path to CSV file to migrate
        db_file: Path to SQLite database file
        skip_duplicates: Whether to skip duplicate domains
        
    Returns:
        Tuple of (imported_count, skipped_count)
    """
    csv_path = Path(csv_file)
    if not csv_path.exists():
        print(f"Error: CSV file {csv_file} not found")
        return 0, 0
    
    # Initialize domain manager
    dm = DomainManager(db_file)
    
    imported_count = 0
    skipped_count = 0
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Check if required columns exist
            required_columns = ['domain', 'source']
            if not all(col in reader.fieldnames for col in required_columns):
                print(f"Error: CSV file must contain columns: {', '.join(required_columns)}")
                print(f"Found columns: {', '.join(reader.fieldnames)}")
                return 0, 0
            
            print(f"Migrating domains from {csv_file} to {db_file}...")
            
            for row_num, row in enumerate(reader, 1):
                domain = row.get('domain', '').strip()
                source = row.get('source', '').strip()
                date_reported = row.get('date_reported', '').strip()
                comments = row.get('comments', '').strip()
                flags = row.get('flags', '').strip()
                
                if not domain or not source:
                    print(f"Row {row_num}: Skipping - missing domain or source")
                    skipped_count += 1
                    continue
                
                # Check for duplicates
                if skip_duplicates and dm.domain_exists(domain):
                    print(f"Row {row_num}: Skipping duplicate domain {domain}")
                    skipped_count += 1
                    continue
                
                # Add domain
                if dm.add_domain(domain, source, comments, flags, date_reported):
                    imported_count += 1
                    if imported_count % 100 == 0:
                        print(f"Imported {imported_count} domains...")
                else:
                    skipped_count += 1
                    print(f"Row {row_num}: Failed to add domain {domain}")
        
        print(f"\nMigration completed:")
        print(f"✅ Successfully imported: {imported_count}")
        print(f"⚠️  Skipped: {skipped_count}")
        
    except Exception as e:
        print(f"Error during migration: {e}")
    
    return imported_count, skipped_count


def backup_csv_file(csv_file: str) -> str:
    """
    Create a backup of the CSV file before migration.
    
    Args:
        csv_file: Path to CSV file to backup
        
    Returns:
        Path to backup file
    """
    csv_path = Path(csv_file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"{csv_path.stem}_backup_{timestamp}{csv_path.suffix}"
    
    try:
        import shutil
        shutil.copy2(csv_file, backup_file)
        print(f"Created backup: {backup_file}")
        return backup_file
    except Exception as e:
        print(f"Warning: Could not create backup: {e}")
        return ""


def verify_migration(csv_file: str, db_file: str) -> bool:
    """
    Verify that the migration was successful by comparing record counts.
    
    Args:
        csv_file: Path to original CSV file
        db_file: Path to SQLite database file
        
    Returns:
        True if migration appears successful, False otherwise
    """
    try:
        # Count CSV records
        csv_count = 0
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            csv_count = sum(1 for row in reader if row.get('domain', '').strip() and row.get('source', '').strip())
        
        # Count SQLite records
        dm = DomainManager(db_file)
        stats = dm.get_stats()
        db_count = stats['total_domains']
        
        print(f"\nVerification:")
        print(f"CSV records: {csv_count}")
        print(f"SQLite records: {db_count}")
        
        if csv_count == db_count:
            print("✅ Migration verification successful!")
            return True
        else:
            print("⚠️  Record count mismatch - some records may not have been migrated")
            return False
            
    except Exception as e:
        print(f"Error during verification: {e}")
        return False


def main():
    """Command-line interface for the migration script."""
    parser = argparse.ArgumentParser(description="Migrate CSV domain dataset to SQLite")
    parser.add_argument("csv_file", help="CSV file to migrate")
    parser.add_argument("--db", default="malicious_domains.db", 
                       help="SQLite database file (default: malicious_domains.db)")
    parser.add_argument("--no-skip-duplicates", action="store_true",
                       help="Don't skip duplicate domains (may cause errors)")
    parser.add_argument("--no-backup", action="store_true",
                       help="Don't create backup of CSV file")
    parser.add_argument("--verify", action="store_true",
                       help="Verify migration after completion")
    
    args = parser.parse_args()
    
    # Check if CSV file exists
    if not Path(args.csv_file).exists():
        print(f"Error: CSV file {args.csv_file} not found")
        return 1
    
    # Check if database already exists
    if Path(args.db).exists():
        response = input(f"Database {args.db} already exists. Continue? (y/N): ").strip().lower()
        if response != 'y':
            print("Migration cancelled.")
            return 0
    
    # Create backup unless disabled
    if not args.no_backup:
        backup_file = backup_csv_file(args.csv_file)
    
    # Perform migration
    print(f"\nStarting migration from {args.csv_file} to {args.db}")
    skip_duplicates = not args.no_skip_duplicates
    
    imported, skipped = migrate_csv_to_sqlite(args.csv_file, args.db, skip_duplicates)
    
    # Verify migration if requested
    if args.verify:
        verify_migration(args.csv_file, args.db)
    
    # Show final statistics
    dm = DomainManager(args.db)
    stats = dm.get_stats()
    
    print(f"\nFinal database statistics:")
    print(f"Total domains: {stats['total_domains']}")
    print(f"Unique sources: {stats['unique_sources']}")
    print(f"Domains with flags: {stats['domains_with_flags']}")
    print(f"Domains with comments: {stats['domains_with_comments']}")
    
    if stats['flag_counts']:
        print(f"\nFlag counts:")
        for flag, count in sorted(stats['flag_counts'].items()):
            print(f"  {flag}: {count}")
    
    print(f"\nMigration completed successfully!")
    print(f"You can now use the SQLite-based domain manager:")
    print(f"  python3 domain_manager.py --db {args.db} stats")
    print(f"  python3 add_domain.py")
    
    return 0


if __name__ == "__main__":
    exit(main())
