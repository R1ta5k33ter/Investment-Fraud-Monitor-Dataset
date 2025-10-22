#!/usr/bin/env python3
"""
Interactive script for managing malicious domains with SQLite database.
This provides a user-friendly way to add, update, and manage domains.
"""

from domain_manager import DomainManager
import sys
from datetime import datetime


def interactive_add_domain():
    """Interactive domain addition with guided prompts."""
    print("=== Malicious Domain Addition Tool ===")
    print("This tool will help you add a new malicious domain to the dataset.\n")
    
    dm = DomainManager()
    
    # Get domain
    while True:
        domain = input("Enter the malicious domain (e.g., example.com): ").strip()
        if not domain:
            print("Domain cannot be empty. Please try again.")
            continue
        
        if not dm.validate_domain(domain):
            print(f"Invalid domain format: {domain}")
            print("Please enter a valid domain (e.g., example.com)")
            continue
        
        if dm.domain_exists(domain):
            print(f"Domain {domain} already exists in the dataset.")
            overwrite = input("Do you want to continue anyway? (y/N): ").strip().lower()
            if overwrite != 'y':
                continue
        
        break
    
    # Get source
    while True:
        source = input("Enter the source URL (e.g., VirusTotal link): ").strip()
        if not source:
            print("Source cannot be empty. Please try again.")
            continue
        break
    
    # Get comments (optional)
    comments = input("Enter comments (optional): ").strip()
    
    # Get flags (optional)
    print("\nCommon flags include: phishing, botnet, c2, malware, spam, scam")
    print("Enter flags separated by semicolons (e.g., phishing;botnet)")
    flags = input("Enter flags (optional): ").strip()
    
    # Get date (optional)
    print(f"\nDefault date: {datetime.now().strftime('%Y-%m-%d')}")
    date_input = input("Enter date reported (YYYY-MM-DD) or press Enter for today: ").strip()
    date_reported = date_input if date_input else None
    
    # Show summary
    print(f"\n=== Summary ===")
    print(f"Domain: {dm.defang_domain(domain)}")
    print(f"Source: {source}")
    print(f"Comments: {comments or 'None'}")
    print(f"Flags: {flags or 'None'}")
    print(f"Date: {date_reported or datetime.now().strftime('%Y-%m-%d')}")
    
    # Confirm
    confirm = input("\nAdd this domain to the dataset? (Y/n): ").strip().lower()
    if confirm in ['', 'y', 'yes']:
        success = dm.add_domain(domain, source, comments, flags, date_reported)
        if success:
            print("✅ Domain successfully added!")
        else:
            print("❌ Failed to add domain.")
            sys.exit(1)
    else:
        print("❌ Domain addition cancelled.")


def batch_add_domains():
    """Add multiple domains from a text file."""
    print("=== Batch Domain Addition ===")
    print("This tool allows you to add multiple domains from a text file.")
    print("Each line should contain: domain,source_url,comments,flags,date_reported")
    print("Example: example.com,https://virustotal.com/example,Malicious site,phishing;botnet,2024-01-15")
    print("Note: date_reported is optional (will use today's date if not provided)\n")
    
    file_path = input("Enter path to text file: ").strip()
    if not file_path:
        print("No file path provided.")
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    dm = DomainManager()
    added_count = 0
    error_count = 0
    
    print(f"\nProcessing {len(lines)} lines...")
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):  # Skip empty lines and comments
            continue
        
        parts = [part.strip() for part in line.split(',')]
        if len(parts) < 2:
            print(f"Line {i}: Invalid format (need at least domain,source)")
            error_count += 1
            continue
        
        domain = parts[0]
        source = parts[1]
        comments = parts[2] if len(parts) > 2 else ""
        flags = parts[3] if len(parts) > 3 else ""
        date_reported = parts[4] if len(parts) > 4 else None
        
        if dm.add_domain(domain, source, comments, flags, date_reported):
            added_count += 1
        else:
            error_count += 1
    
    print(f"\nBatch addition complete:")
    print(f"✅ Successfully added: {added_count}")
    print(f"❌ Errors: {error_count}")


def interactive_update_domain():
    """Interactive domain update with guided prompts."""
    print("=== Domain Update Tool ===")
    print("This tool will help you update an existing domain in the dataset.\n")
    
    dm = DomainManager()
    
    # Get domain to update
    while True:
        domain = input("Enter the domain to update: ").strip()
        if not domain:
            print("Domain cannot be empty. Please try again.")
            continue
        
        # Check if domain exists
        domain_info = dm.get_domain(domain)
        if not domain_info:
            print(f"Domain {domain} not found in dataset.")
            continue_choice = input("Do you want to try another domain? (y/N): ").strip().lower()
            if continue_choice != 'y':
                return
            continue
        
        print(f"\nCurrent information for {domain_info['domain']}:")
        print(f"Source: {domain_info['source']}")
        print(f"Comments: {domain_info['comments'] or 'None'}")
        print(f"Flags: {domain_info['flags'] or 'None'}")
        print(f"Date Reported: {domain_info['date_reported']}")
        break
    
    # Get updates
    update_data = {}
    
    print(f"\nEnter new values (press Enter to keep current value):")
    
    new_source = input(f"New source URL [{domain_info['source']}]: ").strip()
    if new_source:
        update_data['source'] = new_source
    
    new_comments = input(f"New comments [{domain_info['comments'] or 'None'}]: ").strip()
    if new_comments:
        update_data['comments'] = new_comments
    
    new_flags = input(f"New flags [{domain_info['flags'] or 'None'}]: ").strip()
    if new_flags:
        update_data['flags'] = new_flags
    
    new_date = input(f"New date reported [{domain_info['date_reported']}]: ").strip()
    if new_date:
        update_data['date_reported'] = new_date
    
    if not update_data:
        print("No changes made.")
        return
    
    # Show summary
    print(f"\n=== Update Summary ===")
    for field, value in update_data.items():
        print(f"{field}: {value}")
    
    # Confirm
    confirm = input("\nUpdate this domain? (Y/n): ").strip().lower()
    if confirm in ['', 'y', 'yes']:
        success = dm.update_domain(domain, **update_data)
        if success:
            print("✅ Domain successfully updated!")
        else:
            print("❌ Failed to update domain.")
    else:
        print("❌ Domain update cancelled.")


def interactive_delete_domain():
    """Interactive domain deletion with confirmation."""
    print("=== Domain Deletion Tool ===")
    print("This tool will help you delete a domain from the dataset.\n")
    
    dm = DomainManager()
    
    # Get domain to delete
    while True:
        domain = input("Enter the domain to delete: ").strip()
        if not domain:
            print("Domain cannot be empty. Please try again.")
            continue
        
        # Check if domain exists
        domain_info = dm.get_domain(domain)
        if not domain_info:
            print(f"Domain {domain} not found in dataset.")
            continue_choice = input("Do you want to try another domain? (y/N): ").strip().lower()
            if continue_choice != 'y':
                return
            continue
        
        print(f"\nDomain information:")
        print(f"Domain: {domain_info['domain']}")
        print(f"Source: {domain_info['source']}")
        print(f"Comments: {domain_info['comments'] or 'None'}")
        print(f"Flags: {domain_info['flags'] or 'None'}")
        print(f"Date Reported: {domain_info['date_reported']}")
        break
    
    # Confirm deletion
    confirm = input(f"\n⚠️  Are you sure you want to delete {domain_info['domain']}? (y/N): ").strip().lower()
    if confirm == 'y':
        success = dm.delete_domain(domain)
        if success:
            print("✅ Domain successfully deleted!")
        else:
            print("❌ Failed to delete domain.")
    else:
        print("❌ Domain deletion cancelled.")


def interactive_get_domain():
    """Interactive domain retrieval."""
    print("=== Domain Information Tool ===")
    print("This tool will help you view detailed information about a domain.\n")
    
    dm = DomainManager()
    
    domain = input("Enter the domain to view: ").strip()
    if not domain:
        print("Domain cannot be empty.")
        return
    
    domain_info = dm.get_domain(domain)
    if domain_info:
        print(f"\n=== Domain Information ===")
        print(f"Domain: {domain_info['domain']}")
        print(f"Source: {domain_info['source']}")
        print(f"Date Reported: {domain_info['date_reported']}")
        print(f"Flags: {domain_info['flags'] or 'None'}")
        print(f"Comments: {domain_info['comments'] or 'None'}")
        print(f"Created: {domain_info['created_at']}")
        print(f"Last Updated: {domain_info['updated_at']}")
    else:
        print(f"Domain {domain} not found in dataset.")


def main():
    """Main interactive menu."""
    while True:
        print("\n=== Malicious Domain Manager (SQLite) ===")
        print("1. Add single domain (interactive)")
        print("2. Add multiple domains (batch)")
        print("3. Update existing domain")
        print("4. Delete domain")
        print("5. View domain information")
        print("6. View dataset statistics")
        print("7. Search domains")
        print("8. Export to CSV")
        print("9. Import from CSV")
        print("10. Export blocklist")
        print("11. Exit")
        
        choice = input("\nSelect an option (1-11): ").strip()
        
        if choice == '1':
            interactive_add_domain()
        elif choice == '2':
            batch_add_domains()
        elif choice == '3':
            interactive_update_domain()
        elif choice == '4':
            interactive_delete_domain()
        elif choice == '5':
            interactive_get_domain()
        elif choice == '6':
            dm = DomainManager()
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
        elif choice == '7':
            query = input("Enter search query: ").strip()
            if query:
                print("Search options:")
                print("1. Search all fields (default)")
                print("2. Search specific field")
                
                search_option = input("Choose option (1/2) [1]: ").strip()
                
                dm = DomainManager()
                
                if search_option == '2':
                    field = input("Search field (domain/source/comments/flags): ").strip().lower()
                    if field not in ['domain', 'source', 'comments', 'flags']:
                        print("Invalid field, searching all fields instead")
                        field = 'all'
                    else:
                        results = dm.search_domains(query, field)
                else:
                    # Search all fields
                    all_results = []
                    for search_field in ['domain', 'source', 'comments', 'flags']:
                        field_results = dm.search_domains(query, search_field)
                        all_results.extend(field_results)
                    
                    # Remove duplicates based on domain
                    seen_domains = set()
                    unique_results = []
                    for result in all_results:
                        if result['domain'] not in seen_domains:
                            unique_results.append(result)
                            seen_domains.add(result['domain'])
                    
                    results = unique_results
                
                print(f"\nFound {len(results)} matching domains:")
                for domain in results:
                    print(f"- {domain['domain']} ({domain['flags'] or 'no flags'})")
        elif choice == '8':
            dm = DomainManager()
            output_file = input("Output CSV file [malicious_domains_export.csv]: ").strip()
            if not output_file:
                output_file = "malicious_domains_export.csv"
            
            success = dm.export_to_csv(output_file)
            if success:
                print(f"✅ Dataset exported to {output_file}")
        elif choice == '9':
            csv_file = input("Enter CSV file path to import: ").strip()
            if csv_file:
                skip_duplicates = input("Skip duplicate domains? (Y/n): ").strip().lower()
                skip_duplicates = skip_duplicates in ['', 'y', 'yes']
                
                dm = DomainManager()
                imported, skipped = dm.import_from_csv(csv_file, skip_duplicates)
                print(f"Import completed: {imported} imported, {skipped} skipped")
        elif choice == '10':
            dm = DomainManager()
            format_type = input("Export format (defanged/normal) [defanged]: ").strip().lower()
            if format_type not in ['defanged', 'normal']:
                format_type = 'defanged'
            
            output_file = input("Output file [blocklist.txt]: ").strip()
            if not output_file:
                output_file = "blocklist.txt"
            
            success = dm.export_blocklist(output_file, format_type)
            if success:
                print(f"✅ Blocklist exported to {output_file}")
        elif choice == '11':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1-11.")


if __name__ == "__main__":
    main()
