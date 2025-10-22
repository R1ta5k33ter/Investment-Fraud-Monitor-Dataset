#!/usr/bin/env python3
"""
Example script demonstrating the DomainManager functionality.
This script shows how to use the domain management system programmatically.
"""

from domain_manager import DomainManager
from datetime import datetime


def main():
    """Demonstrate DomainManager functionality with example data."""
    print("=== DomainManager SQLite Example ===\n")
    
    # Initialize the domain manager with SQLite
    dm = DomainManager("example_domains.db")
    
    # Example malicious domains to add
    example_domains = [
        {
            "domain": "fake-bank.com",
            "source": "https://virustotal.com/gui/domain/fake-bank.com",
            "comments": "Phishing site impersonating major bank",
            "flags": "phishing;scam"
        },
        {
            "domain": "malware-distro.net",
            "source": "https://virustotal.com/gui/domain/malware-distro.net",
            "comments": "Known malware distribution site",
            "flags": "malware;c2"
        },
        {
            "domain": "crypto-scam.org",
            "source": "https://virustotal.com/gui/domain/crypto-scam.org",
            "comments": "Cryptocurrency investment scam",
            "flags": "scam;cryptocurrency;investment"
        },
        {
            "domain": "botnet-c2.info",
            "source": "https://virustotal.com/gui/domain/botnet-c2.info",
            "comments": "Botnet command and control server",
            "flags": "botnet;c2"
        }
    ]
    
    print("Adding example domains...")
    for domain_data in example_domains:
        success = dm.add_domain(
            domain_data["domain"],
            domain_data["source"],
            domain_data["comments"],
            domain_data["flags"]
        )
        if success:
            print(f"✅ Added: {domain_data['domain']}")
        else:
            print(f"❌ Failed to add: {domain_data['domain']}")
    
    print("\n" + "="*50)
    
    # Show statistics
    print("Dataset Statistics:")
    stats = dm.get_stats()
    print(f"Total domains: {stats['total_domains']}")
    print(f"Unique sources: {stats['unique_sources']}")
    print(f"Domains with flags: {stats['domains_with_flags']}")
    print(f"Domains with comments: {stats['domains_with_comments']}")
    
    if stats['flag_counts']:
        print(f"\nFlag counts:")
        for flag, count in sorted(stats['flag_counts'].items()):
            print(f"  {flag}: {count}")
    
    print("\n" + "="*50)
    
    # Search examples
    print("Search Examples:")
    
    # Search for phishing domains
    phishing_results = dm.search_domains("phishing", "flags")
    print(f"\nPhishing domains found: {len(phishing_results)}")
    for domain in phishing_results:
        print(f"  - {domain['domain']} ({domain['flags']})")
    
    # Search for domains with "bank" in comments
    bank_results = dm.search_domains("bank", "comments")
    print(f"\nDomains with 'bank' in comments: {len(bank_results)}")
    for domain in bank_results:
        print(f"  - {domain['domain']}: {domain['comments']}")
    
    print("\n" + "="*50)
    
    # Export examples
    print("Export Examples:")
    
    # Export to CSV
    if dm.export_to_csv("example_domains_export.csv"):
        print("✅ Exported to CSV")
    
    # Export defanged domains
    if dm.export_blocklist("example_blocklist_defanged.txt", "defanged"):
        print("✅ Exported defanged blocklist")
    
    # Export normal domains
    if dm.export_blocklist("example_blocklist_normal.txt", "normal"):
        print("✅ Exported normal blocklist")
    
    print("\n" + "="*50)
    
    # Show all domains
    print("All domains in dataset:")
    all_domains = dm.get_all_domains()
    for i, domain in enumerate(all_domains, 1):
        print(f"{i}. {domain['domain']}")
        print(f"   Source: {domain['source']}")
        print(f"   Date: {domain['date_reported']}")
        print(f"   Flags: {domain['flags'] or 'None'}")
        print(f"   Comments: {domain['comments'] or 'None'}")
        print()
    
    # Demonstrate update functionality
    print("\n" + "="*50)
    print("Demonstrating update functionality:")
    
    # Update a domain
    update_success = dm.update_domain("fake-bank.com", 
                                     comments="Updated: Confirmed phishing site",
                                     flags="phishing;scam;confirmed")
    if update_success:
        print("✅ Successfully updated fake-bank.com")
    
    # Show updated domain
    updated_domain = dm.get_domain("fake-bank.com")
    if updated_domain:
        print(f"Updated domain info:")
        print(f"  Comments: {updated_domain['comments']}")
        print(f"  Flags: {updated_domain['flags']}")
        print(f"  Last Updated: {updated_domain['updated_at']}")
    
    print("\n" + "="*50)
    print("Example completed! Check the generated files:")
    print("- example_domains.db (SQLite database)")
    print("- example_domains_export.csv (CSV export)")
    print("- example_blocklist_defanged.txt (defanged domains)")
    print("- example_blocklist_normal.txt (normal domains)")


if __name__ == "__main__":
    main()
