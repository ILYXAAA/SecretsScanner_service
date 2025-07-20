#!/usr/bin/env python3
"""
Simple regex tester for rules.yml
"""

import re
import yaml
import os

def load_rules():
    """Load rules from rules.yml file"""
    rules_file = "../Settings/rules.yml"
    
    if not os.path.exists(rules_file):
        print(f"❌ File {rules_file} not found!")
        return None
    
    try:
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)
        
        print(f"✅ Loaded {len(rules)} rules from {rules_file}")
        return rules
    
    except Exception as e:
        print(f"❌ Error loading {rules_file}: {e}")
        return None

def test_string(text, rules):
    """Test string against all rules"""
    matches = []
    
    for rule in rules:
        rule_id = rule.get('id', 'Unknown')
        message = rule.get('message', 'Unknown')
        pattern = rule.get('pattern', '')
        severity = rule.get('severity', 'UNKNOWN')
        
        try:
            if re.search(pattern, text):
                matches.append({
                    'id': rule_id,
                    'message': message,
                    'severity': severity
                })
        except re.error as e:
            print(f"⚠️  Regex error in rule {rule_id}: {e}")
    
    return matches

def main():
    """Main function"""
    print("🔍 Regex Rules Tester")
    print("=" * 40)
    
    # Load rules
    rules = load_rules()
    if not rules:
        return
    
    print("\n📝 Enter strings to test (empty line to exit):")
    print("-" * 40)
    
    while True:
        try:
            # Get input
            text = input("\n> ")
            
            # Exit on empty line
            if not text.strip():
                print("👋 Goodbye!")
                break
            
            # Test string
            matches = test_string(text, rules)
            
            if matches:
                print(f"✅ Found {len(matches)} match(es):")
                for match in matches:
                    print(f"   📋 {match['id']} - {match['message']} ({match['severity']})")
            else:
                print("❌ No matches found")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()