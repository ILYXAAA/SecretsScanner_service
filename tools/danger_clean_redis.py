#!/usr/bin/env python3
"""
DANGER: Redis Clean Script

This script completely wipes ALL data from Redis.
Use ONLY when making breaking changes to Redis data structure.

Usage: python danger_clean_redis.py
"""

import redis
import os
import sys
from dotenv import load_dotenv

def confirm_cleanup():
    """Ask for user confirmation before cleanup"""
    print("⚠️  DANGER: This will DELETE ALL data in Redis!")
    print("⚠️  This action is IRREVERSIBLE!")
    print("⚠️  All tasks, workers, and statistics will be lost!")
    print()
    
    response = input("Type 'DELETE_ALL_REDIS_DATA' to confirm: ").strip()
    
    if response != "DELETE_ALL_REDIS_DATA":
        print("❌ Cleanup cancelled. Wrong confirmation text.")
        return False
    
    # Double confirmation
    print()
    print("🔥 Are you ABSOLUTELY sure?")
    final_response = input("Type 'YES' to proceed with cleanup: ").strip().upper()
    
    return final_response == "YES"

def cleanup_redis():
    """Perform complete Redis cleanup"""
    load_dotenv()
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    try:
        # Connect to Redis
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        print(f"✅ Connected to Redis: {redis_url}")
        
    except Exception as e:
        print(f"❌ Failed to connect to Redis: {e}")
        return False
    
    try:
        # Get initial key count
        initial_keys = redis_client.dbsize()
        print(f"📊 Found {initial_keys} keys in Redis")
        
        if initial_keys == 0:
            print("✅ Redis is already empty")
            return True
        
        # Perform cleanup
        print("🔥 Starting Redis cleanup...")
        redis_client.flushdb()
        
        # Verify cleanup
        final_keys = redis_client.dbsize()
        
        if final_keys == 0:
            print(f"✅ Redis cleanup completed successfully!")
            print(f"📊 Removed {initial_keys} keys")
            return True
        else:
            print(f"⚠️  Cleanup incomplete. {final_keys} keys remaining")
            return False
            
    except Exception as e:
        print(f"❌ Error during Redis cleanup: {e}")
        return False

def main():
    """Main function"""
    print("🧹 Redis Complete Cleanup Tool")
    print("=" * 40)
    
    # Check confirmation
    if not confirm_cleanup():
        print("✅ Cleanup cancelled by user")
        sys.exit(0)
    
    # Perform cleanup
    success = cleanup_redis()
    
    if success:
        print()
        print("🎉 Redis cleanup completed successfully!")
        print("💡 You can now restart your application with clean Redis state")
        sys.exit(0)
    else:
        print()
        print("❌ Redis cleanup failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()