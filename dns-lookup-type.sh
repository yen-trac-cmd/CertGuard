#!/bin/bash

# Script to perform a dig lookup for a specified record type
# for each domain in a file.

# Check if both file and record type are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <path_to_domain_list> <record_type>"
    echo "Example: $0 domains.txt MX"
    exit 1
fi

DOMAIN_FILE="$1"
RECORD_TYPE="$2"

if [ ! -f "$DOMAIN_FILE" ]; then
    echo "Error: File '$DOMAIN_FILE' not found!"
    exit 1
fi

echo "Starting DNS lookup for $RECORD_TYPE records from $DOMAIN_FILE"

while IFS= read -r domain; do
    if [ -z "$domain" ]; then
        continue
    fi

    echo "Processing domain: $domain ($RECORD_TYPE record)"
    dig @8.8.8.8 +short "$domain" "$RECORD_TYPE"
    echo ""

done < "$DOMAIN_FILE"

echo "DNS lookup complete."
