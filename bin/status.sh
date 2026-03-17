#!/usr/bin/env bash


CONFIG_FILE="functions.json"

FUNCTIONS=$(jq -r --arg ID "$FUNCTION_ID" '.[] | .id' "$CONFIG_FILE")

REVISIONS=""

for FNC in $FUNCTIONS; do

  REGION=$(jq -r --arg ID "$FNC" '.[] | select(.id == $ID) | .region' "$CONFIG_FILE")
  
  if [ -z "$REGION" ]; then
    echo "Error: Configuration region for $FNC not found."
    exit 1
  fi
  
  printf "%s\t%s\t" $FNC $REGION

  if OUTPUT=$(gcloud functions describe $FNC --region=$REGION 2>&1); then
    # Extraction logic if command succeeded
    availableCpu=$(echo "$OUTPUT" | grep -oP 'availableCpu:\s+'\''?\K[^'\''\s]+')
    availableMemory=$(echo "$OUTPUT" | grep -oP 'availableMemory:\s+\K\S+')
    uri=$(echo "$OUTPUT" | grep -oP 'uri:\s+\K\S+')
    state=$(echo "$OUTPUT" | grep -oP '^state:\s+\K\S+')
    
    REVISIONS+="${REGION}|${REV}"$'\n'
      
    printf "%s\t%s\t%s CPU  %s\n" $state $uri $availableCpu $availableMemory
  else
    # Logic if command failed (e.g., 404)
    printf "N/A\n"
  fi
done

