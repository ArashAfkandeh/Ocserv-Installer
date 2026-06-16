#!/bin/bash

# ---------- PARSE ARGUMENTS ----------
VERBOSE=false
SSH_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -ssh-only)
            SSH_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

clear
