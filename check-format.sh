#!/bin/bash

if ! git diff --quiet; then
    echo >&2 "There are uncommitted changes in the working directory."
    echo >&2 "Please commit or stash them before running this script."
    exit 1
fi

# Maximum allowed line length
max_line_length=100

directories=("daemon" "tracer" "eavesdropper" "tracer-plug")
file_extensions=(".cpp" ".hpp" ".c" ".h")
files=()

for dir in "${directories[@]}"; do
    for ext in "${file_extensions[@]}"; do
        while IFS= read -r -d $'\0' file; do
            if git ls-files --error-unmatch "$file" &>/dev/null; then
                files+=("$file")
            fi
        done < <(find "$dir" -name "*$ext" -print0)
    done
done

formatting_errors=0

clang-format -i "${files[@]}"

if ! git diff --quiet; then
    echo "The following files are not formatted correctly:"
    git diff --name-only
    git reset --hard HEAD
    formatting_errors=1
fi

for file in "${files[@]}"; do
    # Check if any lines in the file are longer than max_line_length
    if grep -q ".\{$max_line_length\}" "$file"; then
        echo "File $file contains lines longer than $max_line_length characters."
        formatting_errors=1
    fi
done

exit $formatting_errors
