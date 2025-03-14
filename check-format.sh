#!/bin/bash

# SPDX-License-Identifier: MIT

fix_flag=false

while [ $# -gt 0 ]; do
    case $1 in
    -f | --fix)
        fix_flag=true
        ;;
    *)
        echo "Usage: $(basename "$0") [-f|--fix]"
        exit 1
        ;;
    esac
    shift
done

if ! $fix_flag && ! git diff --quiet; then
    echo >&2 "There are uncommitted changes in the working directory."
    echo >&2 "Please commit or stash them before running this script."
    exit 1
fi

# Maximum allowed line length
max_line_length=100

directories=("daemon" "tracer")
file_extensions=(".cpp" ".hpp" ".c" ".h")
files=()
cmakelists=()

for dir in "${directories[@]}"; do
    for ext in "${file_extensions[@]}"; do
        while IFS= read -r -d $'\0' file; do
            if git ls-files --error-unmatch "$file" &>/dev/null; then
                files+=("$file")
            fi
        done < <(find "$dir" -name "*$ext" -print0)
    done

    while IFS= read -r -d $'\0' file; do
        if git ls-files --error-unmatch "$file" &>/dev/null; then
            cmakelists+=("$file")
        fi
    done < <(find "$dir" -name "CMakeLists.txt" -print0)
done

formatting_errors=0

clang-format -i "${files[@]}"

if ! $fix_flag && ! git diff --quiet; then
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

for cmakelist in "${cmakelists[@]}"; do
    if grep -Ewq '[[:alnum:]]*\.h(|pp)' "$cmakelist"; then
        echo "Header file encountered in $cmakelist"
        formatting_errors=1
    fi
done

exit $formatting_errors
