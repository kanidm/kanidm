#!/bin/bash

# Exit if no argument is provided
if [ $# -eq 0 ]; then
    echo "No filename provided"
    exit 1
fi

filename=$1

# Exit if the file doesn't exist
if [ ! -f "${filename}" ]; then
    echo "File ${filename} not found"
    exit 1
fi

original_size_kb=$(du -k "${filename}" | cut -f1)

tmpfile=$(mktemp)

for num in {10..24}
do
    {
        size=$(brotli --lgwin="${num}" -c "${filename}" | wc -c)
        echo "${num} ${size}" >> "${tmpfile}"
    } &
done

# Wait for all background jobs to finish
wait

# Process results
{
    read -r min_num min_size
    while read -r num size; do
        if (( size < min_size )); then
            min_size=$size
            min_num=$num
        fi
    done

    echo "Original size was ${original_size_kb}KB"
    echo "Smallest compressed size was ${min_size} bytes for NUM=${min_num}"
} < "${tmpfile}"

# Clean up
rm "${tmpfile}"

# Use the smallest NUM value found in the test command
brotli --lgwin="${min_num}" "${filename}" -o "${filename}.br"
