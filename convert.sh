#!/bin/sh

# This script is used to generate a libfuzzer compatible
# source file by adding some functions that invoke
# libfuzzer and appending the original source
# and renaming the source's main function.

autogen=\
'// Start of auto-generated segment

#define main arg_fuzz__real_main

// End of auto-generated segment

'

if [ $# != 1 ]; then
    echo "Usage: ./convert.sh <file>"
    exit 1
fi

path=$(readlink -n -e $1)
new_path=$(echo -n "$path" | sed -E 's/(.*)\.c$/\1\.argfuzz\.c/1')

if [ "$path" == "" ]; then
    echo "File does not exist -- or you don't have GNU readlink installed"
    exit 1
fi

echo -n "$autogen" > "$new_path"
cat "$path" >> "$new_path"
# cat "$new_path" >> "$path"
