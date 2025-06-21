#!/bin/bash

# Create directory structure
mkdir -p src/main/java/com/contrastsecurity/deptrast/api
mkdir -p src/main/java/com/contrastsecurity/deptrast/model
mkdir -p src/main/java/com/contrastsecurity/deptrast/service
mkdir -p src/main/java/com/contrastsecurity/deptrast/util

# Move files and update package statements
for file in $(find src/main/java/com/deptrast -name "*.java"); do
    new_file=$(echo $file | sed 's/com\/deptrast/com\/contrastsecurity\/deptrast/')
    sed -i '' 's/package com\.deptrast/package com.contrastsecurity.deptrast/g' $file
    cp $file $new_file
done

# Update import statements in all files
for file in $(find src/main/java/com/contrastsecurity/deptrast -name "*.java"); do
    sed -i '' 's/import com\.deptrast\./import com.contrastsecurity.deptrast./g' $file
done

echo "Files updated and moved to new package structure"