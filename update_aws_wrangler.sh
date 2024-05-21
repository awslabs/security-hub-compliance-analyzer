# (c) 2024 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer
# Agreement available at https://aws.amazon.com/agreement or other written
# agreement between Customer and Amazon Web Services, Inc.

#!/bin/bash

echo "Updating AWS aws-sdk-pandas Lambda Layer"
echo "Getting latest aws-sdk-pandas releases from github"
curl_output=$(curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/aws/aws-sdk-pandas/releases/latest)

download_url=$(echo "$curl_output" | jq -r '.assets[] | select(.name | contains("py3.11.zip")) | .browser_download_url')

filename=$(basename "$download_url")
download_dir="assets/lambda/layers/awswrangler"

filename="$download_dir/$filename"

if ! [ -f "$filename" ]; then
  echo "Downloading latest aws_wrangler layer"
  curl -L -o "$filename" "$download_url"
else
  echo "File already exists at $filename"
fi

file_path="stack/shca_stack.py"
echo "Updating $file_path - self.aws_wrangler_layer with $filename"

os_type=$(uname)
if [ "$os_type" == "Darwin" ]; then
  sed -i "" "s|self.aws_wrangler_layer = .*|self.aws_wrangler_layer = \"$filename\"|g" "$file_path"
else
  sed -i "s|self.aws_wrangler_layer = .*|self.aws_wrangler_layer = \"$filename\"|g" "$file_path"
fi
