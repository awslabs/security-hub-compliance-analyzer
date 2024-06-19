#!/bin/bash

# Check if wget is installed
if ! command -v wget &> /dev/null
then
    echo "wget could not be found. Please install wget and try again."
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install jq and try again."
    exit 1
fi

# Rest of the script
echo "Updating AWS aws-sdk-pandas Lambda Layer"
echo "Getting latest aws-sdk-pandas releases from github"

# Use wget to fetch the latest release information
release_info=$(wget -q --header="Accept: application/vnd.github+json" --header="X-GitHub-Api-Version: 2022-11-28" -O - https://api.github.com/repos/aws/aws-sdk-pandas/releases/latest)

# Check if the wget command was successful
if [ $? -eq 0 ]; then
  download_url=$(echo "$release_info" | jq -r '.assets[] | select(.name | contains("py3.11.zip")) | .browser_download_url')

  # Check if the jq command was successful
  if [ $? -eq 0 ]; then
    filename=$(basename "$download_url")
    download_dir="assets/lambda/layers/awswrangler"

    filename="$download_dir/$filename"

    if ! [ -f "$filename" ]; then
      echo "Downloading latest aws_wrangler layer"
      wget -O "$filename" "$download_url"
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
  else
    echo "Error parsing JSON response from GitHub API"
  fi
else
  echo "Error fetching latest aws-sdk-pandas releases from GitHub"
  echo "HTTP status code: $?"
fi
