#!/bin/bash

set -e

if [[ ! -d "test_data" ]]; then
  echo "test_data not present. downloading it.."
  wget https://github.com/eciavatta/sdhash/releases/download/initial-release/test_data.zip
  unzip test_data.zip
  rm test_data.zip
fi

echo "aaa"


