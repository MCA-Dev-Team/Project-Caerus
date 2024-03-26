#!/bin/bash

# Update package index
sudo apt update

# Install Python3 and Pip
sudo apt install -y python3 python3-pip

# Install Git
sudo apt install -y git

# Display installed versions
echo "Python3 version:"
python3 --version

echo "Pip version:"
pip3 --version

echo "Git version:"
git --version

test:

