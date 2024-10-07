#!/bin/bash

set -e
set -o pipefail

# Variables - Customize these based on your project
PROJECT_NAME="nfclib"
SCHEME_NAME="nfclib" # Replace with your scheme name
OUTPUT_DIR="${PWD}/build" # Output directory
CONFIGURATION="Debug" # Use `Debug` or `Release` based on your requirement
PROJECT_PATH="${PWD}/${PROJECT_NAME}.xcodeproj"
BUILD_DIR="${HOME}/Library/Developer/Xcode/DerivedData/${PROJECT_NAME}/Build/Products" # Add BUILD_DIR definition

# Define universal output folder
UNIVERSAL_OUTPUTFOLDER="${OUTPUT_DIR}/${CONFIGURATION}-universal"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "$UNIVERSAL_OUTPUTFOLDER" "$BUILD_DIR/${CONFIGURATION}-iphoneos" "$BUILD_DIR/${CONFIGURATION}-iphonesimulator"

# Step 1: Build for iOS devices and simulators
echo "Building for iOS devices and simulators..."
for destination in "generic/platform=iOS" "generic/platform=iOS Simulator"; do
  xcodebuild ONLY_ACTIVE_ARCH=NO \
    -project "${PROJECT_PATH}" \
    -scheme "${SCHEME_NAME}" \
    -configuration "${CONFIGURATION}" \
    -destination "${destination}" \
    -derivedDataPath "${HOME}/Library/Developer/Xcode/DerivedData/nfclib" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    OTHER_SWIFT_FLAGS="-no-verify-emitted-module-interface"
done

# Make sure the output directory exists
mkdir -p "${UNIVERSAL_OUTPUTFOLDER}"

# Ensure the documentation directory exists before copying
if [ -d "${PROJECT_DIR}/../doc" ]; then
    cp -R "${PROJECT_DIR}/../doc" "${UNIVERSAL_OUTPUTFOLDER}/"
else
    echo "Documentation directory not found: ${PROJECT_DIR}/../doc"
fi

# Step 2. Create multiplatform binary framework bundle
echo "Creating .xcframework..."
xcodebuild -create-xcframework \
  -framework  "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${PROJECT_NAME}.framework" \
  -framework "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${PROJECT_NAME}.framework" \
  -output "${UNIVERSAL_OUTPUTFOLDER}/${PROJECT_NAME}.xcframework"

# Step 3: Output the result
echo "Created ${PROJECT_NAME}.xcframework at ${UNIVERSAL_OUTPUTFOLDER}"
