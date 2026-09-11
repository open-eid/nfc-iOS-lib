#!/bin/bash

set -e
set -o pipefail

# Variables - Customize these based on your project
PROJECT_NAME="nfclib"
SCHEME_NAME="nfclib" # Replace with your scheme name
OUTPUT_DIR="${PWD}/build" # Output directory
PROJECT_PATH="${PWD}/${PROJECT_NAME}.xcodeproj"
DERIVED_DATA="${HOME}/Library/Developer/Xcode/DerivedData/${PROJECT_NAME}"
BUILD_DIR="${DERIVED_DATA}/Build/Products"

# The device slice is what ships, so it is optimized; the simulator slice stays
# debuggable for day-to-day development. Override either from the environment, e.g.
#   DEVICE_CONFIGURATION=Debug ./build_xcframework.sh
SIMULATOR_CONFIGURATION="${SIMULATOR_CONFIGURATION:-Debug}"
DEVICE_CONFIGURATION="${DEVICE_CONFIGURATION:-Release}"

# Define universal output folder
UNIVERSAL_OUTPUTFOLDER="${OUTPUT_DIR}/universal"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "${UNIVERSAL_OUTPUTFOLDER}" \
       "${BUILD_DIR}/${DEVICE_CONFIGURATION}-iphoneos" \
       "${BUILD_DIR}/${SIMULATOR_CONFIGURATION}-iphonesimulator"

# Step 1: Build each slice with its own configuration
build_slice() {
  local destination="$1"
  local configuration="$2"

  echo "Building ${configuration} for ${destination}..."
  xcodebuild ONLY_ACTIVE_ARCH=NO \
    -project "${PROJECT_PATH}" \
    -scheme "${SCHEME_NAME}" \
    -configuration "${configuration}" \
    -destination "${destination}" \
    -derivedDataPath "${DERIVED_DATA}" \
    SKIP_INSTALL=NO
}

build_slice "generic/platform=iOS" "${DEVICE_CONFIGURATION}"
build_slice "generic/platform=iOS Simulator" "${SIMULATOR_CONFIGURATION}"

# Make sure the output directory exists
mkdir -p "${UNIVERSAL_OUTPUTFOLDER}"

# Copy the repo-root docs next to the .xcframework (not into it).
# Note: this used to point at "${PROJECT_DIR}/../doc", which is unset outside Xcode and
# resolved to "/../doc", so it always silently skipped.
DOCS_DIR="$(cd "${PWD}/../.." && pwd)/docs"
if [ -d "${DOCS_DIR}" ]; then
    echo "Copying documentation from ${DOCS_DIR}..."
    cp -R "${DOCS_DIR}" "${UNIVERSAL_OUTPUTFOLDER}/"
else
    echo "Documentation directory not found: ${DOCS_DIR}"
fi

# Step 2. Create multiplatform binary framework bundle
echo "Creating .xcframework..."
xcodebuild -create-xcframework \
  -framework "${BUILD_DIR}/${DEVICE_CONFIGURATION}-iphoneos/${PROJECT_NAME}.framework" \
  -framework "${BUILD_DIR}/${SIMULATOR_CONFIGURATION}-iphonesimulator/${PROJECT_NAME}.framework" \
  -output "${UNIVERSAL_OUTPUTFOLDER}/${PROJECT_NAME}.xcframework"

# Step 3: Output the result
echo "Created ${PROJECT_NAME}.xcframework at ${UNIVERSAL_OUTPUTFOLDER}"
echo "  device slice:    ${DEVICE_CONFIGURATION}"
echo "  simulator slice: ${SIMULATOR_CONFIGURATION}"
