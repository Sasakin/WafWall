#!/bin/bash
# Build all Java services

echo "Building WAF services..."

# Build common module first
echo "Building common module..."
./gradlew :common:build -q

# Build gateway
echo "Building gateway..."
./gradlew :gateway:build -q

# Build processor
echo "Building processor..."
./gradlew :processor:build -q

# Build alert
echo "Building alert..."
./gradlew :alert:build -q

echo "Build complete!"
echo "JAR files:"
ls -la gateway/build/libs/ 2>/dev/null || echo "gateway: not found"
ls -la processor/build/libs/ 2>/dev/null || echo "processor: not found"
ls -la alert/build/libs/ 2>/dev/null || echo "alert: not found"