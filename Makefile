all:
	xcrun -sdk iphoneos clang -arch armv7 -arch arm64 -arch armv7k nvram_patcher.c -o nvram_patcher
	ldid -Sent.plist nvram_patcher

iphoneos:
	xcrun -sdk iphoneos clang -arch armv7 -arch arm64 nvram_patcher.c -o nvram_patcher
	ldid -Sent.plist nvram_patcher

watchos:
	xcrun -sdk watchos clang -arch armv7k nvram_patcher.c -o nvram_patcher
	ldid -Sent.plist nvram_patcher
