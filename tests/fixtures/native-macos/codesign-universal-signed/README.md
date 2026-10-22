# codesign captures of a universal Mach-O whose slices are signed differently

Each slice of a universal Mach-O is signed on its own. Without `-a`, codesign
describes the slice it selects by default for the host; `codesign -d -r-` on an
ad hoc signature prints the requirement that covers every slice.

These files were captured on macOS 27.0.1 arm64 with the Xcode Command Line
Tools (Apple clang 21.0.0). The executable path in the output is replaced with
`/private/fixture`. CDHashes depend on the toolchain and can differ elsewhere.

| File                         | Command                                                    |
| ---------------------------- | ---------------------------------------------------------- |
| `aggregate.txt`              | `codesign -d --verbose=4 fixture` (stderr)                 |
| `slice-x86_64.txt`           | `codesign -d -a x86_64 --verbose=4 fixture` (stderr)       |
| `slice-arm64.txt`            | `codesign -d -a arm64 --verbose=4 fixture` (stderr)        |
| `entitlements-aggregate.xml` | `codesign -d --entitlements :- fixture` (stdout)           |
| `entitlements-x86_64.xml`    | `codesign -d -a x86_64 --entitlements :- fixture` (stdout) |
| `entitlements-arm64.xml`     | `codesign -d -a arm64 --entitlements :- fixture` (stdout)  |
| `requirements.txt`           | `codesign -d -r- fixture` (stdout)                         |

Generate the executable locally; do not check its binary into the repository:

```sh
printf 'int main(void){return 0;}\n' > main.c
cat > arm.plist <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
XML
cat > x86.plist <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
XML
clang -arch arm64 -o slice-arm64 main.c
clang -arch x86_64 -o slice-x86_64 main.c
codesign -f -s - -i com.example.armslice -o runtime --entitlements arm.plist slice-arm64
codesign -f -s - -i com.example.x86slice --entitlements x86.plist slice-x86_64
lipo -create slice-x86_64 slice-arm64 -o fixture
```

The arm64 slice carries the hardened runtime and
`com.apple.security.cs.disable-library-validation`; the x86_64 slice has no
hardened runtime and `com.apple.security.get-task-allow`.
