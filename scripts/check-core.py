#!/usr/bin/env python3
"""Run core XCTest methods with assertions when Command Line Tools lacks XCTest."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'Tests/CaptureCoreTests/CaptureTests.swift').read_text()
methods = re.findall(r'func (test\w+)\(\)( throws)?', source)
source = source.replace('import XCTest', 'import Foundation').replace('@testable import CaptureCore', '').replace(': XCTestCase', '')
source += '''
func XCTAssertEqual<T: Equatable>(_ a: T, _ b: T, file: StaticString = #file, line: UInt = #line) {
    precondition(a == b, "Expected \\(a) == \\(b)", file: file, line: line)
}
func XCTAssertNil<T>(_ value: T?, file: StaticString = #file, line: UInt = #line) {
    precondition(value == nil, "Expected nil", file: file, line: line)
}
func XCTAssertThrowsError<T>(_ expression: @autoclosure () throws -> T) {
    do { _ = try expression(); fatalError("Expected error") } catch {}
}
@main struct Runner { static func main() throws {
let tests = CaptureTests()
'''
for name, throws in methods:
    source += ('try ' if throws else '') + 'tests.' + name + '()\n'
source += 'print("All ' + str(len(methods)) + ' core checks passed")\n} }\n'
with tempfile.TemporaryDirectory(prefix='Schwabber-checks-') as temp:
    temp = Path(temp)
    harness = temp / 'Checks.swift'
    harness.write_text(source)
    binary = temp / 'checks'
    subprocess.run(['swiftc', '-module-cache-path', str(root / '.build/check-module-cache'), '-I', str(root / 'Sources/CPcap'), *map(str, sorted((root / 'Sources/CaptureCore').glob('*.swift'))), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
