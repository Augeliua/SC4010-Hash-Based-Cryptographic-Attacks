"""Milestone 7: verify the three signature-forgery demonstrations end to end.

Run from the repository root:
    python -m integration.final_check

No third-party dependencies. Exits with error if any claim is not demonstrated.
"""
import subprocess
import sys
from pathlib import Path

# Keep demo commands and the exact output that demonstrates success together.
# This makes our live presentation check reproducible, rather than trusting
# screenshots or assuming that a successful process exit means a forgery worked.
DEMOS = [
    ('Lamport legitimate signing', 'demo_lamport.py',
     ['Legitimate signature valid: True', 'Modified message accepted: False']),
    ('Lamport key-reuse forgery', 'demo_lamport_forgery.py',
     ['Message was never signed by Alice: True', 'Bob accepts forged signature: True']),
    ('WOTS+ legitimate signing', 'demo_wots_plus.py',
     ['Valid signature accepted: True', 'Modified message accepted: False']),
    ('WOTS+ two forgery attacks', 'demo_wots_attacks.py',
     ['Weak verifier accepts forgery: True',
      'Full checksum-protected verifier accepts forgery: True',
      'Message was never signed by Alice: True']),
    ('XMSS rollback forgery', 'demo_xmss_rollback.py',
     ['XMSS-style root verifier accepts forgery: True',
      'Tampered message accepted: False']),
]


def run():
    # Require execution from the project root so imports resolve consistently.
    if not Path('signatures/lamport.py').is_file():
        raise SystemExit('Open the VS Code terminal in your project root first.')

    for name, filename, expected_lines in DEMOS:
        print(f'\n=== {name} ===', flush=True)
        # Use the SAME Python interpreter as the current VS Code terminal.
        result = subprocess.run([sys.executable, filename], capture_output=True,
                                text=True, timeout=90)
        if result.returncode != 0:
            print(result.stdout, result.stderr)
            raise SystemExit(f'FAIL: {filename} crashed')
        for line in expected_lines:
            if line not in result.stdout:
                print(result.stdout)
                raise SystemExit(f'FAIL: {filename} did not show {line!r}')
        print('PASS: all required evidence appears')

    print('\n=== Automatic tests ===', flush=True)
    result = subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                             '-s', 'tests', '-v'], capture_output=True, text=True,
                            timeout=90)
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        raise SystemExit('FAIL: tests')
    print(result.stderr.splitlines()[-1] if result.stderr else 'OK')
    print('\nALL MILESTONE 7 DEMO CHECKS PASSED')


if __name__ == '__main__':
    run()
