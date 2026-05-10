import sys

with open('webauthn_routes.py', 'r', encoding='utf-8') as f:
    routes = f.read()

with open('server.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = '''# ----------------------------------------------------------------------------
# ENTRY POINT'''

if target not in content:
    print("Target not found")
    sys.exit(1)

content = content.replace(target, routes + '\n\n' + target)

with open('server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Injected!")
