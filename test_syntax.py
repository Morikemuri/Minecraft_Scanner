import sys
try:
    with open("minecraft_scanner.py", "r", encoding="utf-8") as f:
        code = f.read()
    compile(code, "minecraft_scanner.py", "exec")
    print("OK")
except SyntaxError as e:
    print(f"SyntaxError at line {e.lineno}: {e.msg}")
    print(f"Text: {e.text}")
except Exception as e:
    print(f"Error: {e}")
