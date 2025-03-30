import bcrypt

# Contraseñas originales
passwords = ["admin123", "user123"]

# Generar y mostrar los hashes
for password in passwords:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    print(f"Contraseña: {password} -> Hash: {hashed}")