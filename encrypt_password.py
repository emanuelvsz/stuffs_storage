import bcrypt

senha_do_usuario = "Test1234!"
tentativa_de_senha = "Test1234!"

hashed_password = bcrypt.hashpw(senha_do_usuario.encode('utf-8'), bcrypt.gensalt())
print(hashed_password)

if bcrypt.checkpw(tentativa_de_senha.encode('utf-8'), hashed_password):
    print("Senha correta, permitindo o login.")
else:
    print("Senha incorreta, negando o login.")
