from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512, SHA1
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

def sign_file(file_path, private_key_path, hash_algorithm):
    # Ler o arquivo
    with open(file_path, 'rb') as f:
        data = f.read()

    # Gerar o hash do arquivo
    h = hash_algorithm.new(data)

    # Carregar a chave privada
    with open(private_key_path, 'rb') as f:
        key = RSA.import_key(f.read())

    # Assinar o hash
    signature = pkcs1_15.new(key).sign(h)

    # Salvar a assinatura e o arquivo original (codificado em base64)
    with open(file_path + '.sign', 'wb') as f:
        f.write(b64encode(signature))
    with open(file_path + '.base64', 'wb') as f:
        f.write(b64encode(data))


def verify_signature(file_path, signature_path, public_key_path, hash_algorithm):
    # Ler o arquivo original
    with open(file_path, 'rb') as f:
        data = f.read()

    # Gerar o hash do arquivo original
    h = hash_algorithm.new(data)

    # Carregar a chave pública
    with open(public_key_path, 'rb') as f:
        key = RSA.import_key(f.read())

    # Carregar a assinatura (decodificada de base64)
    with open(signature_path, 'rb') as f:
        signature = b64decode(f.read())

    try:
        # Verificar a assinatura
        pkcs1_15.new(key).verify(h, signature)
        print("Assinatura válida")
    except (ValueError, TypeError):
        print("Assinatura inválida")

def generate_key():
    # Gerar uma nova chave RSA
    key = RSA.generate(2048)

    # Salvar a chave privada e a chave pública (compatíveis com o padrão openssl)
    with open('private.pem', 'wb') as f:
        f.write(key.export_key('PEM'))
    with open('public.pem', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))

# Exemplo de uso
private_key_path = "private.pem"
public_key_path = "public.pem"

# Menu e execução
if __name__ == "__main__":
    while True:
        print("1 - Assinar Documento\n2 - Verificar Assinatura\n0 - Sair")
        option = int(input())
        if option == 1:
            print("Selecione o algoritmo:\n1 - SHA256\n2 - SHA512\n3 - SHA1\n0 - Sair")
            option1 = int(input())
            if option1 == 1:
                alg = SHA256
            if option1 == 2:
                alg = SHA512
            if option1 == 3:
                alg = SHA1
            if option1 == 0:
                break
            print("Digite o caminho para o arquivo: ")
            path = str(input())
            if not ".txt" in path:
                print("O arquivo precisa ser .txt")
                break
            generate_key()
            sign_file(path, private_key_path, alg)
            print("Documento assinado")
        if option == 2:
            print("Digite o caminho para o arquivo: ")
            path = str(input())
            verify_signature(path, "trabalho.txt.sign", public_key_path, alg)
        if option == 0:
            break