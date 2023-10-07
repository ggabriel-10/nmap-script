import nmap

# Solicita o input do IP ao usuário
ip = input("Digite o IP/URL para varredura de portas: ")

# Solicita o input do intervalo de portas ao usuário e verifica se é um número
while True:
    port_range = input("Digite o intervalo de portas para varredura (1 - 1000): ")
    if port_range.isdigit():
        port_range = int(port_range)
        if 1 <= port_range <= 1000:
            break
        else:
            print("Por favor, insira um número entre 1 e 1000.")
    else:
        print("Por favor, insira um número válido.")

# Cria um objeto nmap.PortScanner
scanner = nmap.PortScanner()

# Executa a varredura de portas no IP fornecido
scanner.scan(ip, f"1-{port_range}")

# Itera sobre os resultados da varredura e imprime as portas abertas
for host in scanner.all_hosts():
    print("IP: ", host)
    for port in scanner[host]['tcp']:
        if scanner[host]['tcp'][port]['state'] == 'open':
            print("Porta: ", port, "Estado: ", scanner[host]['tcp'][port]['state'])
