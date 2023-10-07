import nmap

# Solicita o input do IP ao usuário
ip = input("Digite o IP para varredura de portas: ")
port = input("Digite o intervalo de portas para varredura: (1 - 1000) ")

# Cria um objeto nmap.PortScanner
scanner = nmap.PortScanner()

# Executa a varredura de portas no IP fornecido
scanner.scan(ip, port)

# Itera sobre os resultados da varredura e imprime as portas abertas
for host in scanner.all_hosts():
    print("IP: ", host)
    for port in scanner[host]['tcp']:
        if scanner[host]['tcp'][port]['state'] == 'open':
            print("Porta: ", port, "Estado: ", scanner[host]['tcp'][port]['state'])