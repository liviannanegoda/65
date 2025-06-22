import nmap


def scan_network(target, ports="1-65535"):
    """
    Сканирует указанный хост и диапазон портов.

    :param target: Целевая сеть или IP-адрес (например, '192.168.1.1' или '192.168.1.0/24').
    :param ports: Диапазон портов для сканирования (по умолчанию: '1-65535').
    :return: Результаты сканирования.
    """
    scanner = nmap.PortScanner()

    print(f"Сканирование {target} на порты {ports}...")

    try:
        scanner.scan(hosts=target, ports=ports, arguments='-sS -T4')

        results = []
        for host in scanner.all_hosts():
            print(f"\nХост: {host} ({scanner[host].hostname()})")
            print(f"Состояние: {scanner[host].state()}")
            for proto in scanner[host].all_protocols():
                print(f"Протокол: {proto}")
                ports = scanner[host][proto].keys()
                for port in ports:
                    port_info = scanner[host][proto][port]
                    print(f"  Порт {port}: {port_info['state']}")
                    results.append({
                        "host": host,
                        "protocol": proto,
                        "port": port,
                        "state": port_info['state'],
                        "service": port_info.get('name', '')
                    })
        return results
    except nmap.PortScannerError as e:
        print(f"Ошибка при сканировании: {e}")
        return None
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        return None


if __name__ == "__main__":

    target_ip = input("Введите IP (например, '192.168.1.1') или диапазон (например, '192.168.1.0/24') для сканирования: ")
    ports_range = input("Введите диапазон портов (например, 1-1000, по умолчанию: 1-65535): ") or "1-65535"

    scan_results = scan_network(target_ip, ports_range)
    if scan_results:
        print("\nРезультаты сканирования:")
        for result in scan_results:
            print(result)
    else:
        print("Сканирование завершено без результатов.")
