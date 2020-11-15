def parse_address(address):
    host, port = address.split(':')

    if host == '':
        host = 'localhost'

    return host, int(port)


def parse_ip(ip: str) -> tuple:
    """
    Returns IP address from str as int tuple
    eg: '192.168.43.1' -> (192, 168, 43, 1)
    """

    splitted = ip.split('.')

    if (len(splitted) != 4):
        raise ValueError("Invalid IP format")

    ret = []

    for num in splitted:
        ret.append(int(num))
        if ret[-1] < 0 or ret[-1] > 255:
            raise ValueError("Invalid IP format")

    return tuple(ret)


if __name__ == '__main__':
    print(parse_ip('129.255.12.32'))
