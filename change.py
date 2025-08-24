from pyclash import Clash

def main():

    with open("test.txt") as f:
        nodes = [line.strip() for line in f if line.strip()]

    clash = Clash()
    for node in nodes:
        clash.add_node_from_url(node)

    clash.write_yaml("clash.yaml")


if __name__ == "__main__":
    main()
