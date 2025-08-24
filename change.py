import subprocess
import base64

def main():


    file_path = "test.txt"

    with open(file_path, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        node = line.strip()
        if not node:
            continue

        # Encode node in base64 for SubConverter API
        node_b64 = base64.b64encode(node.encode()).decode()

        url = f"http://127.0.0.1:25500/sub?target=clash&list=true&url=data:text/plain;base64,{node_b64}"
        output_file = f"clash_{i}.yaml"

        subprocess.run(["curl", url, "-o", output_file], check=True)
        print(f"{output_file} created successfully!")


if __name__ == "__main__":
    main()
