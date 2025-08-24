import requests

subconverter_url = "http://127.0.0.1:25500/sub?target=clash&url={node}&list=true"
input_file = "output/all_valid_proxies.txt"
output_file = "clash.yaml"

with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
    for line in infile:
        node = line.strip()
        if not node:
            continue
        url = subconverter_url.format(node=node)
        response = requests.get(url)
        if response.ok:
            outfile.write(response.text + "\n")
        else:
            print(f"Failed to convert: {node}")