def dump_yaml(value) -> str:
    import yaml

    class Dumper(yaml.SafeDumper):
        pass

    def string(dumper, value):
        # Go and Python YAML parsers disagree on values such as 08. Quote all strings.
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style='"')

    Dumper.add_representer(str, string)
    return yaml.dump(value, Dumper=Dumper, allow_unicode=True, sort_keys=False)
