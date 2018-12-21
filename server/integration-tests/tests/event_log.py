import yaml

PATH = "/tmp/test-service-event-stream.yml"


def clear():
    with open(PATH, "w"):
        pass


def load():
    with open(PATH, "r") as f:
        return list(yaml.load_all(f))


def find_change_in_log(log, event_type, search_for):
    for event in log:
        if event["event_type"] != event_type:
            continue

        for value in event["values"]:
            missing_key = False

            for key in search_for.keys():
                if value[key] != search_for[key]:
                    missing_key = True
                    break

            if not missing_key:
                return event

    return None
