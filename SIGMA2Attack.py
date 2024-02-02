import os
import re
import json
from git import Repo

def git_clone_repo(repo_url, destination):
    repo = Repo.clone_from(repo_url, destination)

def validate_mitre_id(mitre_id):
    # Regular expression pattern for validating MITRE IDs
    mitre_id_pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
    return bool(mitre_id_pattern.match(mitre_id))

def is_group_or_software(mitre_id):
    # Check if the ID is a group (GXXXX) or software (SXXXX)
    return mitre_id.startswith("G") or mitre_id.startswith("S")

def scrape_mitre_framework_ids(rule_folder):
    mitre_ids_comments = {}
    for root, dirs, files in os.walk(rule_folder):
        for file in files:
            if file.endswith(".yml"):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Assuming MITRE IDs are present in lines starting with "- attack."
                    mitre_id_lines = [line.strip().split("- attack.")[1].strip().upper() for line in content.splitlines() if "- attack." in line.strip()]
                    for mitre_id_line in mitre_id_lines:
                        # Validate MITRE ID and exclude groups and software
                        if validate_mitre_id(mitre_id_line) and not is_group_or_software(mitre_id_line):
                            mitre_ids_comments[mitre_id_line] = mitre_ids_comments.get(mitre_id_line, [])
                            mitre_ids_comments[mitre_id_line].append(f"Rule included: {file}")
                        # else:
                        #     print(f"Excluded MITRE ID: {mitre_id_line} in file: {file}")

    return mitre_ids_comments

def generate_attack_layer_json_v45(mitre_ids_comments):
    score_range = 20 #Range appears to be mainly 0-20 with some outliers
    colors = ["#6eafdb", "#f4c69a", "#e8bb3a", "#d73027", "#56130F"]

    attack_layer = {
        "name": "Sigma Rules MITRE Heatmap",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK heatmap generated from Sigma rules",
        "sorting": 2,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": True
        },
        "techniques": [],
        "gradient": {
            "colors": ["#5054e6", "#edf04a", "#f08335", "#e83727", "#953bbf"],
            "minValue": 0,
            "maxValue": score_range
        },
        "legendItems": [
           {
                "label": "Low",
                "color": colors[0],
                "value": 1
            },
            {
                "label": "Low-Medium",
                "color": colors[1],
                "value": int(score_range * 0.25)
            },
            {
                "label": "Medium-High",
                "color": colors[2],
                "value": int(score_range * 0.5)
            },
            {
                "label": "High",
                "color": colors[3],
                "value": int(score_range * 0.75)
            },
            {
                "label": "Very High",
                "color": colors[4],
                "value": 1000
            }
        ],
        "tacticRowBackground": "#dddddd",
        "metadata": [
            {
                "name": "SIGMA Heatmap Project",
                "value": "Created by Dave"
            }
        ]
    }

    for mitre_id, comments in mitre_ids_comments.items():
        score = len(comments)
        color = gradient_color(score, score_range)
        technique = {
            "techniqueID": mitre_id,
            "score": score,
            "comment": "\n".join(comments),
            "color": color
        }
        attack_layer["techniques"].append(technique)

    return json.dumps(attack_layer, indent=2)

def gradient_color(value, max_value):
    # Modified gradient for better visibility within the 0-20 score range
    colors = ["#6eafdb", "#edf04a", "#f08335", "#e83727", "#953bbf"]
    if value > max_value:
        return "#953bbf"  # Set to "Very High" color for scores greater than max_value

    return "#953bbf" if max_value > 20 else colors[int((value / max_value) * (len(colors) - 1))]

def main():
    repo_url = "https://github.com/SigmaHQ/sigma.git" 
    destination_folder = "sigma-rules"
    rule_folder = os.path.join(destination_folder, "rules", "windows")

    # Git clone the repo
    git_clone_repo(repo_url, destination_folder)

    # Scrape MITRE framework IDs with comments
    mitre_ids_comments = scrape_mitre_framework_ids(rule_folder)

    # Generate attack layer JSON
    attack_layer_json = generate_attack_layer_json_v45(mitre_ids_comments)

    # Save the JSON to a file or use it as needed
    with open("sigma_mitre_heatmap.json", "w", encoding="utf-8") as json_file:
        json_file.write(attack_layer_json)

if __name__ == "__main__":
    main()