import argparse
from pathlib import Path

import yaml
from schema import CandidateProfile


def load_candidate(path: Path) -> CandidateProfile:
    with path.open("r", encoding="utf-8") as f:
        return CandidateProfile.from_dict(yaml.safe_load(f))


def parse_args():
    parser = argparse.ArgumentParser(description="Schema Parser")

    parser.add_argument(
        "--profile", type=str, required=True, help="Candidate profile file to parse"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.profile:
        profile = load_candidate(Path(args.profile))
        print(profile)


if __name__ == "__main__":
    main()
