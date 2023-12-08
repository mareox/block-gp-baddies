# block-gp-baddies

## Description

`block-gp-baddies` is a Python script designed to automate the process of updating Dynamic Address Groups (DAGs) in PAN-OS firewalls. It queries the firewall logs for failed login attempts, extracts public IP addresses, generates an XML file with these IPs, and updates the firewall's address groups accordingly.

## Installation

### Prerequisites

- Python 3.10 or higher.
- (optional) Poetry for dependency management.

## Steps

Clone the repository:

```bash
git clone https://github.com/cdot65/block-gp-baddies
```

Navigate to the project directory:

```bash
cd block-gp-baddies
```

Install dependencies using Poetry and activate the virtual environment:

```bash
poetry install
poetry shell
```

If you'd rather create your own manually, follow these steps instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install lxml requests dynaconf
```

### Dependencies

- requests: For making HTTP requests to the PAN-OS API.
- dynaconf: For dynamic configuration management.
- lxml: For XML file generation and handling.

Development dependencies like black, flake8, ipdb, and ipython for code formatting, linting, and debugging.

## Usage

> Ensure that the `.secrets.yaml` file is properly set up with the necessary settings for your PAN-OS environment.

To run the script, execute the following command in the project directory:

```bash
python app.py
```

## Contributing

Contributions to the project are welcome. Please follow the standard fork, branch, and pull request workflow.

## Contact

For any queries or contributions, please contact Calvin Remsburg at `cremsburg.dev@gmail.com`.

## License

Apache2.0