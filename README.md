
# SOCautoURLanalyzer

SOCautoURLanalyzer is a tool designed to automate the analysis of URLs for Security Operations Centers (SOC). It streamlines the process of evaluating URLs for malicious content, helping security analysts quickly identify potential threats.

## Features

- **Automated URL Analysis**: Scans URLs for potential security threats using various online services and tools.
- **Reporting**: Generates reports detailing the analysis results in a single page, making it easier for analysts to review.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

```bash
# Example dependency installation
pip install -r requirements.txt
```

### API Keys Configuration

Before using this tool, you need to configure API keys for VirusTotal and URLscan to enable the tool to interact with these services. You will not need an API key for Qualy SSL Labs. Follow the steps below to set up your API keys:

### VirusTotal API Key

1. Create an account on [VirusTotal](https://www.virustotal.com/).
2. Navigate to your profile settings to find your API key.
3. In the project directory, create a file named `.env` and add your VirusTotal API key as follows: VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

### URLscan API Key

1. Create an account on [URLscan](https://urlscan.io/).
2. Navigate to your profile settings to find your API key.
3. Add your URLscan API key to the `.env` file: URLSCAN_API_KEY=your_urlscan_api_key_here

![image](https://github.com/bchiek/SOCautoURLanalyzer/assets/99049187/18f8610a-727b-44eb-84e4-c7bacebba564)

Follow these steps to set up a development environment:

```bash
# Clone the repository
git clone https://github.com/bchiek/SOCautoURLanalyzer.git
cd SOCautoURLanalyzer

# Set up a Python virtual environment (make sure Python is installed, this project was built with 3.12)
python3 -m venv venv

# Activate the virtual environment
# On Windows
.\venv\Scripts\activate
# On Unix or MacOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python analyzer.py
```

## Usage

```bash
# Example command
python app.py
```

## Authors

[bchiek](https://github.com/bchiek)

See also the list of [contributors](https://github.com/bchiek/SOCautoURLanalyzer/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE_FILE_LINK) file for details.

## Acknowledgments

- 
