# NTUSF-Not-The-Usual-Stupid-Fuzzer
## A smart vulnerability scanner powered by Machine Learning
The advent of Artificial Intelligence and Machine Learning has unlocked a plethora of possibilities across various sectors, cybersecurity being a notable example. In this domain, the effectiveness of intrusion detection systems has significantly increased. This thesis presents a novel tool that integrates these technological fields by relying on machine learning to analyze a collection of web application URLs to identify the most likely vulnerable ones. Equipped with attack modules addressing the OWASP top 10 vulnerabilities, this software not only detects possible exploits but also generates omprehensive infographics to illustrate its findings. To validate its practicality, the software was also applied to a live web application, underscoring its real-world use-case. 

## Installation
Follow these steps to install the software components on your local machine:
- Clone The repository
  Download the repository locally via `git clone https://github.com/Jacopobracaloni/NTUSF-Not-The-Usual-Stupid-Fuzzer.git`

- Navigate inside the repository via `cd NTUSF-Not-The-Usual-Stupid-Fuzzer`

- Create a virtual environment in your project folder via `python3 -m venv env`

- Activate the virtual environment by launching `source env/binActivate`

- Install the required python libraries via `pip install requirements.txt`

## Running
Once all the components are installed, you can run the software via `python3 ntusf.py` and follow the instructions prompted to stdout.

## Disclaimer
The usage of this tool should be ethical and comply with the permissions granted by the owner of the target web application. This tool was developed for educational purposes only and the owner is not responsible for any illegitamate use.
