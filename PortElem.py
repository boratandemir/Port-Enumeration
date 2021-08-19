"""
17.08.2021
  ______   ________   ______   __         ______   __    __  ________  ________
 /      \ /        | /      \ /  |       /      \ /  \  /  |/        |/        |
/$$$$$$  |$$$$$$$$/ /$$$$$$  |$$ |      /$$$$$$  |$$  \ $$ |$$$$$$$$/ $$$$$$$$/
$$ |__$$ |   $$ |   $$ |__$$ |$$ |      $$ |__$$ |$$$  \$$ |   $$ |   $$ |__
$$    $$ |   $$ |   $$    $$ |$$ |      $$    $$ |$$$$  $$ |   $$ |   $$    |
$$$$$$$$ |   $$ |   $$$$$$$$ |$$ |      $$$$$$$$ |$$ $$ $$ |   $$ |   $$$$$/
$$ |  $$ |   $$ |   $$ |  $$ |$$ |_____ $$ |  $$ |$$ |$$$$ |   $$ |   $$ |_____
$$ |  $$ |   $$ |   $$ |  $$ |$$       |$$ |  $$ |$$ | $$$ |   $$ |   $$       |
$$/   $$/    $$/    $$/   $$/ $$$$$$$$/ $$/   $$/ $$/   $$/    $$/    $$$$$$$$/

Port Enumeration v1
"""
import argparse
import requests
import json
import csv
from shodan import Shodan
from time import sleep
import os


class portFinder:

    def __init__(self, command, domain, inputName, outputName):
        self.command = command
        self.inputName = inputName
        self.outputName = outputName
        self.domain = domain

    def start(self):
        
        if self.command == "bin":
            self.binaryedge(self.domain)
        elif self.command == "sec":
            self.securitytrails(self.domain)
        elif self.command == "ip":
            self.find_ip()
        elif self.command == "port":
            self.find_port()
        elif self.command == "remove":
            self.remove()
        else:
            print("Incorrect Entry!")

    def binaryedge(self, domain):
        url = "https://api.binaryedge.io/v2/query/domains/subdomain/" + domain

        binaryedge = open("binaryedgeOutput.txt", "w")

        headers = {
            "X-Key": "*********************************",
        }

        count = 0

        params = {
            "page": count
        }

        response = requests.request("GET", url, headers=headers, params=params)
        sub = json.loads(response.text)

        while sub["events"] != []:
            count += 1
            params = {
                "page": count
            }
            response = requests.request("GET", url, headers=headers, params=params)
            sub = json.loads(response.text)
            subdomain = sub["events"]
            for i in subdomain:
                binaryedge.write(i + "\n")
        binaryedge.close()

    def securitytrails(self, domain):
        url = "https://api.securitytrails.com/v1/domain/" + domain + "/subdomains"

        querystring = {"children_only": "false", "include_inactive": "true"}

        headers = {
            "Accept": "application/json",
            "APIKEY": "***********************************"
        }

        response = requests.request("GET", url, headers=headers, params=querystring)

        sub = json.loads(response.text)
        subdomain = sub["subdomains"]

        fSecuritytrails = open("SecuritytrailsOutput.txt", "w")
        for i in subdomain:
            fSecuritytrails.write(i + "." + domain + "\n")
        fSecuritytrails.close()

    def find_ip(self):
        inputFile = open(self.inputName, "r")
        outputFile = open("SubdomIpOutput.txt", "w")
        a = [line.rstrip() for line in inputFile]
        for i in a:
            count = 0
            url = "https://dns.google/resolve?name=" + i
            response = requests.get(url).json()

            if "Answer" in response:

                answer = response["Answer"]
                asd = answer[count]
                if asd["type"] == 1:

                    outputFile.write(i + "," + asd["data"] + "\n")
                else:
                    count += 0
                    continue
        inputFile.close()
        outputFile.close()

    def find_port(self):
        api = Shodan("**************************************")
        inputFile = open(self.inputName, "r")
        outputFile = open("output.csv", "w")

        outputFile.write("Domain,ip,ports\n")
        a = [line.rstrip() for line in inputFile]
        for i in a:
            print(i)
            ip = i.split(",")[1]
            try:
                response = json.loads(json.dumps(api.host(ip)))
            except:
                continue

            port_list = response["ports"]
            ports = str(port_list).replace(",", "-").replace("[", "").replace("]", "").replace(" ", "")

            outputFile.write(i + "," + ports + "\n")

            sleep(1)
        inputFile.close()
        outputFile.close()

    def remove(self):
        if os.path.exists("binaryedgeOutput.txt"):
            os.remove("binaryedgeOutput.txt")
        else:
            print("File Not found.")
        if os.path.exists("SecuritytrailsOutput.txt"):
            os.remove("SecuritytrailsOutput.txt")
        else:
            print("File Not found.")
        if os.path.exists("Subdom-IpOutput.txt"):
            os.remove("Subdom-IpOutput.txt")
        else:
            print("File Not found.")
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='test', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c","--command",required=True,help="Give me command\n"
                                                            "   bin    --> Search Binary Edge\n"
                                                            "   sec    --> Search Security Trails\n"
                                                            "   ip     --> Search IP address of the subdomain\n"
                                                            "   port   --> Search open ports of the subdomains (First find IP address)"
                                                            "   remove --> Remove temp files")
    parser.add_argument("-d", "--domain", required=False, help="Give me domain.")
    parser.add_argument("-i", "--input", required=False, help="Give me input file name.")
    parser.add_argument("-o", "--output", required=False, help="Give me output file name.")
    args = vars(parser.parse_args())

    pf = portFinder(args["command"], args["domain"], args["input"], args["output"])
    pf.start()
