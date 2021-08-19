# Port-Enumeration
PortElem is an application that gives you the subdomain, IP and open ports by entering the domain.

## Usage
python3 PortElem.py [-h] -c COMMAND [-d DOMAIN] [-i INPUT] [-o OUTPUT]

## Keys
|  Action   |  Shortcut  |
|:-------:| :-----:|
| Help  | *-h*      |
| Command  | *-c*    |
| Domain     | *-d*   |
| Input    | *-i*  |
| Output    | *-o*  |


## Command Types (-c)
bin     --> Search Binary Edge

sec     --> Search Security Trails

ip      --> Search IP address of the subdomain

port    --> Search open ports of the subdomains (First find IP address)

remove  --> Remove temp files

## Note: You have to get Binary edge, Security trails and Shodan api from their own sites and replace them with * in the code.
