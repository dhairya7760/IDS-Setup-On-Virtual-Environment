#!/bin/bash

sudo add-apt-repository ppa:oisf/suricata-stable -y && \

sudo apt-get update && \

sudo apt-get install suricata -y && \

sudo systemctl enable suricata.service && \

sudo systemctl status suricata.service && \

sudo systemctl stop suricata.service && \

sudo touch /etc/suricata/rules/local.rules && \

sudo echo 'alert tcp any any -> any any (msg:"SYN scan detected"; flags:S; threshold: type both, track by_src, count 20, seconds 5; sid:1000001; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"FIN scan detected"; flags:F; sid:1000002; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert udp any any -> any any (msg:"UDP scan detected"; threshold: type both, track by_src, count 10, seconds 5; sid:1000003; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Xmas scan detected"; flags:FPU; sid:1000004; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Null scan detected"; flags:0; sid:1000005; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"TCP Connect scan detected"; flags:S; threshold: type both, track by_src, count 20, seconds 1; sid:1000006; rev:2;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Version Scan detected"; threshold: type both, track by_src, count 20, seconds 5; sid:1000007; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000008; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo sed -i '18s/.*/    HOME_NET: "[192.168.0.0\/24]"/' /etc/suricata/suricata.yaml && \

sudo sed -i '589s/.*/  - interface: enp0s3/' /etc/suricata/suricata.yaml && \

sudo sed -i '669s/.*/  - interface: enp0s3/' /etc/suricata/suricata.yaml && \

sudo sed -i '132s/.*/      community-id: true/' /etc/suricata/suricata.yaml && \

sudo sed -i '1925i \  - /etc/suricata/rules/local.rules' /etc/suricata/suricata.yaml && \

sudo suricata-update && \

sudo suricata -T -c /etc/suricata/suricata.yaml -v && \

sudo systemctl start suricata.service  && \

sudo systemctl status suricata.service